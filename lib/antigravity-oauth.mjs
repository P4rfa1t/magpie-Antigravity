import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { validateProxyURL } from './setup.mjs';
import {
  NATIVE_OAUTH_USER_AGENT,
  OFFICIAL_HUB_CL,
  OFFICIAL_HUB_VERSION,
  resolveAntigravityUserAgents,
  shouldDetectLocalByEnv
} from './antigravity-ua.mjs';

// OAuth client keys matching Antigravity-Manager. Credentials themselves are never
// committed in source; load them from options, environment variables, or local
// oauth-clients.json in the user's data directory.
export const PERSONAL_CLIENT_KEY = 'antigravity_enterprise';
export const GCP_CLIENT_KEY = 'antigravity_gcp';

export const PERSONAL_OAUTH_CLIENT = {
  key: PERSONAL_CLIENT_KEY,
  label: 'Personal Google Account',
  clientId: '',
  clientSecret: ''
};

export const GCP_OAUTH_CLIENT = {
  key: GCP_CLIENT_KEY,
  label: 'Enterprise / GCP (Vertex AI)',
  clientId: '',
  clientSecret: ''
};

export const OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const OAUTH_CALLBACK_PATH = '/oauth-callback';
export const DEFAULT_MANUAL_OAUTH_PORT = 51121;
export const OAUTH_SCOPES = Object.freeze([
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs'
]);
export const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const OAUTH_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
export {
  NATIVE_OAUTH_USER_AGENT,
  OFFICIAL_HUB_VERSION,
  OFFICIAL_HUB_CL
};

export const V1_INTERNAL_BASES = [
  'https://daily-cloudcode-pa.googleapis.com/v1internal',
  'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal'
];

export const LOAD_CODE_ASSIST_ENDPOINTS = [
  'https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist',
  'https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist',
  'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:loadCodeAssist'
];

export const ONBOARD_USER_ENDPOINTS = LOAD_CODE_ASSIST_ENDPOINTS.map(u =>
  u.replace(/:loadCodeAssist$/, ':onboardUser')
);

export const FETCH_MODELS_ENDPOINTS = V1_INTERNAL_BASES.map(b => `${b}:fetchAvailableModels`);
export const QUOTA_SUMMARY_ENDPOINTS = V1_INTERNAL_BASES.map(b => `${b}:retrieveUserQuotaSummary`);
export const ANTIGRAVITY_PRIVACY_BASE = 'https://daily-cloudcode-pa.googleapis.com/v1internal';

export const DEFAULT_FALLBACK_PROJECT_ID = 'bamboo-precept-lgxtn';
export const TOKEN_REFRESH_SKEW_MS = 15 * 60 * 1000;
const TOKEN_REFRESH_SKEW_MIN_MS = 10 * 60 * 1000;
const TOKEN_REFRESH_SKEW_MAX_MS = 18 * 60 * 1000;

const REFRESH_TOKEN_RE = /1\/\/[a-zA-Z0-9_\-]+/g;

function uaResolveOptions(envOrOptions = process.env, extraOptions) {
  if (extraOptions && typeof extraOptions === 'object') {
    const env = envOrOptions || process.env;
    const dataDir = extraOptions.dataDir !== undefined
      ? extraOptions.dataDir
      : (env === process.env || env.ANTIGRAVITY_DATA_DIR ? antigravityDataDir(undefined, env) : undefined);
    return {
      env,
      dataDir,
      ...(extraOptions.detectLocal !== undefined ? { detectLocal: extraOptions.detectLocal } : {})
    };
  }
  if (
    envOrOptions &&
    typeof envOrOptions === 'object' &&
    envOrOptions !== process.env &&
    ('dataDir' in envOrOptions || 'env' in envOrOptions || 'detectLocal' in envOrOptions ||
      'baselineOAuthUa' in envOrOptions || 'baselineVersion' in envOrOptions || 'baselineCl' in envOrOptions)
  ) {
    const env = envOrOptions.env || process.env;
    const dataDir = envOrOptions.dataDir !== undefined
      ? envOrOptions.dataDir
      : (env === process.env || env.ANTIGRAVITY_DATA_DIR ? antigravityDataDir(undefined, env) : undefined);
    return {
      ...envOrOptions,
      env,
      dataDir
    };
  }
  const env = envOrOptions || process.env;
  const dataDir = env === process.env || env.ANTIGRAVITY_DATA_DIR
    ? antigravityDataDir(undefined, env)
    : undefined;
  return {
    env,
    dataDir,
    detectLocal: shouldDetectLocalByEnv(env)
  };
}

export function currentOAuthUserAgent(envOrOptions = process.env, extraOptions) {
  return resolveAntigravityUserAgents(uaResolveOptions(envOrOptions, extraOptions)).oauthUserAgent;
}

export function currentEgressUserAgent(envOrOptions = process.env, extraOptions) {
  return resolveAntigravityUserAgents(uaResolveOptions(envOrOptions, extraOptions)).egressUserAgent;
}

export function antigravityDataDir(explicitDir, env = process.env) {
  if (typeof explicitDir === 'string' && explicitDir.trim()) {
    return path.resolve(explicitDir.trim());
  }
  if (typeof env.ANTIGRAVITY_DATA_DIR === 'string' && env.ANTIGRAVITY_DATA_DIR.trim()) {
    return path.resolve(env.ANTIGRAVITY_DATA_DIR.trim());
  }
  return path.join(os.homedir(), '.local', 'share', 'magpie-antigravity');
}

export function normalizeClientType(value) {
  const s = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (s === 'enterprise' || s === 'gcp' || s === 'vertex' || s === 'antigravity_gcp') {
    return 'enterprise';
  }
  return 'personal';
}

export function parseRefreshTokenPackage(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('没有收到 Refresh Token，请粘贴 1//... 格式的 Token 或包含 refresh_token 的 JSON');
  }
  let input = raw.trim();
  if (input.startsWith('go-keyring-base64:')) {
    try {
      input = Buffer.from(input.slice(18).trim(), 'base64').toString('utf8').trim();
    } catch {}
  } else if (input.startsWith('go-keyring-encoded:')) {
    try {
      const hex = input.slice(19).trim();
      if (hex.length > 0 && hex.length % 2 === 0 && /^[0-9a-f]+$/i.test(hex)) {
        input = Buffer.from(hex, 'hex').toString('utf8').trim();
      }
    } catch {}
  }
  const found = [];
  const seen = new Set();
  let embeddedClientId = '';
  let embeddedClientSecret = '';
  const push = token => {
    if (typeof token !== 'string') return;
    const t = token.split('|')[0].trim();
    if (!t.startsWith('1//') || seen.has(t)) return;
    seen.add(t);
    found.push(t);
  };

  const walk = (node, depth = 0) => {
    if (!node || typeof node !== 'object' || depth > 3) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    push(node.refresh_token ?? node.refreshToken ?? node.refresh ?? node.token?.refresh_token ?? node.token?.refreshToken);
    const cid = node.client_id ?? node.clientId ?? node.token?.client_id ?? node.token?.clientId;
    const csec = node.client_secret ?? node.clientSecret ?? node.token?.client_secret ?? node.token?.clientSecret;
    if (typeof cid === 'string' && cid.trim() && typeof csec === 'string' && csec.trim()) {
      embeddedClientId = cid.trim();
      embeddedClientSecret = csec.trim();
    }
    for (const val of Object.values(node)) {
      if (val && typeof val === 'object') walk(val, depth + 1);
    }
  };

  if (input.startsWith('[') || input.startsWith('{')) {
    try {
      walk(JSON.parse(input), 0);
    } catch {
      // Fall through to regex extraction for arbitrary pasted text.
    }
  }

  if (found.length === 0) {
    const matches = input.match(REFRESH_TOKEN_RE);
    if (matches) {
      for (const m of matches) push(m);
    }
  }

  if (found.length === 0) {
    throw new Error('未识别到有效的 Refresh Token（应以 1// 开头，或为含 refresh_token 字段的 JSON）');
  }
  return {
    tokens: found,
    ...(embeddedClientId && embeddedClientSecret ? { clientId: embeddedClientId, clientSecret: embeddedClientSecret } : {})
  };
}

export function parseRefreshTokenInput(raw) {
  return parseRefreshTokenPackage(raw).tokens;
}

function oauthClientsFilePath(dataDir) {
  return path.join(dataDir, 'oauth-clients.json');
}

export function loadOAuthClients({ dataDir = antigravityDataDir(), env = process.env, options = {} } = {}) {
  const byKey = new Map();
  const put = (key, clientId, clientSecret, label) => {
    const k = String(key || '').trim().toLowerCase();
    const id = typeof clientId === 'string' ? clientId.trim() : '';
    const secret = typeof clientSecret === 'string' ? clientSecret.trim() : '';
    if (!k || !id || !secret) return;
    byKey.set(k, { key: k, label: label || k, clientId: id, clientSecret: secret });
  };

  // 1. Persisted local oauth-clients.json in dataDir
  const file = oauthClientsFilePath(dataDir);
  if (fs.existsSync(file)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      const list = Array.isArray(parsed?.clients) ? parsed.clients : Array.isArray(parsed) ? parsed : [];
      for (const c of list) put(c?.key, c?.clientId ?? c?.client_id, c?.clientSecret ?? c?.client_secret, c?.label);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        put(PERSONAL_CLIENT_KEY, parsed.personal?.clientId ?? parsed.personal?.client_id ?? parsed.clientId ?? parsed.client_id, parsed.personal?.clientSecret ?? parsed.personal?.client_secret ?? parsed.clientSecret ?? parsed.client_secret, PERSONAL_OAUTH_CLIENT.label);
        put(GCP_CLIENT_KEY, parsed.enterprise?.clientId ?? parsed.enterprise?.client_id ?? parsed.gcpClientId, parsed.enterprise?.clientSecret ?? parsed.enterprise?.client_secret ?? parsed.gcpClientSecret, GCP_OAUTH_CLIENT.label);
      }
    } catch {}
  }

  // 2. Environment variables (compatible with Antigravity-Manager's ANTIGRAVITY_OAUTH_CLIENTS)
  if (typeof env.ANTIGRAVITY_OAUTH_CLIENTS === 'string' && env.ANTIGRAVITY_OAUTH_CLIENTS.trim()) {
    for (const entry of env.ANTIGRAVITY_OAUTH_CLIENTS.split(';')) {
      const parts = entry.split('|').map(v => v.trim());
      if (parts.length >= 3) put(parts[0], parts[1], parts[2], parts[3]);
    }
  }
  put(PERSONAL_CLIENT_KEY, env.ANTIGRAVITY_OAUTH_CLIENT_ID, env.ANTIGRAVITY_OAUTH_CLIENT_SECRET, PERSONAL_OAUTH_CLIENT.label);
  put(GCP_CLIENT_KEY, env.ANTIGRAVITY_GCP_CLIENT_ID, env.ANTIGRAVITY_GCP_CLIENT_SECRET, GCP_OAUTH_CLIENT.label);

  // 3. Explicit plugin options / per-call overrides
  if (Array.isArray(options.oauthClients)) {
    for (const c of options.oauthClients) put(c?.key, c?.clientId ?? c?.client_id, c?.clientSecret ?? c?.client_secret, c?.label);
  }
  put(PERSONAL_CLIENT_KEY, options.clientId, options.clientSecret, PERSONAL_OAUTH_CLIENT.label);
  put(GCP_CLIENT_KEY, options.gcpClientId, options.gcpClientSecret, GCP_OAUTH_CLIENT.label);
  if (options.customClientId && options.customClientSecret) {
    const k = normalizeClientType(options.clientType) === 'enterprise' ? GCP_CLIENT_KEY : PERSONAL_CLIENT_KEY;
    put(k, options.customClientId, options.customClientSecret);
  }

  return byKey;
}

export function saveOAuthClientCredentials({ clientType = 'personal', clientId, clientSecret, dataDir = antigravityDataDir() }) {
  const id = typeof clientId === 'string' ? clientId.trim() : '';
  const secret = typeof clientSecret === 'string' ? clientSecret.trim() : '';
  if (!id || !secret) {
    throw new Error('OAuth client_id and client_secret must both be non-empty');
  }
  const key = normalizeClientType(clientType) === 'enterprise' ? GCP_CLIENT_KEY : PERSONAL_CLIENT_KEY;
  const label = key === GCP_CLIENT_KEY ? GCP_OAUTH_CLIENT.label : PERSONAL_OAUTH_CLIENT.label;
  const existing = loadOAuthClients({ dataDir, env: {} });
  existing.set(key, { key, label, clientId: id, clientSecret: secret });
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = oauthClientsFilePath(dataDir);
  const tmp = `${file}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, clients: [...existing.values()] }, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
  return existing.get(key);
}

export function resolveOAuthClientForType(options = {}) {
  const map = loadOAuthClients({
    dataDir: options.dataDir || antigravityDataDir(),
    env: options.env || process.env,
    options
  });
  const expectedKey = normalizeClientType(options.clientType) === 'enterprise'
    ? GCP_CLIENT_KEY
    : PERSONAL_CLIENT_KEY;
  const exact = map.get(expectedKey) || null;
  if (exact || !options.allowFallback) return exact;
  const fallbackKey = expectedKey === GCP_CLIENT_KEY ? PERSONAL_CLIENT_KEY : GCP_CLIENT_KEY;
  return map.get(fallbackKey) || [...map.values()][0] || null;
}

export function hasConfiguredOAuthClientForType(options = {}) {
  return Boolean(resolveOAuthClientForType(options));
}

export function hasConfiguredOAuthClient(options = {}) {
  return candidateOAuthClients(options).length > 0;
}

function candidateOAuthClients(options = {}) {
  const map = loadOAuthClients({
    dataDir: options.dataDir || antigravityDataDir(),
    env: options.env || process.env,
    options
  });
  const normalizedType = normalizeClientType(options.clientType);
  const orderedKeys = [];
  if (options.preferredClientKey) orderedKeys.push(String(options.preferredClientKey).trim().toLowerCase());
  orderedKeys.push(normalizedType === 'enterprise' ? GCP_CLIENT_KEY : PERSONAL_CLIENT_KEY);
  orderedKeys.push(normalizedType === 'enterprise' ? PERSONAL_CLIENT_KEY : GCP_CLIENT_KEY);

  const seen = new Set();
  const out = [];
  for (const k of orderedKeys) {
    if (seen.has(k)) continue;
    seen.add(k);
    const cfg = map.get(k);
    if (cfg) out.push(cfg);
  }
  for (const cfg of map.values()) {
    if (!seen.has(cfg.key)) {
      seen.add(cfg.key);
      out.push(cfg);
    }
  }
  return out;
}

const HOP_BY_HOP_H2_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'host'
]);

const H2_SESSION_IDLE_MS = 60 * 1000;
const h2ProxySessionPool = new Map();

function decodeCompressedNodeStream(stream, contentEncoding) {
  const enc = String(contentEncoding || '').trim().toLowerCase();
  if (enc === 'gzip' || enc === 'x-gzip') {
    const gunzip = zlib.createGunzip();
    stream.pipe(gunzip);
    return { stream: gunzip, decoded: true };
  }
  if (enc === 'deflate') {
    const inflate = zlib.createInflate();
    stream.pipe(inflate);
    return { stream: inflate, decoded: true };
  }
  return { stream, decoded: false };
}

function getPooledH2Session(poolKey) {
  if (!poolKey) return null;
  const entry = h2ProxySessionPool.get(poolKey);
  if (!entry) return null;
  if (entry.session.closed || entry.session.destroyed) {
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    h2ProxySessionPool.delete(poolKey);
    return null;
  }
  if (entry.idleTimer) {
    clearTimeout(entry.idleTimer);
    entry.idleTimer = null;
  }
  return entry;
}

function releasePooledH2Session(poolKey, entry) {
  if (!poolKey || !entry) return;
  entry.activeStreams = Math.max(0, entry.activeStreams - 1);
  if (entry.session.closed || entry.session.destroyed) {
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    if (h2ProxySessionPool.get(poolKey) === entry) h2ProxySessionPool.delete(poolKey);
    return;
  }
  if (entry.activeStreams === 0 && !entry.idleTimer) {
    entry.idleTimer = setTimeout(() => {
      entry.idleTimer = null;
      if (entry.activeStreams === 0) {
        if (h2ProxySessionPool.get(poolKey) === entry) h2ProxySessionPool.delete(poolKey);
        try { entry.session.close(); } catch {}
      }
    }, H2_SESSION_IDLE_MS);
    if (typeof entry.idleTimer.unref === 'function') entry.idleTimer.unref();
  }
}

function registerPooledH2Session(poolKey, session) {
  const entry = { session, activeStreams: 0, idleTimer: null };
  const evict = () => {
    if (entry.idleTimer) {
      clearTimeout(entry.idleTimer);
      entry.idleTimer = null;
    }
    if (h2ProxySessionPool.get(poolKey) === entry) {
      h2ProxySessionPool.delete(poolKey);
    }
  };
  session.once('close', evict);
  session.once('goaway', evict);
  session.on('error', evict);
  h2ProxySessionPool.set(poolKey, entry);
  return entry;
}

function normalizeProxyBody(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) return body;
  if (body instanceof URLSearchParams) return body.toString();
  return String(body);
}

function h2PoolKeyFor(proxyUrl, origin, tlsOptions) {
  const keys = tlsOptions && typeof tlsOptions === 'object' ? Object.keys(tlsOptions) : [];
  if (keys.length === 0) return `${proxyUrl || 'direct'}|${origin}`;
  if (keys.length === 1 && keys[0] === 'rejectUnauthorized') {
    return `${proxyUrl || 'direct'}|${origin}|reject=${String(tlsOptions.rejectUnauthorized)}`;
  }
  return '';
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// Bun's fetch supports `{ proxy }` directly; Node's global fetch ignores `{ proxy }` and
// defaults to HTTP/1.1. Under Node we use node:http2 (ALPN h2 with HTTP/1.1 fallback) with
// pooled H2 session reuse and transparent gzip/deflate decoding for both direct HTTPS and
// HTTP/HTTPS CONNECT proxy tunnels.
async function nodeHttpFetch(url, init = {}, proxyUrl = '', tlsOptions = {}, redirectsLeft = 5) {
  const res = await nodeHttpFetchOnce(url, init, proxyUrl, tlsOptions);
  if (
    redirectsLeft > 0 &&
    init.redirect !== 'manual' &&
    REDIRECT_STATUSES.has(res.status)
  ) {
    const loc = res.headers.get('location');
    if (loc) {
      try { await res.body?.cancel?.(); } catch {}
      const nextUrl = new URL(loc, url).toString();
      const method = (init.method || 'GET').toUpperCase();
      const nextInit = { ...init };
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
        nextInit.method = 'GET';
        delete nextInit.body;
      }
      return nodeHttpFetch(nextUrl, nextInit, proxyUrl, tlsOptions, redirectsLeft - 1);
    }
  }
  return res;
}

function nodeHttpFetchOnce(url, init = {}, proxyUrl = '', tlsOptions = {}) {
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    throw new Error(`Unsupported target protocol: ${target.protocol}`);
  }
  const proxy = proxyUrl ? new URL(proxyUrl) : null;
  if (proxy && proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
    throw new Error(`Node 运行时仅内置支持 http/https 代理，暂不支持 ${proxy.protocol}（在 Magpie / Bun 运行时中支持 socks5）`);
  }

  const targetPort = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  const proxyPort = proxy ? Number(proxy.port || (proxy.protocol === 'https:' ? 443 : 80)) : 0;
  const authHeader = proxy && (proxy.username || proxy.password)
    ? 'Basic ' + Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString('base64')
    : null;
  const h2PoolKey = target.protocol === 'https:' ? h2PoolKeyFor(proxyUrl, target.origin, tlsOptions) : '';

  return new Promise((resolve, reject) => {
    const signal = init.signal;
    if (signal?.aborted) {
      reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
      return;
    }

    let settled = false;
    let activeReq = null;
    let activeSocket = null;
    let activeH2Session = null;
    let pooledEntry = null;
    let releasedPool = false;

    const releasePool = () => {
      if (releasedPool || !pooledEntry) return;
      releasedPool = true;
      releasePooledH2Session(h2PoolKey, pooledEntry);
    };

    const onAbort = () => {
      const err = signal.reason || new DOMException('The operation was aborted.', 'AbortError');
      try { activeReq?.close?.(); } catch {}
      try { activeReq?.destroy?.(err); } catch {}
      if (pooledEntry) {
        releasePool();
      } else {
        try { activeH2Session?.destroy?.(err); } catch {}
        try { activeSocket?.destroy?.(err); } catch {}
      }
      if (!settled) {
        settled = true;
        reject(err);
      }
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    const cleanupAbort = () => signal?.removeEventListener('abort', onAbort);

    const fail = err => {
      cleanupAbort();
      if (pooledEntry) {
        releasePool();
      } else {
        try { activeH2Session?.destroy?.(); } catch {}
        try { activeSocket?.destroy?.(); } catch {}
      }
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const sendHttp1OverConnection = conn => {
      const headers = {};
      if (init.headers) {
        new Headers(init.headers).forEach((v, k) => { headers[k] = v; });
      }
      if (!Object.keys(headers).some(k => k.toLowerCase() === 'accept-encoding')) {
        headers['accept-encoding'] = 'gzip';
      }
      const reqMod = target.protocol === 'https:' ? https : http;
      const reqOpts = {
        hostname: target.hostname,
        port: targetPort,
        path: `${target.pathname}${target.search}`,
        method: init.method || 'GET',
        headers,
        createConnection: () => conn
      };

      const req = reqMod.request(reqOpts, res => {
        if (settled) {
          res.resume();
          return;
        }
        settled = true;
        const respHeaders = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) {
            for (const item of v) respHeaders.append(k, item);
          } else if (v !== undefined) {
            respHeaders.set(k, v);
          }
        }
        const status = res.statusCode || 502;
        const noBody = status === 204 || status === 205 || status === 304 || (init.method || 'GET').toUpperCase() === 'HEAD';
        const { stream: decodedStream, decoded } = noBody
          ? { stream: res, decoded: false }
          : decodeCompressedNodeStream(res, respHeaders.get('content-encoding'));
        if (decoded) {
          respHeaders.delete('content-encoding');
          respHeaders.delete('content-length');
        }
        const bodyStream = noBody ? null : new ReadableStream({
          start(controller) {
            decodedStream.on('data', chunk => controller.enqueue(chunk));
            decodedStream.on('end', () => {
              cleanupAbort();
              controller.close();
            });
            decodedStream.on('error', err => {
              cleanupAbort();
              controller.error(err);
            });
            if (decoded) {
              res.on('error', err => {
                cleanupAbort();
                decodedStream.destroy(err);
              });
            }
          },
          cancel() {
            cleanupAbort();
            if (decoded) decodedStream.destroy();
            res.destroy();
          }
        });
        if (noBody) {
          res.resume();
          res.on('end', cleanupAbort);
        }
        resolve(new Response(bodyStream, {
          status,
          statusText: res.statusMessage || '',
          headers: respHeaders
        }));
      });
      activeReq = req;
      req.on('error', fail);

      const bodyPayload = normalizeProxyBody(init.body);
      if (bodyPayload !== null) req.end(bodyPayload);
      else req.end();
    };

    const sendHttp2Request = (h2Session, entry = null) => {
      activeH2Session = h2Session;
      pooledEntry = entry;
      if (entry) entry.activeStreams += 1;
      const finishSession = () => {
        if (entry) {
          releasePool();
        } else {
          try { h2Session.close(); } catch {}
        }
      };

      const method = (init.method || 'GET').toUpperCase();
      const h2Headers = {
        ':method': method,
        ':path': `${target.pathname}${target.search}`,
        ':scheme': 'https',
        ':authority': target.host
      };
      let hasAcceptEncoding = false;
      if (init.headers) {
        new Headers(init.headers).forEach((v, k) => {
          const lk = k.toLowerCase();
          if (lk === 'accept-encoding') hasAcceptEncoding = true;
          if (!HOP_BY_HOP_H2_HEADERS.has(lk) && !lk.startsWith(':')) {
            h2Headers[lk] = v;
          }
        });
      }
      if (!hasAcceptEncoding) {
        h2Headers['accept-encoding'] = 'gzip';
      }

      let h2Req;
      try {
        h2Req = h2Session.request(h2Headers);
      } catch (err) {
        fail(err);
        return;
      }
      activeReq = h2Req;
      h2Req.on('error', fail);
      h2Req.on('response', headers => {
        if (settled) {
          h2Req.close();
          finishSession();
          return;
        }
        settled = true;
        const status = Number(headers[':status'] || 502);
        const respHeaders = new Headers();
        for (const [k, v] of Object.entries(headers)) {
          if (k.startsWith(':') || v === undefined) continue;
          if (Array.isArray(v)) {
            for (const item of v) respHeaders.append(k, item);
          } else {
            respHeaders.set(k, String(v));
          }
        }
        const noBody = status === 204 || status === 205 || status === 304 || method === 'HEAD';
        const { stream: decodedStream, decoded } = noBody
          ? { stream: h2Req, decoded: false }
          : decodeCompressedNodeStream(h2Req, respHeaders.get('content-encoding'));
        if (decoded) {
          respHeaders.delete('content-encoding');
          respHeaders.delete('content-length');
        }
        const bodyStream = noBody ? null : new ReadableStream({
          start(controller) {
            decodedStream.on('data', chunk => controller.enqueue(chunk));
            decodedStream.on('end', () => {
              cleanupAbort();
              finishSession();
              controller.close();
            });
            decodedStream.on('error', err => {
              cleanupAbort();
              finishSession();
              controller.error(err);
            });
            if (decoded) {
              h2Req.on('error', err => {
                cleanupAbort();
                decodedStream.destroy(err);
              });
            }
          },
          cancel() {
            cleanupAbort();
            if (decoded) decodedStream.destroy();
            try { h2Req.close(); } catch {}
            finishSession();
          }
        });
        if (noBody) {
          h2Req.resume();
          h2Req.on('end', () => {
            cleanupAbort();
            finishSession();
          });
        }
        resolve(new Response(bodyStream, {
          status,
          headers: respHeaders
        }));
      });

      const bodyPayload = normalizeProxyBody(init.body);
      if (bodyPayload !== null) h2Req.end(bodyPayload);
      else h2Req.end();
    };

    const existingH2 = getPooledH2Session(h2PoolKey);
    if (existingH2) {
      sendHttp2Request(existingH2.session, existingH2);
      return;
    }

    const sendHttp2OverTls = tlsSocket => {
      const h2Session = http2.connect(target.origin, {
        createConnection: () => tlsSocket
      });
      let entry = null;
      if (h2PoolKey) {
        entry = registerPooledH2Session(h2PoolKey, h2Session);
      } else {
        h2Session.on('error', fail);
      }
      sendHttp2Request(h2Session, entry);
    };

    const sendOverSocket = socket => {
      if (target.protocol !== 'https:') {
        sendHttp1OverConnection(socket);
        return;
      }
      const tlsSocket = tls.connect({
        ...tlsOptions,
        socket,
        ...(net.isIP(target.hostname) === 0 ? { servername: target.hostname } : {}),
        ALPNProtocols: ['h2', 'http/1.1']
      });
      activeSocket = tlsSocket;
      tlsSocket.once('error', fail);
      tlsSocket.once('secureConnect', () => {
        if (settled || signal?.aborted) return;
        if (tlsSocket.alpnProtocol === 'h2') {
          sendHttp2OverTls(tlsSocket);
        } else {
          sendHttp1OverConnection(tlsSocket);
        }
      });
    };

    if (!proxy) {
      const tlsSocket = tls.connect({
        ...tlsOptions,
        host: target.hostname,
        port: targetPort,
        ...(net.isIP(target.hostname) === 0 ? { servername: target.hostname } : {}),
        ALPNProtocols: ['h2', 'http/1.1']
      });
      activeSocket = tlsSocket;
      tlsSocket.once('error', fail);
      tlsSocket.once('secureConnect', () => {
        if (settled || signal?.aborted) return;
        if (tlsSocket.alpnProtocol === 'h2') {
          sendHttp2OverTls(tlsSocket);
        } else {
          sendHttp1OverConnection(tlsSocket);
        }
      });
      return;
    }

    const proxyTransport = proxy.protocol === 'https:' ? https : http;
    const connectReq = proxyTransport.request({
      hostname: proxy.hostname,
      port: proxyPort,
      method: 'CONNECT',
      path: `${target.hostname}:${targetPort}`,
      headers: {
        Host: `${target.hostname}:${targetPort}`,
        ...(authHeader ? { 'Proxy-Authorization': authHeader } : {})
      }
    });
    activeReq = connectReq;
    connectReq.on('connect', (res, socket) => {
      activeSocket = socket;
      if (res.statusCode !== 200) {
        socket.destroy();
        cleanupAbort();
        if (!settled) {
          settled = true;
          reject(new Error(`Proxy CONNECT failed with HTTP ${res.statusCode}`));
        }
        return;
      }
      sendOverSocket(socket);
    });
    connectReq.on('error', err => {
      cleanupAbort();
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
    connectReq.end();
  });
}

export async function fetchWithProxy(url, init = {}, options = {}) {
  const fetchFn = options.fetchFn || globalThis.fetch;
  const rawProxy = options.proxy ? validateProxyURL(options.proxy) : '';
  const signal = options.signal || (options.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : init.signal);
  const reqInit = { ...init, ...(signal ? { signal } : {}) };

  if (!options.fetchFn && !globalThis.Bun) {
    if (rawProxy || String(url).startsWith('https://')) {
      return nodeHttpFetch(url, reqInit, rawProxy, options.tlsOptions);
    }
  }
  if (rawProxy) {
    reqInit.proxy = rawProxy;
  }
  return fetchFn(url, reqInit);
}

function safeEqualString(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function callbackHtml({ ok, title, message }) {
  const accent = ok ? '#10b981' : '#ef4444';
  const badge = ok ? '✓' : '!';
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#f8fafc}
    .card{max-width:440px;padding:32px;border-radius:16px;background:#1e293b;border:1px solid #334155;text-align:center;box-shadow:0 12px 32px rgba(0,0,0,.35)}
    .badge{width:52px;height:52px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;background:${accent};color:#fff;margin-bottom:16px}
    h1{margin:0 0 10px;font-size:20px}
    p{margin:0;font-size:14px;line-height:1.6;color:#cbd5e1;word-break:break-word}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">${badge}</div>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

export function createPkcePair() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const state = crypto.randomBytes(24).toString('base64url');
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
    state
  };
}

export function buildOAuthAuthorizeUrl({
  clientId,
  redirectUri,
  state,
  codeChallenge,
  scopes = OAUTH_SCOPES,
  loginHint
} = {}) {
  const cid = typeof clientId === 'string' ? clientId.trim() : '';
  const redir = typeof redirectUri === 'string' ? redirectUri.trim() : '';
  if (!cid) {
    throw new Error('缺少 Google OAuth client_id，无法构建授权链接');
  }
  if (!redir) {
    throw new Error('缺少 OAuth redirect_uri，无法构建授权链接');
  }
  const url = new URL(OAUTH_AUTH_URL);
  url.searchParams.set('client_id', cid);
  url.searchParams.set('redirect_uri', redir);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', (Array.isArray(scopes) ? scopes.join(' ') : String(scopes || '')).trim());
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'consent');
  url.searchParams.set('include_granted_scopes', 'true');
  if (typeof state === 'string' && state.trim()) {
    url.searchParams.set('state', state.trim());
  }
  if (typeof codeChallenge === 'string' && codeChallenge.trim()) {
    url.searchParams.set('code_challenge', codeChallenge.trim());
    url.searchParams.set('code_challenge_method', 'S256');
  }
  if (typeof loginHint === 'string' && loginHint.trim()) {
    url.searchParams.set('login_hint', loginHint.trim());
  }
  return url.toString();
}

export function parseOAuthCallbackInput(raw, { expectedState } = {}) {
  const trimmed = typeof raw === 'string' ? raw.trim() : '';
  if (!trimmed) {
    throw new Error('没有收到回调链接或 Authorization Code，请粘贴浏览器跳转后的完整链接或授权码');
  }

  let params = null;
  let redirectUri;
  if (/^https?:\/\//i.test(trimmed)) {
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error('回调链接格式无效，请粘贴完整 URL 或 Authorization Code');
    }
    redirectUri = `${parsed.origin}${parsed.pathname}`;
    params = parsed.searchParams;
    if (!params.get('code') && !params.get('error') && parsed.hash) {
      params = new URLSearchParams(parsed.hash.replace(/^#/, ''));
    }
  } else if (trimmed.startsWith('?') || (trimmed.includes('=') && /(?:^|[?&])(?:code|error)=/.test(trimmed))) {
    params = new URLSearchParams(trimmed.replace(/^[?#]/, ''));
  }

  if (params) {
    const oauthError = params.get('error');
    if (oauthError) {
      const desc = params.get('error_description');
      throw new Error(`Google OAuth 授权失败：${oauthError}${desc ? ` (${desc})` : ''}`);
    }
    const code = (params.get('code') || '').trim();
    if (!code) {
      throw new Error('回调链接中未包含 code 参数，请确认复制了完整跳转地址或直接粘贴 Authorization Code');
    }
    const state = (params.get('state') || '').trim();
    if (expectedState && state && !safeEqualString(expectedState, state)) {
      throw new Error('OAuth state 校验不匹配，请重新发起授权');
    }
    return {
      code,
      ...(state ? { state } : {}),
      ...(redirectUri ? { redirectUri } : {})
    };
  }

  return { code: trimmed };
}

export async function startOAuthCallbackServer({
  port = 0,
  state,
  callbackPath = OAUTH_CALLBACK_PATH,
  timeoutMs = 5 * 60 * 1000,
  signal
} = {}) {
  if (typeof callbackPath !== 'string' || !callbackPath.startsWith('/')) {
    throw new Error('OAuth callbackPath must start with "/"');
  }
  const expectedState = typeof state === 'string' ? state.trim() : '';

  let settled = false;
  let resolveWait;
  let rejectWait;
  const codePromise = new Promise((resolve, reject) => {
    resolveWait = resolve;
    rejectWait = reject;
  });
  // Prevent unhandled rejection if caller closes server before awaiting waitForCode()
  codePromise.catch(() => {});

  let boundPort = Number.isInteger(port) && port > 0 ? port : 0;
  let timer = null;
  let closed = false;
  const servers = [];

  const cleanupTimers = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    if (signal && onAbort) {
      signal.removeEventListener('abort', onAbort);
    }
  };

  const finishResolve = payload => {
    if (settled) return;
    settled = true;
    cleanupTimers();
    resolveWait(payload);
  };

  const finishReject = err => {
    if (settled) return;
    settled = true;
    cleanupTimers();
    rejectWait(err);
  };

  const onAbort = () => {
    finishReject(signal?.reason || new DOMException('The operation was aborted.', 'AbortError'));
  };

  const sendHtml = (res, statusCode, html) => {
    res.writeHead(statusCode, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'"
    });
    res.end(html);
  };

  const handleRequest = (req, res) => {
    const reqUrl = new URL(req.url || '/', `http://localhost:${boundPort || 80}`);
    if (req.method === 'GET' && reqUrl.pathname === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed');
      return;
    }
    if (reqUrl.pathname !== callbackPath) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }

    const receivedState = (reqUrl.searchParams.get('state') || '').trim();
    if (expectedState && (!receivedState || !safeEqualString(expectedState, receivedState))) {
      sendHtml(res, 400, callbackHtml({
        ok: false,
        title: 'OAuth 状态校验失败',
        message: '回调参数中的 state 无效或已过期，请返回 Magpie 重新发起授权。'
      }));
      return;
    }

    const oauthError = (reqUrl.searchParams.get('error') || '').trim();
    if (oauthError) {
      const desc = (reqUrl.searchParams.get('error_description') || '').trim();
      sendHtml(res, 400, callbackHtml({
        ok: false,
        title: 'Google 授权未完成',
        message: `授权失败：${oauthError}${desc ? ` (${desc})` : ''}`
      }));
      finishReject(new Error(`Google OAuth 授权失败：${oauthError}${desc ? ` (${desc})` : ''}`));
      return;
    }

    const code = (reqUrl.searchParams.get('code') || '').trim();
    if (!code) {
      sendHtml(res, 400, callbackHtml({
        ok: false,
        title: '未收到授权码',
        message: '回调地址中缺少 code 参数，请返回 Magpie 重试。'
      }));
      return;
    }

    sendHtml(res, 200, callbackHtml({
      ok: true,
      title: 'Google OAuth 授权成功',
      message: '已获取到授权码并交给 Magpie 完成校验，现在可以关闭此浏览器标签页。'
    }));
    finishResolve({
      code,
      ...(receivedState ? { state: receivedState } : {}),
      redirectUri: `http://localhost:${boundPort}${callbackPath}`
    });
  };

  const ipv4Server = http.createServer(handleRequest);
  await new Promise((resolve, reject) => {
    const onErr = err => reject(err);
    ipv4Server.once('error', onErr);
    ipv4Server.listen(boundPort, '127.0.0.1', () => {
      ipv4Server.off('error', onErr);
      resolve();
    });
  });
  ipv4Server.unref?.();
  servers.push(ipv4Server);
  const addr = ipv4Server.address();
  if (addr && typeof addr === 'object' && Number.isInteger(addr.port)) {
    boundPort = addr.port;
  }

  // Best-effort sibling IPv6 loopback listener so localhost resolving to ::1 succeeds too.
  if (boundPort > 0) {
    const ipv6Server = http.createServer(handleRequest);
    await new Promise(resolve => {
      ipv6Server.once('error', () => {
        try { ipv6Server.close(); } catch {}
        resolve();
      });
      ipv6Server.listen(boundPort, '::1', () => {
        ipv6Server.unref?.();
        servers.push(ipv6Server);
        resolve();
      });
    });
  }

  const redirectUri = `http://localhost:${boundPort}${callbackPath}`;

  if (signal?.aborted) {
    onAbort();
  } else {
    signal?.addEventListener('abort', onAbort, { once: true });
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        finishReject(new Error(`等待 Google OAuth 浏览器回调超时（${Math.round(timeoutMs / 1000)} 秒），请重试或改用手动粘贴回调链接`));
      }, timeoutMs);
      timer.unref?.();
    }
  }

  const close = async () => {
    if (closed) return;
    closed = true;
    if (!settled) {
      finishReject(new Error('OAuth 回调服务已关闭'));
    } else {
      cleanupTimers();
    }
    await Promise.all(servers.map(s => new Promise(resolve => {
      try { s.closeAllConnections?.(); } catch {}
      try {
        s.close(() => resolve());
      } catch {
        resolve();
      }
    })));
  };

  return {
    port: boundPort,
    redirectUri,
    waitForCode: () => codePromise,
    close
  };
}

export async function exchangeAuthorizationCode({
  code,
  redirectUri,
  codeVerifier,
  clientType = 'personal',
  customClientId,
  customClientSecret,
  dataDir,
  env,
  options,
  proxy,
  fetchFn,
  timeoutMs,
  detectLocal
} = {}) {
  const authCode = typeof code === 'string' ? code.trim() : '';
  const redir = typeof redirectUri === 'string' ? redirectUri.trim() : '';
  if (!authCode) {
    throw new Error('缺少 Google OAuth Authorization Code');
  }
  if (!redir) {
    throw new Error('缺少 OAuth redirect_uri');
  }

  const clientCfg = resolveOAuthClientForType({
    clientType,
    customClientId,
    customClientSecret,
    dataDir,
    env,
    ...(options && typeof options === 'object' ? options : {})
  });
  if (!clientCfg) {
    throw new Error('缺少匹配的 Google OAuth client_id / client_secret：请在登录提示中填写，或运行 npm run antigravity:oauth 配置');
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: redir,
    client_id: clientCfg.clientId,
    client_secret: clientCfg.clientSecret
  });
  if (typeof codeVerifier === 'string' && codeVerifier.trim()) {
    form.set('code_verifier', codeVerifier.trim());
  }

  let res;
  try {
    res = await fetchWithProxy(OAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': currentOAuthUserAgent(uaResolveOptions(env || process.env, { dataDir, detectLocal }))
      },
      body: form.toString()
    }, {
      proxy,
      fetchFn,
      timeoutMs: timeoutMs ?? 20000
    });
  } catch (err) {
    throw new Error(`无法连接 Google OAuth 端点 (${err?.message || err})`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Authorization Code 换取 Token 失败 (HTTP ${res.status}): ${text}`);
  }

  const data = await res.json();
  if (!data?.access_token) {
    throw new Error('Google OAuth 返回结果缺少 access_token');
  }
  if (!data?.refresh_token || !String(data.refresh_token).startsWith('1//')) {
    throw new Error('Google 未返回 refresh_token（可能之前已授权过该应用）。请到 https://myaccount.google.com/permissions 撤销授权后重新登录，并确认授权页勾选全部权限。');
  }

  const expiresIn = Number(data.expires_in) > 0 ? Number(data.expires_in) : 3599;
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn,
    expiresAt: Date.now() + expiresIn * 1000,
    idToken: data.id_token || undefined,
    oauthClientKey: clientCfg.key,
    clientType: clientCfg.key === GCP_CLIENT_KEY ? 'enterprise' : 'personal'
  };
}

function isClientMismatchError(status, errorText) {
  const lower = String(errorText || '').toLowerCase();
  return status === 400 || status === 401 || status === 403 ||
    lower.includes('unauthorized_client') || lower.includes('invalid_client');
}

export async function refreshAccessToken(refreshToken, options = {}) {
  if (typeof refreshToken !== 'string' || !refreshToken.trim().startsWith('1//')) {
    throw new Error('Invalid refresh_token: must start with 1//');
  }
  const token = refreshToken.trim();
  const candidates = candidateOAuthClients(options);
  if (candidates.length === 0) {
    throw new Error('缺少 Google OAuth client_id / client_secret：请在登录提示中填写，或配置环境变量 ANTIGRAVITY_OAUTH_CLIENT_ID 与 ANTIGRAVITY_OAUTH_CLIENT_SECRET（或运行 npm run antigravity:oauth）');
  }
  const errors = [];
  let sawInvalidGrant = false;

  for (const clientCfg of candidates) {
    let lastStatus = null;
    let lastText = '';

    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) {
        await new Promise(resolve => setTimeout(resolve, options.retryDelayMs ?? 500));
      }

      let res;
      try {
        const body = new URLSearchParams({
          client_id: clientCfg.clientId,
          client_secret: clientCfg.clientSecret,
          refresh_token: token,
          grant_type: 'refresh_token'
        }).toString();
        res = await fetchWithProxy(OAUTH_TOKEN_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': currentOAuthUserAgent(uaResolveOptions(options.env || process.env, { dataDir: options.dataDir, detectLocal: options.detectLocal }))
          },
          body
        }, { ...options, timeoutMs: options.timeoutMs ?? 20000 });
      } catch (err) {
        lastStatus = null;
        lastText = `无法连接 Google OAuth 端点 (${err?.message || err})`;
        break;
      }

      if (res.ok) {
        const data = await res.json();
        if (!data?.access_token) {
          throw new Error('Google OAuth 返回结果缺少 access_token');
        }
        const expiresIn = Number(data.expires_in) > 0 ? Number(data.expires_in) : 3599;
        return {
          accessToken: data.access_token,
          refreshToken: data.refresh_token || token,
          expiresIn,
          expiresAt: Date.now() + expiresIn * 1000,
          idToken: data.id_token || undefined,
          oauthClientKey: clientCfg.key,
          clientType: clientCfg.key === GCP_OAUTH_CLIENT.key ? 'enterprise' : 'personal'
        };
      }

      lastStatus = res.status;
      lastText = await res.text().catch(() => '');
      if (lastText.includes('invalid_grant') && attempt === 0) {
        continue;
      }
      break;
    }

    if (lastText.includes('invalid_grant')) {
      sawInvalidGrant = true;
    }
    errors.push(`[${clientCfg.key}] ${lastStatus ? `HTTP ${lastStatus}: ` : ''}${lastText}`);

    const explicitClientMismatch = /unauthorized_client|invalid_client/i.test(lastText);
    const pinnedClient = Boolean(options.preferredClientKey);
    if (lastStatus !== null && isClientMismatchError(lastStatus, lastText) && (!pinnedClient || explicitClientMismatch)) {
      continue;
    }
    break;
  }

  const err = new Error(`Refresh Token 换取 access_token 失败：${errors.join(' | ')}`);
  if (sawInvalidGrant) {
    err.invalidGrant = true;
    err.signIn = 'expired';
  }
  throw err;
}

export async function fetchUserInfo(accessToken, options = {}) {
  const res = await fetchWithProxy(OAUTH_USERINFO_URL, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'User-Agent': currentOAuthUserAgent(uaResolveOptions(options.env || process.env, { dataDir: options.dataDir, detectLocal: options.detectLocal }))
    }
  }, { ...options, timeoutMs: options.timeoutMs ?? 15000 });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`获取 Google 用户信息失败 (HTTP ${res.status}): ${text}`);
  }
  const info = await res.json();
  if (!info?.email) {
    throw new Error('Google 用户信息中缺少 email 字段');
  }
  return {
    email: String(info.email),
    name: info.name || [info.given_name, info.family_name].filter(Boolean).join(' ') || undefined
  };
}

export function normalizeSubscriptionTier(rawTier) {
  const s = String(rawTier || '').trim().toLowerCase();
  if (!s) return 'FREE';
  if (s.includes('ultra')) return 'ULTRA';
  if (s.includes('pro')) return 'PRO';
  return 'FREE';
}

export function isSandboxEndpoint(url) {
  return String(url || '').includes('sandbox.googleapis.com');
}

function selectEndpoints(list, options = {}) {
  if (options?.sandboxFallback === true) return list;
  const filtered = list.filter(u => !isSandboxEndpoint(u));
  return filtered.length > 0 ? filtered : list;
}

export function shouldFallbackEndpoint(status, url) {
  if (status === 400) return isSandboxEndpoint(url);
  return status === 408 || status === 404 || status === 429 || status >= 500;
}

function extractProjectId(raw) {
  if (typeof raw === 'string') return raw.trim() || null;
  if (raw && typeof raw === 'object' && typeof raw.id === 'string') {
    return raw.id.trim() || null;
  }
  return null;
}

function cloudCodePlatform(platform = process.platform, arch = process.arch) {
  if (platform === 'darwin') return arch === 'arm64' ? 'DARWIN_ARM64' : 'DARWIN_AMD64';
  if (platform === 'win32') return 'WINDOWS_AMD64';
  if (platform === 'linux') return arch === 'arm64' ? 'LINUX_ARM64' : 'LINUX_AMD64';
  return 'PLATFORM_UNSPECIFIED';
}

export function parseAvailableCredits(rawList) {
  if (!Array.isArray(rawList)) return [];
  const out = [];
  for (const item of rawList) {
    if (!item || typeof item !== 'object') continue;
    const creditType = String(item.creditType ?? item.credit_type ?? '').trim();
    if (!creditType) continue;
    const amountRaw = item.creditAmount ?? item.credit_amount;
    const minRaw = item.minimumCreditAmountForUsage ??
      item.minimum_credit_amount_for_usage ??
      item.minimumUsableCreditAmount ??
      item.minimum_usable_credit_amount;
    const creditAmount = amountRaw !== undefined && amountRaw !== null && String(amountRaw).trim() !== ''
      ? Number(amountRaw)
      : null;
    const minimumCreditAmountForUsage = minRaw !== undefined && minRaw !== null && String(minRaw).trim() !== ''
      ? Number(minRaw)
      : 0;
    out.push({
      creditType,
      ...(Number.isFinite(creditAmount) ? { creditAmount } : {}),
      ...(Number.isFinite(minimumCreditAmountForUsage) ? { minimumCreditAmountForUsage } : {})
    });
  }
  return out;
}

export async function loadCodeAssist(accessToken, options = {}) {
  const ideType = options.ideType || 'ANTIGRAVITY';
  const payload = JSON.stringify({ metadata: { ideType } });
  let lastErr;

  for (const url of selectEndpoints(LOAD_CODE_ASSIST_ENDPOINTS, options)) {
    let res;
    try {
      res = await fetchWithProxy(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': currentEgressUserAgent(uaResolveOptions(options.env || process.env, { dataDir: options.dataDir, detectLocal: options.detectLocal }))
        },
        body: payload
      }, { ...options, timeoutMs: options.timeoutMs ?? 15000 });
    } catch (err) {
      lastErr = err;
      continue;
    }

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      lastErr = new Error(`loadCodeAssist (${url}) HTTP ${res.status}: ${text}`);
      if (shouldFallbackEndpoint(res.status, url)) continue;
      throw lastErr;
    }

    const data = await res.json();
    const projectId = extractProjectId(data?.cloudaicompanionProject);
    const onboardTierId =
      (typeof data?.currentTier?.id === 'string' && data.currentTier.id.trim()) ||
      data?.allowedTiers?.find?.(t => t?.isDefault && typeof t?.id === 'string')?.id?.trim() ||
      data?.allowedTiers?.find?.(t => t?.id === 'free-tier' || t?.id === 'legacy-tier')?.id ||
      data?.allowedTiers?.find?.(t => typeof t?.id === 'string')?.id?.trim() ||
      'free-tier';
    const rawTier = data?.paidTier?.id || data?.paidTier?.name ||
      data?.currentTier?.id || data?.currentTier?.name ||
      onboardTierId ||
      'free-tier';
    const allowedUsesGcpTos = Array.isArray(data?.allowedTiers) &&
      data.allowedTiers.some(t => t?.usesGcpTos === true && t?.id === data?.currentTier?.id);
    const availableCredits = parseAvailableCredits(data?.paidTier?.availableCredits || data?.availableCredits);
    return {
      projectId,
      rawTier,
      tier: normalizeSubscriptionTier(rawTier),
      usesGcpTos: allowedUsesGcpTos,
      onboardTierId,
      ...(availableCredits.length > 0 ? { availableCredits } : {})
    };
  }

  throw lastErr || new Error('loadCodeAssist 所有端点均不可用');
}

export async function onboardCodeAssistUser(accessToken, options = {}) {
  const tierId = typeof options.tierId === 'string' && options.tierId.trim() ? options.tierId.trim() : 'free-tier';
  const ideType = options.ideType || 'ANTIGRAVITY';
  const platform = options.cloudCodePlatform || cloudCodePlatform(options.platform, options.arch);
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 15000;
  const maxPollAttempts = Number.isInteger(options.maxPollAttempts) && options.maxPollAttempts >= 0
    ? options.maxPollAttempts
    : 6;
  const pollIntervalMs = Number.isFinite(options.pollIntervalMs) && options.pollIntervalMs >= 0
    ? options.pollIntervalMs
    : 1500;
  const ua = currentEgressUserAgent(uaResolveOptions(options.env || process.env, {
    dataDir: options.dataDir,
    detectLocal: options.detectLocal
  }));
  const payload = JSON.stringify({
    tierId,
    metadata: {
      ideType,
      platform,
      pluginType: 'GEMINI'
    }
  });

  const startedAt = Date.now();
  for (const url of selectEndpoints(ONBOARD_USER_ENDPOINTS, options)) {
    let res;
    try {
      res = await fetchWithProxy(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': ua
        },
        body: payload
      }, { ...options, timeoutMs });
    } catch {
      continue;
    }

    if (!res.ok) {
      if (shouldFallbackEndpoint(res.status, url)) continue;
      return null;
    }

    let op;
    try {
      op = await res.json();
    } catch {
      return null;
    }

    const immediate = extractProjectId(op?.response?.cloudaicompanionProject) ||
      extractProjectId(op?.cloudaicompanionProject);
    if (immediate) return immediate;
    if (op?.done === true) return null;

    const opName = typeof op?.name === 'string' ? op.name.trim().replace(/^\/+/, '') : '';
    if (!opName || maxPollAttempts === 0) return null;

    const base = url.slice(0, url.indexOf(':onboardUser'));
    const pollUrl = `${base}/${opName}`;
    for (let attempt = 0; attempt < maxPollAttempts; attempt++) {
      if (Date.now() - startedAt >= timeoutMs) return null;
      if (pollIntervalMs > 0) {
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
      }
      if (Date.now() - startedAt >= timeoutMs) return null;

      let pollRes;
      try {
        pollRes = await fetchWithProxy(pollUrl, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
            'User-Agent': ua
          }
        }, { ...options, timeoutMs: Math.max(2000, timeoutMs - (Date.now() - startedAt)) });
      } catch {
        continue;
      }
      if (!pollRes.ok) {
        if (pollRes.status === 404 || pollRes.status === 429 || pollRes.status >= 500) continue;
        return null;
      }
      const nextOp = await pollRes.json().catch(() => null);
      const provisioned = extractProjectId(nextOp?.response?.cloudaicompanionProject) ||
        extractProjectId(nextOp?.cloudaicompanionProject);
      if (provisioned) return provisioned;
      if (nextOp?.done === true) return null;
    }
    return null;
  }

  return null;
}

function classify403Text(text) {
  const lower = String(text || '').toLowerCase();
  const isValidation = lower.includes('validation_required') ||
    lower.includes('validation_url') ||
    lower.includes('verify your account') ||
    lower.includes('further action is required');
  let validationUrl;
  try {
    const parsed = JSON.parse(text);
    const details = parsed?.error?.details;
    if (Array.isArray(details)) {
      for (const d of details) {
        if (typeof d?.metadata?.validation_url === 'string') {
          validationUrl = d.metadata.validation_url;
          break;
        }
      }
    }
  } catch {}
  return { isValidation, validationUrl };
}

export async function fetchAvailableModels(accessToken, projectId, options = {}) {
  const payload = JSON.stringify(projectId ? { project: projectId } : {});
  let lastErr;

  for (const url of selectEndpoints(FETCH_MODELS_ENDPOINTS, options)) {
    let res;
    try {
      res = await fetchWithProxy(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': currentEgressUserAgent(uaResolveOptions(options.env || process.env, { dataDir: options.dataDir, detectLocal: options.detectLocal }))
        },
        body: payload
      }, { ...options, timeoutMs: options.timeoutMs ?? 15000 });
    } catch (err) {
      lastErr = err;
      continue;
    }

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      if (res.status === 401) {
        const err = new Error(`Antigravity 鉴权失败 (HTTP 401): ${text}`);
        err.status = 401;
        err.signIn = 'expired';
        throw err;
      }
      if (res.status === 403) {
        const { isValidation, validationUrl } = classify403Text(text);
        const msg = isValidation
          ? `账号需要完成 Google 验证才能使用 Antigravity${validationUrl ? `：${validationUrl}` : ''}`
          : `账号无权访问 Antigravity (HTTP 403): ${text}`;
        const err = new Error(msg);
        err.status = 403;
        err.validationRequired = isValidation;
        err.validationUrl = validationUrl;
        throw err;
      }
      lastErr = new Error(`fetchAvailableModels (${url}) HTTP ${res.status}: ${text}`);
      lastErr.status = res.status;
      if (shouldFallbackEndpoint(res.status, url)) continue;
      throw lastErr;
    }

    return res.json();
  }

  throw lastErr || new Error('fetchAvailableModels 所有端点均不可用');
}

export async function fetchQuotaSummary(accessToken, projectId, options = {}) {
  const payload = JSON.stringify(projectId ? { project: projectId } : {});
  for (const url of selectEndpoints(QUOTA_SUMMARY_ENDPOINTS, options)) {
    try {
      const res = await fetchWithProxy(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': currentEgressUserAgent(uaResolveOptions(options.env || process.env, { dataDir: options.dataDir, detectLocal: options.detectLocal }))
        },
        body: payload
      }, { ...options, timeoutMs: options.timeoutMs ?? 15000 });
      if (res.ok) {
        return await res.json();
      }
      if (!shouldFallbackEndpoint(res.status, url)) return null;
    } catch {
      continue;
    }
  }
  return null;
}

export async function setAntigravityPrivacy(accessToken, projectId, options = {}) {
  if (!accessToken) return null;
  const ua = currentEgressUserAgent(uaResolveOptions(options.env || process.env, {
    dataDir: options.dataDir,
    detectLocal: options.detectLocal
  }));
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'User-Agent': ua
  };
  const timeoutMs = Number.isFinite(options.privacyTimeoutMs) ? options.privacyTimeoutMs : 10000;

  let setRes;
  try {
    setRes = await fetchWithProxy(`${ANTIGRAVITY_PRIVACY_BASE}:setUserSettings`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ user_settings: {} })
    }, { ...options, timeoutMs });
  } catch {
    return null;
  }
  if (!setRes.ok) {
    return { privacyMode: 'privacy_set_failed', step: 'setUserSettings', status: setRes.status };
  }
  let setBody;
  try {
    setBody = await setRes.json();
  } catch {
    return { privacyMode: 'privacy_set_failed', step: 'setUserSettings' };
  }
  if (setBody?.userSettings && Object.prototype.hasOwnProperty.call(setBody.userSettings, 'telemetryEnabled')) {
    return { privacyMode: 'privacy_set_failed', step: 'setUserSettings' };
  }

  const normalizedProject = typeof projectId === 'string' ? projectId.trim() : '';
  if (!normalizedProject) {
    return { privacyMode: 'privacy_set_failed', step: 'fetchUserInfo' };
  }

  let verifyRes;
  try {
    verifyRes = await fetchWithProxy(`${ANTIGRAVITY_PRIVACY_BASE}:fetchUserInfo`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ project: normalizedProject })
    }, { ...options, timeoutMs });
  } catch {
    return { privacyMode: 'privacy_set_failed', step: 'fetchUserInfo' };
  }
  if (!verifyRes.ok) {
    return { privacyMode: 'privacy_set_failed', step: 'fetchUserInfo', status: verifyRes.status };
  }
  let infoBody;
  try {
    infoBody = await verifyRes.json();
  } catch {
    return { privacyMode: 'privacy_set_failed', step: 'fetchUserInfo' };
  }
  if (infoBody?.userSettings && Object.prototype.hasOwnProperty.call(infoBody.userSettings, 'telemetryEnabled')) {
    return { privacyMode: 'privacy_set_failed', step: 'fetchUserInfo' };
  }

  return { privacyMode: 'privacy_set' };
}

export async function completeAccountVerification(tokenData, options = {}) {
  const userInfo = await fetchUserInfo(tokenData.accessToken, options);
  const isPersonalEmail = /@(gmail|googlemail)\.com$/i.test(userInfo.email);
  const ideType = options.clientType === 'enterprise' || !isPersonalEmail ? 'JETSKI' : 'ANTIGRAVITY';
  const projectInfo = await loadCodeAssist(tokenData.accessToken, { ...options, ideType }).catch(() => ({
    projectId: null,
    tier: 'FREE',
    rawTier: 'free-tier',
    usesGcpTos: false,
    onboardTierId: 'free-tier'
  }));
  let provisionedProjectId = projectInfo.projectId;
  if (!provisionedProjectId && options.autoOnboard !== false && projectInfo.onboardTierId) {
    provisionedProjectId = await onboardCodeAssistUser(tokenData.accessToken, {
      ...options,
      tierId: projectInfo.onboardTierId,
      ideType
    }).catch(() => null);
  }
  const projectId = provisionedProjectId || DEFAULT_FALLBACK_PROJECT_ID;
  const catalog = await fetchAvailableModels(tokenData.accessToken, provisionedProjectId, options);
  const modelsCount = catalog?.models && typeof catalog.models === 'object'
    ? Object.keys(catalog.models).length
    : 0;
  const privacy = options.autoPrivacy === true
    ? await setAntigravityPrivacy(tokenData.accessToken, provisionedProjectId || projectId, options).catch(() => null)
    : null;

  return {
    id: userInfo.email.toLowerCase(),
    email: userInfo.email,
    name: userInfo.name,
    refreshToken: tokenData.refreshToken,
    accessToken: tokenData.accessToken,
    expiresAt: tokenData.expiresAt,
    oauthClientKey: tokenData.oauthClientKey,
    clientType: tokenData.clientType,
    projectId,
    tier: projectInfo.tier,
    rawTier: projectInfo.rawTier,
    modelsCount,
    ...(Array.isArray(projectInfo.availableCredits) && projectInfo.availableCredits.length > 0
      ? { availableCredits: projectInfo.availableCredits }
      : {}),
    ...(privacy?.privacyMode ? { privacyMode: privacy.privacyMode } : {}),
    ...(options.proxy ? { proxy: validateProxyURL(options.proxy) } : {}),
    updatedAt: Date.now()
  };
}

export async function verifyRefreshToken(refreshToken, options = {}) {
  const tokenData = await refreshAccessToken(refreshToken, options);
  return completeAccountVerification(tokenData, options);
}

export async function verifyAuthorizationCode(options = {}) {
  const tokenData = await exchangeAuthorizationCode(options);
  return completeAccountVerification(tokenData, options);
}

function accountsFilePath(dataDir) {
  return path.join(dataDir, 'accounts.json');
}

export function loadAntigravityAccounts(dataDir = antigravityDataDir()) {
  const file = accountsFilePath(dataDir);
  if (!fs.existsSync(file)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.accounts)) return [];
    return parsed.accounts.filter(a => a && typeof a.refreshToken === 'string' && a.refreshToken.startsWith('1//'));
  } catch {
    return [];
  }
}

export function writeAntigravityAccounts(accounts, dataDir = antigravityDataDir()) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = accountsFilePath(dataDir);
  const tmp = `${file}.tmp.${process.pid}.${Date.now()}`;
  const content = JSON.stringify({ version: 1, accounts }, null, 2) + '\n';
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function saveAntigravityAccount(account, dataDir = antigravityDataDir()) {
  const list = loadAntigravityAccounts(dataDir);
  const id = String(account.id || account.email || '').trim().toLowerCase();
  const normalized = { ...account, id };
  const idx = list.findIndex(a => a.id === id || (a.refreshToken && a.refreshToken === normalized.refreshToken));
  if (idx >= 0) {
    list[idx] = { ...list[idx], ...normalized };
  } else {
    list.push(normalized);
  }
  writeAntigravityAccounts(list, dataDir);
  return normalized;
}

export function removeAntigravityAccount(idOrEmail, dataDir = antigravityDataDir()) {
  const target = String(idOrEmail || '').trim().toLowerCase();
  const list = loadAntigravityAccounts(dataDir);
  const next = list.filter(a => a.id !== target && String(a.email || '').toLowerCase() !== target);
  if (next.length !== list.length) {
    writeAntigravityAccounts(next, dataDir);
    return true;
  }
  return false;
}

export async function ensureFreshAccountToken(account, options = {}) {
  const now = options.now ?? Date.now();
  const skewMs = Number.isFinite(options.refreshSkewMs)
    ? options.refreshSkewMs
    : (options.now !== undefined
      ? TOKEN_REFRESH_SKEW_MS
      : TOKEN_REFRESH_SKEW_MIN_MS + Math.floor(Math.random() * (TOKEN_REFRESH_SKEW_MAX_MS - TOKEN_REFRESH_SKEW_MIN_MS)));
  if (
    account.accessToken &&
    Number.isFinite(account.expiresAt) &&
    account.expiresAt - now > skewMs &&
    !options.forceRefresh
  ) {
    return account;
  }
  const refreshed = await refreshAccessToken(account.refreshToken, {
    ...options,
    clientType: account.clientType,
    preferredClientKey: account.oauthClientKey,
    proxy: options.proxy || account.proxy
  });
  let projectId = account.projectId;
  let tier = account.tier;
  let rawTier = account.rawTier;
  let availableCredits = account.availableCredits;
  if (!projectId) {
    const isPersonalEmail = /@(gmail|googlemail)\.com$/i.test(account.email || '');
    const ideType = account.clientType === 'enterprise' || (account.email && !isPersonalEmail)
      ? 'JETSKI'
      : 'ANTIGRAVITY';
    const info = await loadCodeAssist(refreshed.accessToken, {
      ...options,
      proxy: options.proxy || account.proxy,
      ideType
    }).catch(() => null);
    if (info) {
      let resolvedId = info.projectId;
      if (!resolvedId && options.autoOnboard !== false && info.onboardTierId) {
        resolvedId = await onboardCodeAssistUser(refreshed.accessToken, {
          ...options,
          proxy: options.proxy || account.proxy,
          tierId: info.onboardTierId,
          ideType
        }).catch(() => null);
      }
      projectId = resolvedId || DEFAULT_FALLBACK_PROJECT_ID;
      tier = info.tier;
      rawTier = info.rawTier;
      if (Array.isArray(info.availableCredits) && info.availableCredits.length > 0) {
        availableCredits = info.availableCredits;
      }
    }
  }
  const updated = {
    ...account,
    refreshToken: refreshed.refreshToken,
    accessToken: refreshed.accessToken,
    expiresAt: refreshed.expiresAt,
    oauthClientKey: refreshed.oauthClientKey,
    clientType: refreshed.clientType,
    projectId: projectId || DEFAULT_FALLBACK_PROJECT_ID,
    ...(tier ? { tier } : {}),
    ...(rawTier ? { rawTier } : {}),
    ...(Array.isArray(availableCredits) && availableCredits.length > 0 ? { availableCredits } : {}),
    updatedAt: now
  };
  if (options.persist !== false) {
    try {
      saveAntigravityAccount(updated, options.dataDir);
    } catch {}
  }
  return updated;
}
