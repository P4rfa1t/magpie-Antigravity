import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import tls from 'node:tls';
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

export const DEFAULT_FALLBACK_PROJECT_ID = 'bamboo-precept-lgxtn';
export const TOKEN_REFRESH_SKEW_MS = 15 * 60 * 1000;

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

function normalizeProxyBody(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) return body;
  if (body instanceof URLSearchParams) return body.toString();
  return String(body);
}

// Bun's fetch supports `{ proxy }` directly; Node's global fetch ignores it, so
// when running under Node with an HTTP/HTTPS proxy URL we tunnel via node:http CONNECT,
// negotiating ALPN h2 (HTTP/2) over TLS with transparent HTTP/1.1 fallback.
function nodeProxyFetch(url, init = {}, proxyUrl, tlsOptions = {}) {
  const target = new URL(url);
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
    throw new Error(`Node 运行时仅内置支持 http/https 代理，暂不支持 ${proxy.protocol}（在 Magpie / Bun 运行时中支持 socks5）`);
  }
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    throw new Error(`Unsupported target protocol: ${target.protocol}`);
  }

  const targetPort = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  const proxyPort = Number(proxy.port || (proxy.protocol === 'https:' ? 443 : 80));
  const authHeader = proxy.username || proxy.password
    ? 'Basic ' + Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString('base64')
    : null;

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
    const onAbort = () => {
      const err = signal.reason || new DOMException('The operation was aborted.', 'AbortError');
      try { activeReq?.close?.(); } catch {}
      try { activeReq?.destroy?.(err); } catch {}
      try { activeH2Session?.destroy?.(err); } catch {}
      try { activeSocket?.destroy?.(err); } catch {}
      if (!settled) {
        settled = true;
        reject(err);
      }
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    const cleanupAbort = () => signal?.removeEventListener('abort', onAbort);

    const fail = err => {
      cleanupAbort();
      try { activeH2Session?.destroy?.(); } catch {}
      try { activeSocket?.destroy?.(); } catch {}
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
        const bodyStream = new ReadableStream({
          start(controller) {
            res.on('data', chunk => controller.enqueue(chunk));
            res.on('end', () => {
              cleanupAbort();
              controller.close();
            });
            res.on('error', err => {
              cleanupAbort();
              controller.error(err);
            });
          },
          cancel() {
            cleanupAbort();
            res.destroy();
          }
        });
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
        resolve(new Response(noBody ? null : bodyStream, {
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

    const sendHttp2OverTls = tlsSocket => {
      const h2Session = http2.connect(target.origin, {
        createConnection: () => tlsSocket
      });
      activeH2Session = h2Session;
      const closeSession = () => {
        try { h2Session.close(); } catch {}
      };
      h2Session.on('error', fail);

      const method = (init.method || 'GET').toUpperCase();
      const h2Headers = {
        ':method': method,
        ':path': `${target.pathname}${target.search}`,
        ':scheme': 'https',
        ':authority': target.host
      };
      if (init.headers) {
        new Headers(init.headers).forEach((v, k) => {
          const lk = k.toLowerCase();
          if (!HOP_BY_HOP_H2_HEADERS.has(lk) && !lk.startsWith(':')) {
            h2Headers[lk] = v;
          }
        });
      }

      const h2Req = h2Session.request(h2Headers);
      activeReq = h2Req;
      h2Req.on('error', fail);
      h2Req.on('response', headers => {
        if (settled) {
          h2Req.close();
          closeSession();
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
        const bodyStream = noBody ? null : new ReadableStream({
          start(controller) {
            h2Req.on('data', chunk => controller.enqueue(chunk));
            h2Req.on('end', () => {
              cleanupAbort();
              closeSession();
              controller.close();
            });
            h2Req.on('error', err => {
              cleanupAbort();
              closeSession();
              controller.error(err);
            });
          },
          cancel() {
            cleanupAbort();
            try { h2Req.close(); } catch {}
            closeSession();
          }
        });
        if (noBody) {
          h2Req.resume();
          h2Req.on('end', () => {
            cleanupAbort();
            closeSession();
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

    const sendOverSocket = socket => {
      if (target.protocol !== 'https:') {
        sendHttp1OverConnection(socket);
        return;
      }
      const tlsSocket = tls.connect({
        ...tlsOptions,
        socket,
        servername: target.hostname,
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

  if (rawProxy && !options.fetchFn && !globalThis.Bun) {
    return nodeProxyFetch(url, reqInit, rawProxy, options.tlsOptions);
  }
  if (rawProxy) {
    reqInit.proxy = rawProxy;
  }
  return fetchFn(url, reqInit);
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
      Accept: 'application/json'
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

export async function loadCodeAssist(accessToken, options = {}) {
  const ideType = options.ideType || 'ANTIGRAVITY';
  const payload = JSON.stringify({ metadata: { ideType } });
  let lastErr;

  for (const url of LOAD_CODE_ASSIST_ENDPOINTS) {
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
    return {
      projectId,
      rawTier,
      tier: normalizeSubscriptionTier(rawTier),
      usesGcpTos: allowedUsesGcpTos,
      onboardTierId
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
  for (const url of ONBOARD_USER_ENDPOINTS) {
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

  for (const url of FETCH_MODELS_ENDPOINTS) {
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
  for (const url of QUOTA_SUMMARY_ENDPOINTS) {
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

export async function verifyRefreshToken(refreshToken, options = {}) {
  const tokenData = await refreshAccessToken(refreshToken, options);
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
    ...(options.proxy ? { proxy: validateProxyURL(options.proxy) } : {}),
    updatedAt: Date.now()
  };
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
  if (
    account.accessToken &&
    Number.isFinite(account.expiresAt) &&
    account.expiresAt - now > TOKEN_REFRESH_SKEW_MS &&
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
    updatedAt: now
  };
  if (options.persist !== false) {
    try {
      saveAntigravityAccount(updated, options.dataDir);
    } catch {}
  }
  return updated;
}
