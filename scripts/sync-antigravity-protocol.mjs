#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import { validateProxyURL } from '../lib/setup.mjs';
import { fetchWithProxy } from '../lib/antigravity-oauth.mjs';
import {
  compareHubVersions,
  parseOfficialDownloadPage
} from '../lib/antigravity-ua.mjs';

const isValidVersion = v => typeof v === 'string' && /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v.trim());
const isValidCl = c => typeof c === 'string' && /^\d{5,15}$/.test(c.trim());

const DEFAULT_PROTOCOL_PATH = path.resolve('lib/antigravity-protocol.json');
const DEFAULT_UA_PATH = path.resolve('lib/antigravity-ua.json');
const DEFAULT_DOWNLOAD_URL = 'https://antigravity.google/download';

const V1_INTERNAL_ENDPOINT_RE = /\/v1internal:[a-z][A-Za-z0-9]{2,64}/g;
const ENDPOINT_BLEED_RE = /(?:url|chunk|crypto|failed|The|[A-Z])$/;
const GOOGLE_AUTH_SCOPE_RE =
  /https:\/\/www\.googleapis\.com\/auth\/(?:userinfo\.(?:email|profile)|experimentsandconfigs|cloud-platform|cclog|aicode|drive(?:\.(?:file|appdata|scripts|metadata\.readonly|metadata|apps\.readonly|meet\.readonly|photos\.readonly|readonly))?)/g;

function normalizePosixPlatform(uaString) {
  return String(uaString || '')
    .replace(/os_type=[a-z0-9_]+/i, 'os_type=<os>')
    .replace(/arch=[a-z0-9_]+/i, 'arch=<arch>');
}

function classifyRequestIdFormat(id) {
  const s = String(id || '');
  if (s.startsWith('checkpoint/')) return 'checkpoint/<uuid>';
  if (s.startsWith('agent/')) return 'agent/<cascade_uuid>/<ts_ms>/<trajectory_uuid>/<step>';
  return s ? s.split('/')[0] : 'unknown';
}

function parseTarOctalOrBase256(buf, start, end) {
  if ((buf[start] & 0x80) !== 0) {
    let val = 0;
    for (let i = start + 1; i < end; i++) val = val * 256 + buf[i];
    return val;
  }
  const str = buf.subarray(start, end).toString('utf8').replace(/\0.*$/, '').trim();
  if (!str) return 0;
  const parsed = Number.parseInt(str, 8);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function isZeroTarBlock(buf) {
  for (let i = 0; i < 512; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function isLanguageServerTarCandidate(tarPath, size) {
  if (!Number.isFinite(size) || size < 1024 * 1024) return false;
  const base = path.posix.basename(String(tarPath || '')).toLowerCase();
  return /^language_server(?:_[a-z0-9_]+)?(?:\.exe)?$/.test(base);
}

/**
 * Extract public static protocol constants (endpoints, OAuth scopes, UA tokens)
 * from a language_server binary without requiring credentials or network access.
 */
export function extractStaticProtocolSignals(buf) {
  const text = Buffer.isBuffer(buf) ? buf.toString('latin1') : String(buf || '');
  const rawEndpoints = new Set();
  for (const m of text.matchAll(V1_INTERNAL_ENDPOINT_RE)) {
    const cleaned = m[0].replace(ENDPOINT_BLEED_RE, '');
    if (cleaned.length > '/v1internal:'.length + 2) {
      rawEndpoints.add(cleaned);
    }
  }
  const endpoints = [...rawEndpoints].filter(ep => {
    for (const candidate of rawEndpoints) {
      if (candidate !== ep && ep.startsWith(candidate)) return false;
    }
    return true;
  }).sort();

  const oauthScopes = new Set();
  for (const m of text.matchAll(GOOGLE_AUTH_SCOPE_RE)) {
    oauthScopes.add(m[0]);
  }
  const userAgentFragments = [];
  for (const marker of ['aidev_client', 'os_type=%s', 'arch=%s', 'cl=%s', 'datacollection_opt_in=false']) {
    if (text.includes(marker)) userAgentFragments.push(marker);
  }
  const hasAcceptEncodingGzip = text.includes('Accept-Encoding');
  const hasStreamQueryAltSse = text.includes('streamGenerateContent?alt=sse');
  return {
    endpoints: [...endpoints].sort(),
    oauthScopes: [...oauthScopes].sort(),
    userAgentFragments,
    hasAcceptEncodingGzip,
    hasStreamQueryAltSse
  };
}

/**
 * Summarize captured local wire exchanges into a deterministic, timestamp-free
 * protocol snapshot suitable for CI drift detection and git diffing.
 */
export function summarizeCapturedExchanges(exchanges, staticSignals = {}, meta = {}) {
  const endpoints = [];
  const seenEndpoints = new Set();
  const streamMeta = {
    envelopeKeys: [],
    requestTypes: new Set(),
    requestIdFormats: new Set(),
    agentRequestKeys: [],
    labelKeys: new Set(),
    generationConfigKeys: new Set(),
    thinkingConfigKeys: new Set(),
    toolsPacking: null,
    userAgentField: null,
    sessionIdFormat: null
  };
  let loadCodeAssistMetadata = null;
  let listExperimentsMetadata = null;
  let egressRawHeaderOrder = [];
  let egressAcceptEncoding = null;
  let egressContentType = null;
  let egressUserAgentTemplate = null;

  for (const ex of exchanges || []) {
    const endpointKey = `${ex.method} ${ex.url}`;
    if (!seenEndpoints.has(endpointKey)) {
      seenEndpoints.add(endpointKey);
      endpoints.push(endpointKey);
    }

    let parsed = null;
    if (typeof ex.body === 'string' && ex.body.trim().startsWith('{')) {
      try {
        parsed = JSON.parse(ex.body);
      } catch {}
    }

    if (ex.url.includes(':loadCodeAssist') && parsed?.metadata) {
      loadCodeAssistMetadata = parsed.metadata;
    }
    if (ex.url.includes(':listExperiments') && parsed?.metadata) {
      listExperimentsMetadata = parsed.metadata;
    }

    if (ex.url.includes(':streamGenerateContent')) {
      if (egressRawHeaderOrder.length === 0 && Array.isArray(ex.rawHeaderNames)) {
        egressRawHeaderOrder = [...ex.rawHeaderNames];
      }
      if (!egressAcceptEncoding && ex.headers?.['accept-encoding']) {
        egressAcceptEncoding = String(ex.headers['accept-encoding']);
      }
      if (!egressContentType && ex.headers?.['content-type']) {
        egressContentType = String(ex.headers['content-type']);
      }
      if (!egressUserAgentTemplate && ex.headers?.['user-agent']) {
        egressUserAgentTemplate = normalizePosixPlatform(ex.headers['user-agent']);
      }

      if (parsed && typeof parsed === 'object') {
        if (streamMeta.envelopeKeys.length === 0) {
          streamMeta.envelopeKeys = Object.keys(parsed);
        }
        if (parsed.requestType) streamMeta.requestTypes.add(parsed.requestType);
        if (parsed.requestId) streamMeta.requestIdFormats.add(classifyRequestIdFormat(parsed.requestId));
        if (!streamMeta.userAgentField && typeof parsed.userAgent === 'string') {
          streamMeta.userAgentField = parsed.userAgent;
        }

        const reqObj = parsed.request;
        if (reqObj && typeof reqObj === 'object') {
          if (parsed.requestType === 'agent' && streamMeta.agentRequestKeys.length === 0) {
            streamMeta.agentRequestKeys = Object.keys(reqObj);
          }
          if (!streamMeta.sessionIdFormat && typeof reqObj.sessionId === 'string') {
            streamMeta.sessionIdFormat = /^-?\d+$/.test(reqObj.sessionId) ? 'signed_int64_string' : 'string';
          }
          if (reqObj.labels && typeof reqObj.labels === 'object') {
            for (const k of Object.keys(reqObj.labels)) streamMeta.labelKeys.add(k);
          }
          if (reqObj.generationConfig && typeof reqObj.generationConfig === 'object') {
            for (const k of Object.keys(reqObj.generationConfig)) streamMeta.generationConfigKeys.add(k);
            if (reqObj.generationConfig.thinkingConfig && typeof reqObj.generationConfig.thinkingConfig === 'object') {
              for (const k of Object.keys(reqObj.generationConfig.thinkingConfig)) {
                streamMeta.thinkingConfigKeys.add(k);
              }
            }
          }
          if (Array.isArray(reqObj.tools) && reqObj.tools.length > 0 && !streamMeta.toolsPacking) {
            if (reqObj.tools.length === 1 && Array.isArray(reqObj.tools[0]?.functionDeclarations)) {
              streamMeta.toolsPacking = 'single_function_declarations_wrapper';
            } else if (reqObj.tools.every(t => Array.isArray(t?.functionDeclarations) && t.functionDeclarations.length === 1)) {
              streamMeta.toolsPacking = 'per_declaration_wrapper';
            } else {
              streamMeta.toolsPacking = 'mixed';
            }
          }
        }
      }
    }
  }

  return {
    version: meta.version || '',
    cl: meta.cl || '',
    ...(meta.oauthUserAgent ? { oauthUserAgent: meta.oauthUserAgent } : {}),
    apiVersion: 'v1internal',
    observedEndpoints: [...endpoints].sort(),
    headers: {
      rawHeaderOrder: egressRawHeaderOrder,
      userAgentTemplate: egressUserAgentTemplate || '',
      contentType: egressContentType || 'application/json',
      acceptEncoding: egressAcceptEncoding || ''
    },
    clientMetadata: {
      ...(loadCodeAssistMetadata ? { loadCodeAssist: loadCodeAssistMetadata } : {}),
      ...(listExperimentsMetadata ? { listExperiments: listExperimentsMetadata } : {})
    },
    streamGenerateContent: {
      envelopeKeys: streamMeta.envelopeKeys,
      requestTypes: [...streamMeta.requestTypes].sort(),
      requestIdFormats: [...streamMeta.requestIdFormats].sort(),
      agentRequestKeys: streamMeta.agentRequestKeys,
      toolsPacking: streamMeta.toolsPacking || 'none',
      labelKeys: [...streamMeta.labelKeys].sort(),
      generationConfigKeys: [...streamMeta.generationConfigKeys].sort(),
      thinkingConfigKeys: [...streamMeta.thinkingConfigKeys].sort(),
      userAgentField: streamMeta.userAgentField || 'antigravity',
      sessionIdFormat: streamMeta.sessionIdFormat || 'signed_int64_string'
    },
    binarySignals: {
      endpoints: staticSignals.endpoints || [],
      oauthScopes: staticSignals.oauthScopes || [],
      userAgentFragments: staticSignals.userAgentFragments || [],
      hasAcceptEncodingGzip: Boolean(staticSignals.hasAcceptEncodingGzip),
      hasStreamQueryAltSse: Boolean(staticSignals.hasStreamQueryAltSse)
    },
    source: meta.source || 'official-sync'
  };
}

/**
 * Compare two protocol manifests ignoring only updatedAt timestamp so CI
 * commits only on meaningful protocol or UA drift.
 */
export function isSameProtocolSnapshot(a, b) {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const stripMeta = obj => {
    const clone = structuredClone(obj);
    delete clone.updatedAt;
    return clone;
  };
  return JSON.stringify(stripMeta(a)) === JSON.stringify(stripMeta(b));
}

async function allocateLoopbackPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(err => (err ? reject(err) : resolve(port)));
    });
  });
}

function createLanguageServerTarExtractor(outFilePath) {
  let state = 'header';
  let buffer = Buffer.alloc(0);
  let gnuLongName = null;
  let paxOverrides = null;
  let remainingPayload = 0;
  let remainingPad = 0;
  let currentName = '';
  let currentType = '';
  let currentMode = 'skip';
  let metaChunks = [];
  let writeFd = null;
  let extractedPath = null;
  let finished = false;

  const parsePax = str => {
    const attrs = {};
    let idx = 0;
    while (idx < str.length) {
      const sp = str.indexOf(' ', idx);
      if (sp === -1) break;
      const len = Number.parseInt(str.slice(idx, sp), 10);
      if (!Number.isFinite(len) || len <= 0) break;
      const record = str.slice(sp + 1, idx + len).replace(/\n$/, '');
      const eq = record.indexOf('=');
      if (eq !== -1) attrs[record.slice(0, eq)] = record.slice(eq + 1);
      idx += len;
    }
    return attrs;
  };

  const finishEntry = () => {
    if (currentMode === 'collect-meta') {
      const raw = Buffer.concat(metaChunks).toString('utf8');
      if (currentType === 'L') gnuLongName = raw.replace(/\0+$/, '');
      else if (currentType === 'x') paxOverrides = parsePax(raw);
    } else if (currentMode === 'extract') {
      if (writeFd !== null) {
        fs.closeSync(writeFd);
        writeFd = null;
      }
      extractedPath = outFilePath;
      finished = true;
    }
    metaChunks = [];
  };

  const push = chunk => {
    if (finished || !chunk || chunk.length === 0) return false;
    buffer = buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([buffer, chunk]);
    while (!finished) {
      if (state === 'header') {
        if (buffer.length < 512) break;
        const header = buffer.subarray(0, 512);
        buffer = buffer.subarray(512);
        if (isZeroTarBlock(header)) {
          finished = true;
          break;
        }
        const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
        const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
        let fullName = prefix ? `${prefix}/${rawName}` : rawName;
        const typeByte = header[156];
        const typeflag = typeByte === 0 ? '0' : String.fromCharCode(typeByte);
        let size = parseTarOctalOrBase256(header, 124, 136);
        if (gnuLongName !== null) {
          fullName = gnuLongName;
          gnuLongName = null;
        }
        if (paxOverrides) {
          if (typeof paxOverrides.path === 'string' && paxOverrides.path) fullName = paxOverrides.path;
          if (paxOverrides.size !== undefined) {
            const paxSize = Number(paxOverrides.size);
            if (Number.isFinite(paxSize) && paxSize >= 0) size = paxSize;
          }
          paxOverrides = null;
        }

        currentName = fullName;
        currentType = typeflag;
        remainingPayload = size;
        remainingPad = (512 - (size % 512)) % 512;
        metaChunks = [];

        if (typeflag === 'L' || typeflag === 'x') {
          currentMode = 'collect-meta';
        } else if ((typeflag === '0' || typeflag === '\0') && !extractedPath && isLanguageServerTarCandidate(fullName, size)) {
          currentMode = 'extract';
          writeFd = fs.openSync(outFilePath, 'w', 0o755);
        } else {
          currentMode = 'skip';
        }

        if (remainingPayload > 0) state = 'payload';
        else {
          finishEntry();
          state = remainingPad > 0 ? 'pad' : 'header';
        }
        continue;
      }

      if (state === 'payload') {
        if (buffer.length === 0) break;
        const take = Math.min(buffer.length, remainingPayload);
        const slice = buffer.subarray(0, take);
        buffer = buffer.subarray(take);
        remainingPayload -= take;
        if (currentMode === 'collect-meta') metaChunks.push(Buffer.from(slice));
        else if (currentMode === 'extract' && writeFd !== null) fs.writeSync(writeFd, slice);
        if (remainingPayload === 0) {
          finishEntry();
          state = remainingPad > 0 ? 'pad' : 'header';
        }
        continue;
      }

      if (state === 'pad') {
        if (buffer.length === 0) break;
        const skip = Math.min(buffer.length, remainingPad);
        buffer = buffer.subarray(skip);
        remainingPad -= skip;
        if (remainingPad === 0) state = 'header';
      }
    }
    return Boolean(extractedPath);
  };

  const cleanup = () => {
    if (writeFd !== null) {
      try { fs.closeSync(writeFd); } catch {}
      writeFd = null;
    }
  };

  return { push, cleanup, get extractedPath() { return extractedPath; }, get entryName() { return currentName; } };
}

async function extractLanguageServerFromArchive({ archiveUrl, doFetch, outFilePath, timeoutMs = 120000 }) {
  const controller = new AbortController();
  const timeoutSignal = timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined;
  const signal = timeoutSignal ? AbortSignal.any([timeoutSignal, controller.signal]) : controller.signal;
  const res = await doFetch(archiveUrl, { method: 'GET' }, signal);
  if (!res.ok || !res.body) {
    throw new Error(`Failed to fetch official archive (${archiveUrl}): HTTP ${res.status}`);
  }

  const extractor = createLanguageServerTarExtractor(outFilePath);
  const gunzip = zlib.createGunzip();
  let reader = null;
  let earlyStopped = false;

  const stopEarly = () => {
    if (earlyStopped) return;
    earlyStopped = true;
    try { controller.abort(new Error('Early stop: language_server extracted')); } catch {}
    try { gunzip.destroy(); } catch {}
    try { reader?.cancel?.().catch(() => {}); } catch {}
  };

  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = fn => arg => {
      if (settled) return;
      settled = true;
      extractor.cleanup();
      fn(arg);
    };
    const ok = finish(resolve);
    const errFn = finish(reject);

    gunzip.on('data', chunk => {
      if (earlyStopped) return;
      try {
        if (extractor.push(chunk)) stopEarly();
      } catch (err) {
        errFn(err);
      }
    });
    gunzip.on('end', () => ok());
    gunzip.on('close', () => {
      if (earlyStopped) ok();
    });
    gunzip.on('error', err => {
      if (earlyStopped) ok();
      else errFn(err);
    });

    (async () => {
      try {
        reader = res.body.getReader();
        while (!earlyStopped) {
          const { done, value } = await reader.read();
          if (done || earlyStopped) break;
          if (value && value.byteLength > 0 && !gunzip.write(value) && !earlyStopped) {
            await new Promise(r => {
              const doneDrain = () => {
                gunzip.off('close', doneDrain);
                r();
              };
              gunzip.once('drain', doneDrain);
              gunzip.once('close', doneDrain);
            });
          }
        }
        if (!earlyStopped) gunzip.end();
      } catch (err) {
        if (earlyStopped) ok();
        else {
          try { gunzip.destroy(err); } catch {}
          errFn(err);
        }
      }
    })();
  });

  if (!extractor.extractedPath || !fs.existsSync(outFilePath)) {
    throw new Error(`No language_server binary found inside ${archiveUrl}`);
  }
  try {
    fs.chmodSync(outFilePath, 0o755);
  } catch {}
  return outFilePath;
}

/**
 * Run a zero-credential headless probe against an official language_server binary
 * redirected to a local loopback mock HTTP server to observe outbound headers and JSON schemas.
 */
export async function probeLanguageServerBinary({
  binaryPath,
  version,
  cl,
  oauthUserAgent,
  timeoutMs = 20000
}) {
  if (!binaryPath || !fs.existsSync(binaryPath)) {
    throw new Error(`language_server binary not found: ${binaryPath}`);
  }
  const binaryBuf = fs.readFileSync(binaryPath);
  const staticSignals = extractStaticProtocolSignals(binaryBuf);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-proto-probe-'));
  const geminiDir = path.join(tmpDir, 'gemini');
  fs.mkdirSync(geminiDir, { recursive: true });

  const exchanges = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      exchanges.push({
        method: req.method,
        url: req.url,
        rawHeaderNames: req.rawHeaders.filter((_, idx) => idx % 2 === 0),
        headers: req.headers,
        body
      });

      if (req.url.includes('/userinfo')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ email: 'probe@example.com', name: 'Protocol Probe' }));
        return;
      }
      if (req.url.includes(':loadCodeAssist')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          cloudaicompanionProject: 'ci-probe-project',
          currentTier: { id: 'free-tier', name: 'Antigravity' },
          paidTier: { id: 'g1-pro-tier', name: 'Google AI Pro' },
          allowedTiers: [{ id: 'free-tier', isDefault: true }]
        }));
        return;
      }
      if (req.url.includes(':fetchAvailableModels')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          models: {
            'gemini-4-hydrogen-high': {
              displayName: 'Gemini 4 Hydrogen (High)',
              model: 'MODEL_PLACEHOLDER_M525',
              modelProvider: 'MODEL_PROVIDER_GOOGLE',
              maxTokens: 1048576,
              maxOutputTokens: 65536,
              supportsThinking: true,
              thinkingLevel: 3,
              recommended: true
            },
            'claude-opus-5-5-high': {
              displayName: 'Claude Opus 5.5 (High)',
              model: 'MODEL_PLACEHOLDER_M402',
              modelProvider: 'MODEL_PROVIDER_ANTHROPIC',
              maxTokens: 1000000,
              maxOutputTokens: 65536,
              supportsThinking: true,
              thinkingLevel: 3,
              recommended: true
            }
          },
          defaultAgentModelId: 'gemini-4-hydrogen-high',
          agentModelSorts: [{
            displayName: 'Recommended',
            groups: [{ modelIds: ['gemini-4-hydrogen-high', 'claude-opus-5-5-high'] }]
          }]
        }));
        return;
      }
      if (req.url.includes(':streamGenerateContent')) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write(`data: ${JSON.stringify({
          response: {
            candidates: [{ content: { role: 'model', parts: [{ text: 'ok' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 1, totalTokenCount: 11 }
          }
        })}\n\n`);
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });

  let lsProc = null;
  try {
    const httpPort = await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        resolve(typeof addr === 'object' && addr ? addr.port : 0);
      });
    });
    const rpcPort = await allocateLoopbackPort();
    const csrf = crypto.randomUUID();
    const env = { ...process.env };
    for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
      env[key] = '';
    }
    env.JETSKI_OAUTH_TOKEN = 'ya29.ci_protocol_probe_dummy';
    env.USER_INFO_OVERRIDE_URL = `http://127.0.0.1:${httpPort}/userinfo`;

    const args = [
      '--standalone',
      '--override_ide_name', 'antigravity',
      '--subclient_type', 'cli',
      ...(isValidVersion(version) ? ['--override_ide_version', version] : []),
      '--override_user_agent_name', 'antigravity',
      '--gemini_dir', geminiDir,
      '--app_data_dir', 'agy_proto_probe',
      '--cloud_code_endpoint', `http://127.0.0.1:${httpPort}`,
      '--http_server_port', String(rpcPort),
      '--csrf_token', csrf
    ];

    lsProc = spawn(binaryPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise(resolve => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        resolve();
      };
      const timer = setTimeout(finish, Math.min(8000, timeoutMs));
      const checkReady = chunk => {
        if (chunk.toString().includes(String(rpcPort))) {
          clearTimeout(timer);
          setTimeout(finish, 300);
        }
      };
      lsProc.stdout.on('data', checkReady);
      lsProc.stderr.on('data', checkReady);
      lsProc.once('exit', () => {
        clearTimeout(timer);
        finish();
      });
    });

    const rpc = async (method, payload = {}) => {
      const res = await fetch(`http://127.0.0.1:${rpcPort}/exa.language_server_pb.LanguageServerService/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-codeium-csrf-token': csrf },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000)
      });
      return res.json().catch(() => ({}));
    };

    await rpc('GetUserStatus');
    const cascade = await rpc('StartCascade', { source: 1 });
    if (cascade?.cascadeId) {
      await rpc('SendUserCascadeMessage', {
        cascadeId: cascade.cascadeId,
        items: [{ text: 'Reply ok.' }],
        cascadeConfig: { plannerConfig: { requestedModel: { model: 'MODEL_PLACEHOLDER_M525' } } }
      });
      await new Promise(r => setTimeout(r, 1500));
      await rpc('SendUserCascadeMessage', {
        cascadeId: cascade.cascadeId,
        items: [{ text: 'Follow up.' }],
        cascadeConfig: { plannerConfig: { requestedModel: { model: 'MODEL_PLACEHOLDER_M402' } } }
      });
      await new Promise(r => setTimeout(r, 1500));
    }

    return summarizeCapturedExchanges(exchanges, staticSignals, {
      version,
      cl,
      oauthUserAgent,
      source: 'official-sync'
    });
  } finally {
    if (lsProc && lsProc.exitCode === null && !lsProc.killed) {
      try { lsProc.kill('SIGKILL'); } catch {}
    }
    await new Promise(r => server.close(() => r()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function parseCliArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--binary') flags.binary = argv[++i];
    else if (a === '--out') flags.out = argv[++i];
    else if (a === '--ua-file') flags.uaFile = argv[++i];
    else if (a === '--download-url') flags.downloadUrl = argv[++i];
    else if (a === '--proxy') flags.proxy = argv[++i];
    else if (a === '--version') flags.version = argv[++i];
    else if (a === '--cl') flags.cl = argv[++i];
    else if (a === '--force') flags.force = true;
    else if (a === '--write') flags.write = true;
  }
  return flags;
}

async function main() {
  const flags = parseCliArgs(process.argv.slice(2));
  const outPath = path.resolve(flags.out || DEFAULT_PROTOCOL_PATH);
  const uaPath = path.resolve(flags.uaFile || DEFAULT_UA_PATH);
  const uaJson = fs.existsSync(uaPath) ? JSON.parse(fs.readFileSync(uaPath, 'utf8')) : {};
  let version = flags.version || uaJson.version || '';
  let cl = flags.cl || uaJson.cl || '';
  const oauthUserAgent = uaJson.oauthUserAgent || undefined;

  let binaryPath = flags.binary ? path.resolve(flags.binary) : '';
  let downloadTmpDir = '';
  try {
    if (!binaryPath) {
      const proxy = flags.proxy ? validateProxyURL(flags.proxy) : undefined;
      const doFetch = (url, init = {}, signal) => fetchWithProxy(url, init, { ...(proxy ? { proxy } : {}), signal });
      const dlUrl = flags.downloadUrl || DEFAULT_DOWNLOAD_URL;
      const pageRes = await doFetch(dlUrl, {
        method: 'GET',
        headers: { Accept: 'text/html,application/xhtml+xml,*/*' }
      }, AbortSignal.timeout(45000));
      if (!pageRes.ok) throw new Error(`Failed to fetch ${dlUrl}: HTTP ${pageRes.status}`);
      const html = await pageRes.text();
      const parsed = parseOfficialDownloadPage(html);
      if (!parsed?.preferredUrl) throw new Error(`Could not find linux-x64/Antigravity.tar.gz on ${dlUrl}`);
      if (!isValidVersion(version) && isValidVersion(parsed.version)) version = parsed.version;
      downloadTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-ls-extract-'));
      binaryPath = path.join(downloadTmpDir, 'language_server');
      await extractLanguageServerFromArchive({
        archiveUrl: parsed.preferredUrl,
        doFetch,
        outFilePath: binaryPath
      });
    }

    if (!isValidVersion(version) || !isValidCl(cl)) {
      throw new Error(`Missing valid version/cl (${version}/${cl}); pass --version/--cl or run antigravity-ua sync first.`);
    }

    const current = fs.existsSync(outPath) ? JSON.parse(fs.readFileSync(outPath, 'utf8')) : null;
    if (!flags.force && current?.version && compareHubVersions(version, current.version) < 0) {
      console.log(`Skip downgrade: probed ${version} < current ${current.version}`);
      if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'changed=false\n');
      return;
    }

    const snapshot = await probeLanguageServerBinary({ binaryPath, version, cl, oauthUserAgent });
    if (!flags.force && current && isSameProtocolSnapshot(snapshot, current)) {
      console.log(`No protocol drift at ${snapshot.version} (cl=${snapshot.cl})`);
      if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'changed=false\n');
      return;
    }

    const output = { ...snapshot, updatedAt: Date.now() };
    if (flags.write) {
      fs.writeFileSync(outPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
    } else {
      console.log(JSON.stringify(output, null, 2));
    }
    if (process.env.GITHUB_OUTPUT) {
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `changed=true\nversion=${output.version}\ncl=${output.cl}\n`);
    }
    console.log(`Synced protocol manifest -> ${outPath} (${output.version}, cl=${output.cl})`);
  } finally {
    if (downloadTmpDir) {
      fs.rmSync(downloadTmpDir, { recursive: true, force: true });
    }
  }
}

const isEntrypoint = process.argv[1] &&
  path.resolve(process.argv[1]).toLowerCase() === path.resolve(fileURLToPath(import.meta.url)).toLowerCase();
if (isEntrypoint) {
  main().catch(err => {
    console.error(err?.stack || err?.message || String(err));
    process.exitCode = 1;
  });
}
