import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { makeOpenAIError, PLUGIN_ICON } from './backend.mjs';
import { validateProxyURL } from './setup.mjs';
import { isContainerEnv, dockerProxyHint } from './proc.mjs';
import {
  refreshRemoteHubVersion,
  resolveAntigravityUserAgents,
  resolveUaManifestUrl
} from './antigravity-ua.mjs';
import {
  V1_INTERNAL_BASES,
  DEFAULT_FALLBACK_PROJECT_ID,
  antigravityDataDir,
  currentEgressUserAgent,
  ensureFreshAccountToken,
  fetchAvailableModels,
  fetchQuotaSummary,
  fetchWithProxy,
  hasConfiguredOAuthClient,
  loadAntigravityAccounts,
  normalizeClientType,
  parseRefreshTokenPackage,
  saveAntigravityAccount,
  saveOAuthClientCredentials,
  shouldFallbackEndpoint,
  verifyRefreshToken
} from './antigravity-oauth.mjs';
import {
  antigravitySSEToOpenAIStream,
  antigravityToOpenAIResponse,
  deriveConversationAnchor,
  deriveUpstreamSessionId,
  isGeminiResponseEmpty,
  isOpenAIChatResponseEmpty,
  openAIToAntigravityRequest,
  resolveAntigravityModel,
  unwrapGeminiNativeSSE,
  wrapGeminiNativeRequest
} from './antigravity-mapper.mjs';

export const ANTIGRAVITY_ID = 'antigravity-rt';
export const ANTIGRAVITY_BASE = 'https://antigravity.local/v1';

const SKIP_USER_PROJECT = new Set(['aicode-consumers', 'test-project', 'project-id']);
const TIER_SUFFIX_RE = /^(.*)-(minimal|low|medium|high|xhigh|max)$/i;
const GEMINI_CALL_RE = /^\/models\/([^/:]+):(generateContent|streamGenerateContent)$/;
const IGNORED_MODEL_RE = /^(?:tab_|chat_)|(?:[-_]disabled)$|^gemini-flash-worker-agy$|^gemini-2\.5-|-sonar$|-tiered$/i;

function isOrchestratorModel(id, displayName) {
  return /^gemini-[a-z0-9.]*-?orchestrator/i.test(String(id || '')) ||
    /^Orchestrator\b/i.test(String(displayName || ''));
}

export const VERIFY_ADVICE = 'this Google account needs to be verified';

export function verifyLinkIn(output) {
  const said = String(output ?? '').replace(/\\u0026/g, '&').replace(/&amp;/g, '&');
  const named = key => new RegExp(`"?${key}"?\\s*[:=]\\s*"?(https://[^\\s"'\\\\<>]+)`, 'i').exec(said)?.[1];
  const link = named('validation_?link') || named('validation_?url') ||
    /in your browser to continue:\s*(https:\/\/[^\s"'\\<>]+)/i.exec(said)?.[1] ||
    /(https:\/\/accounts\.google\.com\/[^\s"'\\<>]+)/i.exec(said)?.[1] || '';
  const trimmed = link.replace(/[).,;\]}]+$/, '');
  try {
    const u = new URL(trimmed);
    return u.protocol === 'https:' && u.host ? trimmed : '';
  } catch {
    return '';
  }
}

function formatVerifyRefusal(errText) {
  if (!/verify your account|validation_required|verification required/i.test(String(errText || ''))) return '';
  const link = verifyLinkIn(errText);
  const said = 'Google wants this account verified before Antigravity serves it again';
  return link
    ? `${said} — ${VERIFY_ADVICE}: open ${link} in a browser signed in to it, verify it, then try again`
    : `${said} — ${VERIFY_ADVICE}: open the Antigravity app signed in to it and complete verification, then try again`;
}

const KNOWN_ANTIGRAVITY_NESTED = new Set([
  'proxy',
  'dataDir',
  'clientId',
  'clientSecret',
  'gcpClientId',
  'gcpClientSecret',
  'allowTools',
  'allowImages',
  'imageModels',
  'contextLimit',
  'outputLimit',
  'requestTimeoutMs',
  'modelTimeoutMs',
  'compactPrompt',
  'toolTokenBudget',
  'failoverOnError',
  'uaManifestUrl',
  'detectLocal',
  'emptyReplyMaxWaitMs',
  'emptyReplyRetryDelayMs',
  'streamIdleTimeoutMs'
]);

const DEFAULT_EMPTY_REPLY_RETRY_DELAY_MS = 1500;
const MAX_EMPTY_REPLY_RETRIES = 3;

const MAX_SIGNATURE_CACHE = 10000;
const SIGNATURE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const signatureStores = new Map();

export function loadSignatureStore(dataDir) {
  const dirKey = dataDir ? path.resolve(dataDir) : '__memory__';
  if (signatureStores.has(dirKey)) return signatureStores.get(dirKey);

  const map = new Map();
  const filePath = dataDir ? path.join(dirKey, 'signature-cache.json') : null;
  if (filePath && fs.existsSync(filePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const cutoff = Date.now() - SIGNATURE_TTL_MS;
      for (const item of Array.isArray(parsed?.entries) ? parsed.entries : []) {
        if (!Array.isArray(item) || typeof item[0] !== 'string' || typeof item[1] !== 'string') continue;
        const ts = Number.isFinite(item[2]) ? item[2] : Date.now();
        if (ts < cutoff) continue;
        map.delete(item[0]);
        map.set(item[0], { sig: item[1], ts });
        if (map.size > MAX_SIGNATURE_CACHE) {
          const oldest = map.keys().next().value;
          if (oldest !== undefined) map.delete(oldest);
        }
      }
    } catch {}
  }

  let flushTimer = null;
  const flush = () => {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    if (!filePath) return;
    try {
      fs.mkdirSync(dirKey, { recursive: true, mode: 0o700 });
      const entries = [...map.entries()].map(([k, v]) => [k, v.sig, v.ts]);
      const tmp = `${filePath}.tmp.${process.pid}.${Date.now()}`;
      fs.writeFileSync(tmp, JSON.stringify({ version: 1, entries }) + '\n', { mode: 0o600 });
      fs.renameSync(tmp, filePath);
    } catch {}
  };

  const scheduleFlush = () => {
    if (!filePath || flushTimer) return;
    flushTimer = setTimeout(flush, 100);
    if (typeof flushTimer.unref === 'function') flushTimer.unref();
  };

  const cache = {
    get(key) {
      if (!key || !map.has(key)) return undefined;
      const entry = map.get(key);
      if (Date.now() - entry.ts > SIGNATURE_TTL_MS) {
        map.delete(key);
        return undefined;
      }
      map.delete(key);
      map.set(key, entry);
      return entry.sig;
    },
    set(callId, sig) {
      if (!callId || !sig) return;
      if (map.has(callId)) {
        map.delete(callId);
      } else if (map.size >= MAX_SIGNATURE_CACHE) {
        const oldest = map.keys().next().value;
        if (oldest !== undefined) map.delete(oldest);
      }
      map.set(callId, { sig, ts: Date.now() });
      scheduleFlush();
    },
    flush
  };
  signatureStores.set(dirKey, cache);
  return cache;
}

const catalogCache = new Map();
const CATALOG_CACHE_MS = 5 * 60 * 1000;

function parseNonNegativeIntEnv(raw, fallback) {
  if (raw === undefined || String(raw).trim() === '') return fallback;
  const trimmed = String(raw).trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  return fallback;
}

export function antigravitySettings(options = {}, env = process.env) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('Plugin options must be an object');
  }

  let allowTools = options.allowTools !== undefined ? Boolean(options.allowTools) : true;
  let allowImages = options.allowImages !== undefined ? Boolean(options.allowImages) : true;
  let imageModels = true;
  let requestTimeoutMs = 570000;
  let modelTimeoutMs = 15000;
  let explicitContextLimit = null;
  let explicitOutputLimit = null;
  let proxy = env.ANTIGRAVITY_PROXY ? validateProxyURL(env.ANTIGRAVITY_PROXY) : '';
  let dataDir = antigravityDataDir(undefined, env);
  let clientId = '';
  let clientSecret = '';
  let gcpClientId = '';
  let gcpClientSecret = '';
  let compactPrompt = /^(?:1|true|on|yes)$/i.test(String(env.ANTIGRAVITY_COMPACT_PROMPT || '').trim());
  let failoverOnError = !/^(?:0|false|off|no)$/i.test(String(env.ANTIGRAVITY_FAILOVER ?? '1').trim());
  let uaManifestUrl = env.ANTIGRAVITY_UA_MANIFEST_URL !== undefined
    ? resolveUaManifestUrl({ env, strict: true })
    : undefined;
  let detectLocal = env.ANTIGRAVITY_DETECT_LOCAL !== undefined
    ? /^(?:1|true|on|yes)$/i.test(String(env.ANTIGRAVITY_DETECT_LOCAL).trim())
    : undefined;
  let emptyReplyMaxWaitMs = parseNonNegativeIntEnv(env.ANTIGRAVITY_EMPTY_REPLY_MAX_WAIT_MS, 0);
  let emptyReplyRetryDelayMs = parseNonNegativeIntEnv(
    env.ANTIGRAVITY_EMPTY_REPLY_RETRY_DELAY_MS,
    DEFAULT_EMPTY_REPLY_RETRY_DELAY_MS
  );
  let streamIdleTimeoutMs = parseNonNegativeIntEnv(env.ANTIGRAVITY_STREAM_IDLE_TIMEOUT_MS, 0);
  let toolTokenBudget;
  if (env.ANTIGRAVITY_TOOL_TOKEN_BUDGET !== undefined && String(env.ANTIGRAVITY_TOOL_TOKEN_BUDGET).trim() !== '') {
    const rawBudget = String(env.ANTIGRAVITY_TOOL_TOKEN_BUDGET).trim();
    if (/^(?:0|off|false|no)$/i.test(rawBudget)) toolTokenBudget = 0;
    else if (/^\d+$/.test(rawBudget)) toolTokenBudget = Number(rawBudget);
  }

  if (options.requestTimeoutMs !== undefined) {
    if (!Number.isInteger(options.requestTimeoutMs) || options.requestTimeoutMs <= 0) {
      throw new Error('Invalid option requestTimeoutMs: must be a positive integer');
    }
    requestTimeoutMs = options.requestTimeoutMs;
  }
  if (options.modelTimeoutMs !== undefined) {
    if (!Number.isInteger(options.modelTimeoutMs) || options.modelTimeoutMs <= 0) {
      throw new Error('Invalid option modelTimeoutMs: must be a positive integer');
    }
    modelTimeoutMs = options.modelTimeoutMs;
  }

  if (options.antigravity !== undefined) {
    const a = options.antigravity;
    if (!a || typeof a !== 'object' || Array.isArray(a)) {
      throw new Error('Invalid option antigravity: must be an object');
    }
    for (const key of Object.keys(a)) {
      if (!KNOWN_ANTIGRAVITY_NESTED.has(key)) {
        throw new Error(`Unknown antigravity option: ${key}`);
      }
    }
    if (a.proxy !== undefined) proxy = a.proxy ? validateProxyURL(a.proxy) : '';
    if (a.dataDir !== undefined) dataDir = antigravityDataDir(a.dataDir, env);
    if (typeof a.clientId === 'string') clientId = a.clientId.trim();
    if (typeof a.clientSecret === 'string') clientSecret = a.clientSecret.trim();
    if (typeof a.gcpClientId === 'string') gcpClientId = a.gcpClientId.trim();
    if (typeof a.gcpClientSecret === 'string') gcpClientSecret = a.gcpClientSecret.trim();
    if (a.allowTools !== undefined) {
      if (typeof a.allowTools !== 'boolean') throw new Error('Invalid option antigravity.allowTools: must be a boolean');
      allowTools = a.allowTools;
    }
    if (a.allowImages !== undefined) {
      if (typeof a.allowImages !== 'boolean') throw new Error('Invalid option antigravity.allowImages: must be a boolean');
      allowImages = a.allowImages;
    }
    if (a.imageModels !== undefined) {
      if (typeof a.imageModels !== 'boolean') throw new Error('Invalid option antigravity.imageModels: must be a boolean');
      imageModels = a.imageModels;
    }
    if (a.requestTimeoutMs !== undefined) {
      if (!Number.isInteger(a.requestTimeoutMs) || a.requestTimeoutMs <= 0) {
        throw new Error('Invalid option antigravity.requestTimeoutMs: must be a positive integer');
      }
      requestTimeoutMs = a.requestTimeoutMs;
    }
    if (a.modelTimeoutMs !== undefined) {
      if (!Number.isInteger(a.modelTimeoutMs) || a.modelTimeoutMs <= 0) {
        throw new Error('Invalid option antigravity.modelTimeoutMs: must be a positive integer');
      }
      modelTimeoutMs = a.modelTimeoutMs;
    }
    if (a.contextLimit !== undefined) {
      if (!Number.isInteger(a.contextLimit) || a.contextLimit <= 0) {
        throw new Error('Invalid option antigravity.contextLimit: must be a positive integer');
      }
      explicitContextLimit = a.contextLimit;
    }
    if (a.outputLimit !== undefined) {
      if (!Number.isInteger(a.outputLimit) || a.outputLimit <= 0) {
        throw new Error('Invalid option antigravity.outputLimit: must be a positive integer');
      }
      explicitOutputLimit = a.outputLimit;
    }
    if (explicitContextLimit !== null && explicitOutputLimit !== null && explicitOutputLimit > explicitContextLimit) {
      throw new Error('Invalid option antigravity.outputLimit: cannot exceed contextLimit');
    }
    if (a.compactPrompt !== undefined) {
      if (typeof a.compactPrompt !== 'boolean') {
        throw new Error('Invalid option antigravity.compactPrompt: must be a boolean');
      }
      compactPrompt = a.compactPrompt;
    }
    if (a.toolTokenBudget !== undefined) {
      if (!Number.isInteger(a.toolTokenBudget) || a.toolTokenBudget < 0) {
        throw new Error('Invalid option antigravity.toolTokenBudget: must be a non-negative integer');
      }
      toolTokenBudget = a.toolTokenBudget;
    }
    if (a.failoverOnError !== undefined) {
      if (typeof a.failoverOnError !== 'boolean') {
        throw new Error('Invalid option antigravity.failoverOnError: must be a boolean');
      }
      failoverOnError = a.failoverOnError;
    }
    if (a.uaManifestUrl !== undefined) {
      if (typeof a.uaManifestUrl !== 'string') {
        throw new Error('Invalid option antigravity.uaManifestUrl: must be a string');
      }
      uaManifestUrl = resolveUaManifestUrl({ manifestUrl: a.uaManifestUrl, strict: true });
    }
    if (a.detectLocal !== undefined) {
      if (typeof a.detectLocal !== 'boolean') {
        throw new Error('Invalid option antigravity.detectLocal: must be a boolean');
      }
      detectLocal = a.detectLocal;
    }
    if (a.emptyReplyMaxWaitMs !== undefined) {
      if (!Number.isInteger(a.emptyReplyMaxWaitMs) || a.emptyReplyMaxWaitMs < 0) {
        throw new Error('Invalid option antigravity.emptyReplyMaxWaitMs: must be a non-negative integer');
      }
      emptyReplyMaxWaitMs = a.emptyReplyMaxWaitMs;
    }
    if (a.emptyReplyRetryDelayMs !== undefined) {
      if (!Number.isInteger(a.emptyReplyRetryDelayMs) || a.emptyReplyRetryDelayMs < 0) {
        throw new Error('Invalid option antigravity.emptyReplyRetryDelayMs: must be a non-negative integer');
      }
      emptyReplyRetryDelayMs = a.emptyReplyRetryDelayMs;
    }
    if (a.streamIdleTimeoutMs !== undefined) {
      if (!Number.isInteger(a.streamIdleTimeoutMs) || a.streamIdleTimeoutMs < 0) {
        throw new Error('Invalid option antigravity.streamIdleTimeoutMs: must be a non-negative integer');
      }
      streamIdleTimeoutMs = a.streamIdleTimeoutMs;
    }
  }

  return {
    baseURL: ANTIGRAVITY_BASE,
    proxy,
    dataDir,
    ...(clientId ? { clientId } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    ...(gcpClientId ? { gcpClientId } : {}),
    ...(gcpClientSecret ? { gcpClientSecret } : {}),
    allowTools,
    allowImages,
    imageModels,
    requestTimeoutMs,
    modelTimeoutMs,
    explicitContextLimit,
    explicitOutputLimit,
    compactPrompt,
    failoverOnError,
    emptyReplyMaxWaitMs,
    emptyReplyRetryDelayMs,
    streamIdleTimeoutMs,
    ...(detectLocal !== undefined ? { detectLocal } : {}),
    ...(uaManifestUrl !== undefined ? { uaManifestUrl } : {}),
    ...(toolTokenBudget !== undefined ? { toolTokenBudget } : {}),
    fetchFn: options.fetchFn,
    rateLimitBackoffMs: options.rateLimitBackoffMs,
    rateLimitRetries: options.rateLimitRetries,
    maxRetryDelayMs: options.maxRetryDelayMs
  };
}

export function accountGroupLabel(accounts) {
  const ids = [...new Set(accounts.map(a => a.email || a.id))].sort();
  if (ids.length === 1) return ids[0];
  const hash = createHash('sha256').update(JSON.stringify(ids)).digest('hex').slice(0, 12);
  return `${ids[0]} +${ids.length - 1} [${hash}]`;
}

export function resolveAuthAccounts(auth, opts) {
  if (!auth || typeof auth !== 'object') return [];
  const meta = auth.metadata && typeof auth.metadata === 'object' ? auth.metadata : {};
  const disk = loadAntigravityAccounts(opts.dataDir);
  const byId = new Map(disk.map(a => [a.id, a]));

  if (Array.isArray(meta.accounts) && meta.accounts.length > 0) {
    const matched = meta.accounts.map(id => byId.get(String(id).toLowerCase())).filter(Boolean);
    if (matched.length > 0) return matched;
  }
  if (typeof meta.account === 'string' && meta.account) {
    const found = byId.get(meta.account.toLowerCase());
    if (found) return [found];
  }
  if (typeof auth.key === 'string' && auth.key.startsWith('1//')) {
    const byToken = disk.find(a => a.refreshToken === auth.key.trim());
    if (byToken) return [byToken];
    return [{
      id: (meta.account || meta.email || 'default').toLowerCase(),
      email: meta.email || 'antigravity',
      refreshToken: auth.key.trim(),
      clientType: normalizeClientType(meta.clientType),
      oauthClientKey: meta.oauthClientKey,
      projectId: meta.projectId || DEFAULT_FALLBACK_PROJECT_ID,
      proxy: meta.proxy || opts.proxy || undefined
    }];
  }
  return disk;
}

function cleanDisplayName(rawName, id) {
  if (typeof rawName !== 'string' || !rawName.trim()) return id;
  return rawName.replace(/\s*\((?:Low|Medium|High|XHigh|Minimal)\)\s*$/i, '').trim() || id;
}

function contextLimitForModel(id, info) {
  if (Number.isInteger(info?.maxTokens) && info.maxTokens > 0) return info.maxTokens;
  if (/^claude-(?:opus|sonnet)-5-5(?:-|$)/i.test(id)) return 1000000;
  if (/^claude-/i.test(id)) return 200000;
  if (/^gpt-oss-/i.test(id)) return 131072;
  return 1000000;
}

export function buildAntigravityModels(catalog, opts = {}) {
  const modelsMap = catalog?.models && typeof catalog.models === 'object' ? catalog.models : {};
  const imageIds = new Set(Array.isArray(catalog?.imageGenerationModelIds) ? catalog.imageGenerationModelIds : []);
  const result = Object.create(null);
  const families = new Map();
  const singletons = [];

  for (const [id, info] of Object.entries(modelsMap)) {
    if (!info || typeof info !== 'object') continue;
    if (info.disabled === true || info.isInternal === true) continue;
    if (IGNORED_MODEL_RE.test(id)) continue;
    if (isOrchestratorModel(id, info.displayName)) continue;
    // Redundant tiered duplicates share the same displayName as the canonical variants.
    if (/-tiered-(?:minimal|low|medium|high|xhigh|max)$/i.test(id) && modelsMap[id.replace(/-tiered-/i, '-')]) {
      continue;
    }

    const isImage = imageIds.has(id) || /image/i.test(id);
    if (isImage && !opts.imageModels) continue;

    const match = !isImage ? TIER_SUFFIX_RE.exec(id) : null;
    if (match) {
      const base = match[1];
      const tier = match[2].toLowerCase();
      if (!families.has(base)) families.set(base, []);
      families.get(base).push({ id, tier, info });
    } else {
      singletons.push({ id, info, isImage });
    }
  }

  const addModel = (id, name, info, variants = {}, isImage = false) => {
    const rawContext = contextLimitForModel(id, info);
    const rawOutput = Number.isInteger(info?.maxOutputTokens) && info.maxOutputTokens > 0
      ? info.maxOutputTokens
      : (Number.isInteger(info?.maxTokens) && info.maxTokens > 0 ? info.maxTokens : 65536);
    const context = opts.explicitContextLimit ? Math.min(rawContext, opts.explicitContextLimit) : rawContext;
    const output = Math.min(opts.explicitOutputLimit ? Math.min(rawOutput, opts.explicitOutputLimit) : rawOutput, context);
    const isGoogle = (info?.modelProvider || '').includes('GOOGLE') || /^gemini-/i.test(id);
    const supportsImageInput = isImage || Boolean(opts.allowImages && (isGoogle || info?.supportsImages || info?.supportedMimeTypes?.['image/png']));
    const reasoning = Boolean(info?.supportsThinking || info?.thinkingLevel !== undefined || info?.thinkingBudget !== undefined || Object.keys(variants).length > 0);

    result[id] = {
      id,
      providerID: ANTIGRAVITY_ID,
      name,
      api: {
        id,
        url: opts.baseURL || ANTIGRAVITY_BASE,
        npm: isImage ? '@ai-sdk/google' : '@ai-sdk/openai-compatible'
      },
      limit: { context, output },
      capabilities: {
        temperature: !isImage,
        reasoning,
        attachment: supportsImageInput,
        toolcall: Boolean(!isImage && opts.allowTools),
        input: { text: true, image: supportsImageInput },
        output: { text: true, image: isImage }
      },
      cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
      options: {},
      headers: {},
      variants,
      status: 'active'
    };
  };

  for (const [base, items] of families.entries()) {
    if (items.length >= 2) {
      const order = { minimal: 0, low: 1, medium: 2, high: 3, xhigh: 4, max: 5 };
      items.sort((a, b) => (order[a.tier] ?? 9) - (order[b.tier] ?? 9));
      const variants = {};
      for (const item of items) variants[item.tier] = {};
      const rep = items.find(i => i.tier === 'high') || items.find(i => i.tier === 'medium') || items[0];
      addModel(base, cleanDisplayName(rep.info.displayName, base), rep.info, variants, false);
    } else {
      const only = items[0];
      addModel(only.id, only.info.displayName || only.id, only.info, {}, false);
      if (only.id === 'gpt-oss-120b-medium' && !result['gpt-oss-120b']) {
        addModel('gpt-oss-120b', cleanDisplayName(only.info.displayName, 'gpt-oss-120b'), only.info, { medium: {} }, false);
      }
    }
  }

  for (const { id, info, isImage } of singletons) {
    if (result[id]) continue;
    addModel(id, info.displayName || id, info, {}, isImage);
  }

  if (Object.keys(result).length === 0) {
    throw new Error('No usable models found in Antigravity catalog');
  }
  return result;
}

async function getAccountCatalog(account, opts) {
  const cached = catalogCache.get(account.id);
  if (cached && Date.now() - cached.at < CATALOG_CACHE_MS) {
    return cached.catalog;
  }
  const fresh = await ensureFreshAccountToken(account, opts);
  const catalog = await fetchAvailableModels(fresh.accessToken, fresh.projectId, {
    ...opts,
    proxy: opts.proxy || fresh.proxy,
    timeoutMs: opts.modelTimeoutMs
  });
  catalogCache.set(account.id, { catalog, at: Date.now() });
  return catalog;
}

export async function listAntigravityModels(auth, opts) {
  const accounts = resolveAuthAccounts(auth, opts);
  if (accounts.length === 0) {
    throw new Error('Antigravity 还没有登录账号');
  }
  let lastErr;
  for (const acc of accounts) {
    try {
      const catalog = await getAccountCatalog(acc, opts);
      return buildAntigravityModels(catalog, opts);
    } catch (err) {
      lastErr = err;
      if (err?.invalidGrant) continue;
    }
  }
  throw lastErr || new Error('Failed to fetch Antigravity models');
}

function normalizeCatalogName(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\s+/g, ' ').replace(/[.,;]$/, '');
}

function stripEffortSuffix(name) {
  return String(name ?? '').replace(/\s+\((?:high|medium|low|minimal|xhigh|max)\)$/i, '').trim();
}

function listedGroupNames(description) {
  const match = /Models within this group:\s*(.+)/i.exec(String(description ?? ''));
  if (!match) return null;
  return match[1]
    .split(/,|\s+and\s+/i)
    .map(normalizeCatalogName)
    .filter(Boolean);
}

function vendorOfFamily(id, name) {
  const l = String(id ?? '').toLowerCase();
  if (l.startsWith('gemini')) return 'Gemini';
  if (l.startsWith('claude')) return 'Claude';
  if (l.startsWith('gpt-oss')) return 'GPT-OSS';
  return String(name ?? '').trim().split(' ')[0] || String(id ?? '').split('-')[0];
}

function cadenceOfBucket(bucket) {
  const id = String(bucket?.bucketId ?? bucket?.bucket_id ?? bucket?.id ?? '').trim();
  const label = String(bucket?.displayName ?? bucket?.display_name ?? bucket?.name ?? '').trim();
  const win = String(bucket?.window ?? '').trim();
  const value = win || `${id} ${label}`;
  if (/^(?:5h|five[_ -]?hours?|five_hour|session)$/i.test(value) || (!win && /(?:5h|five[ _-]hour|session)/i.test(value))) {
    return { name: '5 hours', span: 5 * 3600 };
  }
  if (/^(?:weekly|week|7d|seven[_ -]?days?)$/i.test(value) || (!win && /(?:weekly|week|7d)/i.test(value))) {
    return { name: '7 days', span: 7 * 24 * 3600 };
  }
  return { name: label || id || 'Quota' };
}

function normalizeResetTime(value) {
  if (value == null || value === '' || typeof value === 'boolean') return undefined;
  const raw = String(value);
  let ms;
  if (/^\d+(?:\.\d+)?$/.test(raw)) ms = Number(raw) * (Number(raw) < 1e11 ? 1000 : 1);
  else if (/^\d{4}-\d{2}-\d{2}T/.test(raw)) ms = Date.parse(raw);
  if (!Number.isFinite(ms) || ms <= 0 || ms > 253402300799999) return undefined;
  return new Date(ms).toISOString();
}

function buildCatalogNameIndex(catalog) {
  const index = new Map();
  const modelsMap = catalog?.models && typeof catalog.models === 'object' ? catalog.models : {};
  const families = new Map();
  const shown = new Map();
  const claims = new Map();

  for (const [id, info] of Object.entries(modelsMap)) {
    if (!info || typeof info !== 'object') continue;
    if (info.disabled === true || info.isInternal === true) continue;
    if (IGNORED_MODEL_RE.test(id)) continue;
    if (isOrchestratorModel(id, info.displayName)) continue;
    if (/image/i.test(id)) continue;
    if (/-tiered-(?:minimal|low|medium|high|xhigh|max)$/i.test(id) && modelsMap[id.replace(/-tiered-/i, '-')]) continue;

    const effort = TIER_SUFFIX_RE.exec(id)?.[2]?.toLowerCase() || '';
    const family = effort ? id.slice(0, -(effort.length + 1)) : id;
    if (!families.has(family)) families.set(family, new Set());
    families.get(family).add(id);

    const rawName = String(info.displayName || '').trim().replace(/\s+/g, ' ');
    const norm = normalizeCatalogName(rawName);
    if (!norm) continue;
    if (!shown.has(family)) shown.set(family, stripEffortSuffix(rawName));
    for (const alias of [norm, normalizeCatalogName(stripEffortSuffix(rawName))]) {
      if (!claims.has(alias)) claims.set(alias, new Set());
      claims.get(alias).add(family);
    }
  }

  for (const [family, ids] of families) {
    ids.add(family);
  }
  for (const [name, owners] of claims) {
    if (owners.size !== 1) continue;
    const [family] = owners;
    index.set(name, {
      family,
      name: shown.get(family) || family,
      ids: [...families.get(family)].sort()
    });
  }
  return index;
}

function familiesInGroup(group, index) {
  if (!index || !index.size) return [];
  const found = new Map();
  const add = entry => {
    if (entry && !found.has(entry.family)) found.set(entry.family, entry);
  };
  for (const name of listedGroupNames(group?.description) || []) {
    add(index.get(name));
  }
  const groupTitle = String(group?.displayName ?? group?.display_name ?? group?.name ?? '');
  if (!found.size) {
    add(index.get(normalizeCatalogName(groupTitle.replace(/\s+models$/i, ''))));
  }
  if (!found.size) {
    const g = groupTitle.toLowerCase();
    for (const entry of index.values()) {
      const f = entry.family.toLowerCase();
      if (g.includes('argon') && f.includes('argon')) add(entry);
      else if ((g.includes('claude') || g.includes('gpt') || g.includes('3p')) && (f.startsWith('claude') || f.startsWith('gpt'))) add(entry);
      else if (g.includes('gemini') && !g.includes('argon') && f.startsWith('gemini') && !f.includes('argon')) add(entry);
    }
  }
  return [...found.values()].map(e => ({ id: e.family, name: e.name, ids: [...e.ids].sort() }));
}

function parseUsageSummary(summary, catalog) {
  const index = buildCatalogNameIndex(catalog);
  const poolWindows = [];
  const models = new Map();

  for (const group of Array.isArray(summary?.groups) ? summary.groups : []) {
    const rawPool = String(group?.displayName ?? group?.display_name ?? group?.name ?? '').trim() || 'Quota';
    const pool = rawPool.replace(/\s+models$/i, '').replace(/\s+and\s+/gi, ' & ');
    const families = familiesInGroup(group, index);
    const ids = [...new Set(families.flatMap(f => f.ids))].sort();
    let tightest = null;

    for (const bucket of Array.isArray(group?.buckets) ? group.buckets : []) {
      if (!bucket || bucket.disabled === true) continue;
      const period = cadenceOfBucket(bucket);
      const fraction = bucket.remainingFraction ?? bucket.remaining_fraction ?? bucket.remaining?.remainingFraction;
      const known = typeof fraction === 'number' && Number.isFinite(fraction) && fraction >= 0 && fraction <= 1;
      const resetsAt = normalizeResetTime(bucket.resetTime ?? bucket.reset_time);
      const w = {
        name: period.name,
        pool,
        // Displays quota only; must not lock or change model routing in Magpie.
        aside: true,
        ...(ids.length ? { models: ids } : {}),
        ...(known ? { used: Math.round((1 - fraction) * 1e8) / 1e6 } : { display: 'Limits not available' }),
        ...(period.span ? { span: period.span } : {}),
        ...(resetsAt ? { resetsAt } : {})
      };
      poolWindows.push(w);
      if (known && (!tightest || w.used > tightest.used)) tightest = w;
    }

    if (!tightest) continue;
    for (const f of families) {
      const had = models.get(f.id);
      if (had && had.used >= tightest.used) continue;
      models.set(f.id, {
        name: f.name,
        model: f.id,
        family: vendorOfFamily(f.id, f.name),
        pool,
        aside: true,
        models: f.ids,
        used: tightest.used,
        ...(tightest.span ? { span: tightest.span } : {}),
        ...(tightest.resetsAt ? { resetsAt: tightest.resetsAt } : {})
      });
    }
  }

  return [...[...models.values()].sort((a, b) => a.name.localeCompare(b.name)), ...poolWindows];
}

export async function antigravityUsage(auth, opts) {
  if (!auth || auth.type !== 'api') {
    return { error: 'Antigravity 还没有登录', windows: [], signIn: 'kept' };
  }
  const accounts = resolveAuthAccounts(auth, opts);
  if (accounts.length === 0) {
    return { error: '没有找到对应的 Antigravity 账号，请重新导入 Refresh Token', windows: [], signIn: 'expired' };
  }

  const reads = await Promise.all(accounts.map(async acc => {
    try {
      const fresh = await ensureFreshAccountToken(acc, opts);
      let catalog = catalogCache.get(acc.id)?.catalog;
      const [summary, fetchedCatalog] = await Promise.all([
        fetchQuotaSummary(fresh.accessToken, fresh.projectId, {
          ...opts,
          proxy: opts.proxy || fresh.proxy,
          timeoutMs: opts.modelTimeoutMs
        }),
        catalog
          ? Promise.resolve(catalog)
          : fetchAvailableModels(fresh.accessToken, fresh.projectId, {
            ...opts,
            proxy: opts.proxy || fresh.proxy,
            timeoutMs: opts.modelTimeoutMs
          }).catch(() => null)
      ]);
      if (fetchedCatalog && !catalog) {
        catalog = fetchedCatalog;
        catalogCache.set(acc.id, { catalog, at: Date.now() });
      }
      let windows = parseUsageSummary(summary, catalog);
      if (windows.length === 0 && catalog) {
        const models = catalog?.models || {};
        const rep = models['gemini-4-hydrogen-high'] || models['gemini-3.8-flash-high'] || Object.values(models)[0];
        if (typeof rep?.quotaInfo?.remainingFraction === 'number') {
          const resetsAt = normalizeResetTime(rep.quotaInfo.resetTime);
          windows.push({
            name: '5 hours',
            pool: 'Gemini',
            aside: true,
            used: Math.round((1 - rep.quotaInfo.remainingFraction) * 1e8) / 1e6,
            span: 5 * 3600,
            ...(resetsAt ? { resetsAt } : {})
          });
        }
      }
      return { account: fresh, windows };
    } catch (err) {
      return { account: acc, error: err };
    }
  }));

  const ok = reads.filter(r => !r.error);
  const user = accountGroupLabel(accounts);
  if (ok.length === 0) {
    const firstErr = reads[0]?.error;
    const verifyMsg = formatVerifyRefusal(firstErr?.message);
    return {
      user,
      error: verifyMsg || firstErr?.message || '无法读取 Antigravity 额度',
      windows: [],
      signIn: firstErr?.invalidGrant ? 'expired' : 'kept'
    };
  }

  const plan = ok[0].account.tier;
  if (ok.length === 1) {
    return { user, ...(plan ? { plan } : {}), windows: ok[0].windows, signIn: 'kept' };
  }

  // Aggregate across multiple accounts in a batch card using the tightest window per key.
  const byKey = new Map();
  for (const r of ok) {
    for (const w of r.windows) {
      const key = w.model ? `model:${w.model}` : `pool:${w.pool || ''}:${w.name}`;
      const list = byKey.get(key) || [];
      list.push({ ...w, email: r.account.email });
      byKey.set(key, list);
    }
  }
  const windows = [];
  for (const entries of byKey.values()) {
    const tightest = entries.reduce((a, b) => ((b.used ?? -1) > (a.used ?? -1) ? b : a));
    const { email: _e, ...rest } = tightest;
    if (!rest.model) {
      const summaryParts = entries.map(e => `${String(e.email || '').replace(/@gmail\.com$/i, '')} ${Math.round(e.used ?? 0)}%`);
      windows.push({ ...rest, display: `各账号已用 ${summaryParts.join('，')}` });
    } else {
      windows.push(rest);
    }
  }
  return { user, ...(plan ? { plan } : {}), windows, signIn: 'kept' };
}

function buildInferenceHeaders(accessToken, projectId, targetModel, opts = {}) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'User-Agent': currentEgressUserAgent({
      dataDir: opts.dataDir,
      env: opts.env || process.env,
      ...(opts.detectLocal !== undefined ? { detectLocal: opts.detectLocal } : {})
    })
  };
  if (projectId && !SKIP_USER_PROJECT.has(projectId)) {
    headers['x-goog-user-project'] = projectId;
  }
  if (String(targetModel || '').toLowerCase().includes('claude')) {
    headers['anthropic-beta'] = 'claude-code-20250219';
  }
  return headers;
}

function parseDurationStringMs(raw) {
  if (typeof raw !== 'string') return null;
  const re = /([\d.]+)\s*(ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?)/gi;
  let total = 0;
  let matched = false;
  let m;
  while ((m = re.exec(raw)) !== null) {
    matched = true;
    const val = Number(m[1]);
    if (!Number.isFinite(val)) continue;
    const unit = m[2].toLowerCase();
    if (unit === 'ms' || unit.startsWith('millisecond')) total += val;
    else if (unit === 's' || unit.startsWith('sec')) total += val * 1000;
    else if (unit === 'm' || unit.startsWith('min')) total += val * 60 * 1000;
    else if (unit === 'h' || unit.startsWith('hr') || unit.startsWith('hour')) total += val * 3600 * 1000;
  }
  return matched ? Math.round(total) : null;
}

function findStructuredRetryDelayMs(node, depth = 0) {
  if (depth > 8 || !node || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findStructuredRetryDelayMs(item, depth + 1);
      if (found !== null) return found;
    }
    return null;
  }
  for (const [k, v] of Object.entries(node)) {
    const lk = k.toLowerCase();
    if (lk === 'retrydelay' || lk === 'retry_delay' || lk === 'quotaresetdelay' || lk === 'quota_reset_delay') {
      if (typeof v === 'string') {
        const ms = parseDurationStringMs(v);
        if (ms !== null) return ms;
      } else if (typeof v === 'number' && Number.isFinite(v)) {
        return Math.round(v * 1000);
      }
    }
    if (v && typeof v === 'object') {
      const found = findStructuredRetryDelayMs(v, depth + 1);
      if (found !== null) return found;
    }
  }
  return null;
}

function parseRetryDelayMs(res, bodyText) {
  const retryAfter = res?.headers?.get?.('retry-after');
  let headerMs = null;
  if (retryAfter) {
    const trimmed = retryAfter.trim();
    if (/^\d+$/.test(trimmed)) headerMs = Number(trimmed) * 1000;
    else headerMs = parseDurationStringMs(trimmed);
  }
  let bodyMs = null;
  if (bodyText) {
    try {
      bodyMs = findStructuredRetryDelayMs(JSON.parse(bodyText));
    } catch {}
    if (bodyMs === null) {
      const textMatch = /(?:retry after|try again in|reset in|resets in|backoff for)\s+([^.,;\n\]]+)/i.exec(bodyText);
      if (textMatch) bodyMs = parseDurationStringMs(textMatch[1]);
    }
  }
  if (headerMs !== null && bodyMs !== null) return Math.max(headerMs, bodyMs);
  return bodyMs ?? headerMs;
}

function abortableSleep(ms, signal) {
  if (ms <= 0) return Promise.resolve();
  if (signal?.aborted) return Promise.reject(signal.reason || new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason || new DOMException('Aborted', 'AbortError'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function nextRetryRequestId(prevId) {
  const parts = typeof prevId === 'string' ? prevId.split('/') : [];
  if (parts.length === 5 && parts[0] === 'agent') {
    return `agent/${parts[1]}/${Date.now()}/${parts[3]}/${parts[4]}`;
  }
  return prevId;
}

const LARGE_PAYLOAD_FALLBACK_THRESHOLD = 512 * 1024;
const DEFAULT_RATE_LIMIT_BACKOFFS_MS = [3000, 6000, 10000];

function isLongQuotaExhausted(status, text) {
  return status === 429
    && /Individual quota reached|quota.*exhausted/i.test(text || '')
    && /Resets in \d+[hm]/i.test(text || '');
}

async function callV1Internal({ account, method, envelope, targetModel, opts, signal }) {
  let fresh = await ensureFreshAccountToken(account, opts);
  let forceRefreshed = false;
  let lastRes = null;
  let lastText = '';
  let lastErr = null;
  const maxRateRetries = Number.isInteger(opts.rateLimitRetries) ? opts.rateLimitRetries : 3;
  const maxRetryDelayMs = Number.isInteger(opts.maxRetryDelayMs) ? opts.maxRetryDelayMs : 15000;

  for (let rateTry = 0; rateTry <= maxRateRetries; rateTry++) {
    if (rateTry > 0 && envelope?.requestId) {
      envelope.requestId = nextRetryRequestId(envelope.requestId);
      const traj = envelope.requestId.split('/')[3];
      if (traj && envelope.request?.labels && typeof envelope.request.labels === 'object') {
        envelope.request.labels.trajectory_id = traj;
        envelope.request.labels.request_id = `${traj}-${envelope.request.labels.last_step_index ?? 0}`;
      }
    }
    const payloadStr = JSON.stringify(envelope);

    lastRes = null;
    lastText = '';
    let shouldRetryRateLimit = false;

    for (const base of V1_INTERNAL_BASES) {
      const url = method === 'streamGenerateContent'
        ? `${base}:streamGenerateContent?alt=sse`
        : `${base}:${method}`;

      for (let authTry = 0; authTry < 2; authTry++) {
        let res;
        try {
          res = await fetchWithProxy(url, {
            method: 'POST',
            headers: buildInferenceHeaders(fresh.accessToken, fresh.projectId, targetModel, opts),
            body: payloadStr,
            signal
          }, { ...opts, proxy: opts.proxy || fresh.proxy });
        } catch (err) {
          if (signal?.aborted) throw err;
          lastErr = err;
          break;
        }

        if (res.status === 401 && !forceRefreshed) {
          forceRefreshed = true;
          fresh = await ensureFreshAccountToken(fresh, { ...opts, forceRefresh: true });
          continue;
        }

        if (res.ok) {
          return { res, text: '', account: fresh };
        }

        const errText = await res.text().catch(() => '');
        // Do not let sandbox geo-restriction 400 hide an earlier primary 429/5xx error.
        if (!lastRes || !(res.status === 400 && url.includes('sandbox.googleapis.com') && lastRes.status >= 429)) {
          lastRes = res;
          lastText = errText;
        }

        if (isLongQuotaExhausted(res.status, errText)) {
          return { res: lastRes, text: lastText, account: fresh };
        }

        // Daily and sandbox share the user rate-limit bucket; avoid re-uploading multi-MB bodies
        // or re-probing sandbox on subsequent retry rounds after a primary 429.
        if (res.status === 429 && (rateTry > 0 || payloadStr.length > LARGE_PAYLOAD_FALLBACK_THRESHOLD)) {
          break;
        }

        if (shouldFallbackEndpoint(res.status, url)) {
          break;
        }
        return { res: lastRes, text: lastText, account: fresh };
      }
      if (lastRes?.status === 429 && (rateTry > 0 || payloadStr.length > LARGE_PAYLOAD_FALLBACK_THRESHOLD)) {
        break;
      }
    }

    if (lastRes && (lastRes.status === 429 || lastRes.status === 503) && rateTry < maxRateRetries) {
      const parsedDelay = parseRetryDelayMs(lastRes, lastText);
      const waitMs = parsedDelay !== null
        ? parsedDelay + 150
        : (Number.isFinite(opts.rateLimitBackoffMs)
          ? opts.rateLimitBackoffMs * (rateTry + 1)
          : (DEFAULT_RATE_LIMIT_BACKOFFS_MS[rateTry] ?? 10000));
      if (waitMs <= maxRetryDelayMs) {
        shouldRetryRateLimit = true;
        await abortableSleep(waitMs, signal);
      }
    }
    if (!shouldRetryRateLimit) break;
  }

  if (lastRes) return { res: lastRes, text: lastText, account: fresh };
  throw lastErr || new Error('All Antigravity endpoints failed');
}

function isMeaningfulOpenAISSELine(line) {
  if (!line.startsWith('data:')) return false;
  const raw = line.slice(5).trim();
  if (!raw || raw === '[DONE]') return false;
  try {
    const obj = JSON.parse(raw);
    const choices = Array.isArray(obj?.choices) ? obj.choices : [];
    return choices.some(c => {
      const delta = c?.delta;
      if (!delta || typeof delta !== 'object') return false;
      if (typeof delta.content === 'string' && delta.content.length > 0) return true;
      if (typeof delta.reasoning_content === 'string' && delta.reasoning_content.length > 0) return true;
      if (Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0) return true;
      return false;
    });
  } catch {
    return false;
  }
}

function isMeaningfulGeminiSSELine(line) {
  if (!line.startsWith('data:')) return false;
  const raw = line.slice(5).trim();
  if (!raw || raw === '[DONE]') return false;
  try {
    const obj = JSON.parse(raw);
    return !isGeminiResponseEmpty(obj);
  } catch {
    return false;
  }
}

async function gateMeaningfulSSEStream(stream, isMeaningfulLine) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  const buffered = [];
  let scanBuffer = '';
  let sawMeaningful = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      buffered.push(value);
      scanBuffer += decoder.decode(value, { stream: true });
      const lines = scanBuffer.split(/\r?\n/);
      scanBuffer = lines.pop() || '';
      if (lines.some(isMeaningfulLine)) {
        sawMeaningful = true;
        break;
      }
    }
  }

  if (!sawMeaningful) {
    scanBuffer += decoder.decode();
    if (scanBuffer.split(/\r?\n/).some(isMeaningfulLine)) {
      sawMeaningful = true;
    }
  }

  if (!sawMeaningful) {
    try { await reader.cancel(); } catch {}
    return { empty: true, stream: null };
  }

  const replayed = new ReadableStream({
    start(controller) {
      for (const chunk of buffered) {
        controller.enqueue(chunk);
      }
    },
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        return;
      }
      controller.enqueue(value);
    },
    cancel(reason) {
      return reader.cancel(reason);
    }
  });
  return { empty: false, stream: replayed };
}

async function waitEmptyReplyBudget({ emptyAttempt, emptyStartMs, opts, signal }) {
  const maxWaitMs = Number(opts.emptyReplyMaxWaitMs) || 0;
  if (maxWaitMs <= 0 || signal?.aborted) {
    return { retry: false, elapsedMs: 0 };
  }
  const elapsedMs = Math.max(0, Date.now() - emptyStartMs);
  const remainingMs = maxWaitMs - elapsedMs;
  if (remainingMs <= 0 || emptyAttempt >= MAX_EMPTY_REPLY_RETRIES) {
    return { retry: false, elapsedMs };
  }
  const baseDelay = Number.isFinite(opts.emptyReplyRetryDelayMs)
    ? opts.emptyReplyRetryDelayMs
    : DEFAULT_EMPTY_REPLY_RETRY_DELAY_MS;
  const waitMs = Math.min(Math.max(0, baseDelay), remainingMs);
  if (waitMs > 0) {
    await abortableSleep(waitMs, signal);
  }
  return { retry: !signal?.aborted, elapsedMs };
}

export async function forwardAntigravity(input, init, getAuth, opts) {
  const req = new Request(input, init);
  let auth;
  try {
    auth = await getAuth();
  } catch {
    return makeOpenAIError(401, 'Authentication loader failed');
  }
  if (!auth || auth.type !== 'api') {
    return makeOpenAIError(401, 'Unauthorized: Antigravity sign-in required');
  }

  const accounts = resolveAuthAccounts(auth, opts);
  if (accounts.length === 0) {
    return makeOpenAIError(401, 'Unauthorized: no Antigravity account found');
  }

  let reqUrl;
  try {
    reqUrl = new URL(req.url);
  } catch {
    return makeOpenAIError(400, 'Invalid request URL');
  }
  const base = new URL(opts.baseURL || ANTIGRAVITY_BASE);
  if (reqUrl.origin !== base.origin || !reqUrl.pathname.startsWith(base.pathname)) {
    return makeOpenAIError(404, 'Endpoint not found');
  }
  const subPath = reqUrl.pathname.slice(base.pathname.length);
  const geminiMatch = GEMINI_CALL_RE.exec(subPath);

  if (subPath === '/models' && req.method === 'GET') {
    try {
      const models = await listAntigravityModels(auth, opts);
      return Response.json({
        object: 'list',
        data: Object.keys(models).map(id => ({ id, object: 'model' }))
      });
    } catch (err) {
      return makeOpenAIError(err?.status || 502, err?.message || 'Failed to list models');
    }
  }

  if (subPath !== '/chat/completions' && !geminiMatch) {
    return makeOpenAIError(404, 'Endpoint not found');
  }
  if (req.method !== 'POST') {
    return makeOpenAIError(400, 'Method not allowed: POST required');
  }

  let body;
  try {
    body = JSON.parse(await req.text());
  } catch {
    return makeOpenAIError(400, 'Invalid JSON body');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return makeOpenAIError(400, 'Request body must be a JSON object');
  }

  if (!opts.allowTools && Array.isArray(body.tools) && body.tools.length > 0) {
    return makeOpenAIError(400, 'Tool calls are turned off for Antigravity in plugin options');
  }

  const timeoutController = new AbortController();
  const timer = setTimeout(() => {
    timeoutController.abort(new DOMException(`Antigravity request timed out after ${opts.requestTimeoutMs} ms`, 'TimeoutError'));
  }, opts.requestTimeoutMs);
  const signal = AbortSignal.any([req.signal, timeoutController.signal]);

  try {
    const signatureCache = loadSignatureStore(opts.dataDir);
    const activeAccounts = opts.failoverOnError === false ? accounts.slice(0, 1) : accounts;
    let lastErrorRes = null;
    let lastErrorText = '';
    let lastError = null;
    let lastEmptyErrorMsg = '';
    let sawInvalidGrant = false;
    const useEmptyGate = Number(opts.emptyReplyMaxWaitMs) > 0;
    const emptyStartMs = useEmptyGate ? Date.now() : 0;
    const maxEmptyPasses = useEmptyGate ? MAX_EMPTY_REPLY_RETRIES + 1 : 1;
    let emptyAttempt = 0;

    outer: for (let emptyPass = 0; emptyPass < maxEmptyPasses; emptyPass++) {
      for (let accIdx = 0; accIdx < activeAccounts.length; accIdx++) {
        const acc = activeAccounts[accIdx];
        const hasNextAccount = accIdx + 1 < activeAccounts.length;
        const callOpts = hasNextAccount ? { ...opts, rateLimitRetries: 0 } : opts;
        let catalog = catalogCache.get(acc.id)?.catalog;
        if (!catalog) {
          try {
            catalog = await getAccountCatalog(acc, opts);
          } catch {
            catalog = {};
          }
        }

        const conversationSeed = deriveConversationAnchor(body, Boolean(geminiMatch));
        const upstreamSessionId = deriveUpstreamSessionId(acc.id, conversationSeed);

        if (geminiMatch) {
          const targetModel = resolveAntigravityModel(decodeURIComponent(geminiMatch[1]), null, catalog);
          const method = geminiMatch[2];
          const envelope = wrapGeminiNativeRequest(body, {
            targetModel,
            projectId: acc.projectId,
            email: acc.email,
            clientType: acc.clientType,
            sessionId: upstreamSessionId,
            conversationSeed,
            catalog,
            compactPrompt: opts.compactPrompt
          });
          try {
            const { res, text } = await callV1Internal({ account: acc, method, envelope, targetModel, opts: callOpts, signal });
            if (res.ok) {
              if (method === 'streamGenerateContent') {
                const sse = unwrapGeminiNativeSSE(res.body, { idleTimeoutMs: opts.streamIdleTimeoutMs, signal });
                if (!useEmptyGate) {
                  return new Response(sse, {
                    status: 200,
                    headers: { 'content-type': 'text/event-stream; charset=utf-8' }
                  });
                }
                const gated = await gateMeaningfulSSEStream(sse, isMeaningfulGeminiSSELine);
                if (!gated.empty) {
                  return new Response(gated.stream, {
                    status: 200,
                    headers: { 'content-type': 'text/event-stream; charset=utf-8' }
                  });
                }
                const waitState = await waitEmptyReplyBudget({ emptyAttempt, emptyStartMs, opts, signal });
                emptyAttempt += 1;
                if (waitState.retry) {
                  lastErrorRes = null;
                  lastErrorText = '';
                  lastError = null;
                  continue;
                }
                lastEmptyErrorMsg = `Antigravity returned an empty reply (candidatesTokenCount = 0) after ${waitState.elapsedMs} ms (emptyReplyMaxWaitMs=${opts.emptyReplyMaxWaitMs})`;
                break outer;
              }
              const json = await res.json();
              const unwrapped = json?.response || json;
              if (useEmptyGate && isGeminiResponseEmpty(unwrapped)) {
                const waitState = await waitEmptyReplyBudget({ emptyAttempt, emptyStartMs, opts, signal });
                emptyAttempt += 1;
                if (waitState.retry) {
                  lastErrorRes = null;
                  lastErrorText = '';
                  lastError = null;
                  continue;
                }
                lastEmptyErrorMsg = `Antigravity returned an empty reply (candidatesTokenCount = 0) after ${waitState.elapsedMs} ms (emptyReplyMaxWaitMs=${opts.emptyReplyMaxWaitMs})`;
                break outer;
              }
              return Response.json(unwrapped);
            }
            lastErrorRes = res;
            lastErrorText = text;
            if (res.status === 429 || res.status === 503 || res.status === 403 || res.status === 401) continue;
            break outer;
          } catch (err) {
            if (err?.invalidGrant) sawInvalidGrant = true;
            lastError = err;
            if (req.signal.aborted) throw err;
            if (err?.name === 'TimeoutError') break outer;
          }
          continue;
        }

        const stream = Boolean(body.stream);
        const includeUsage = Boolean(body.stream_options?.include_usage);
        const { targetModel, envelope } = openAIToAntigravityRequest(body, {
          catalog,
          projectId: acc.projectId,
          email: acc.email,
          clientType: acc.clientType,
          signatureCache,
          sessionId: upstreamSessionId,
          conversationSeed,
          compactPrompt: opts.compactPrompt,
          toolTokenBudget: opts.toolTokenBudget
        });

        try {
          const method = stream ? 'streamGenerateContent' : 'generateContent';
          const { res, text } = await callV1Internal({ account: acc, method, envelope, targetModel, opts: callOpts, signal });

          if (res.ok) {
            if (stream) {
              const sseStream = antigravitySSEToOpenAIStream(res.body, {
                model: body.model || targetModel,
                includeUsage,
                signatureCache,
                idleTimeoutMs: opts.streamIdleTimeoutMs,
                signal
              });
              if (!useEmptyGate) {
                return new Response(sseStream, {
                  status: 200,
                  headers: {
                    'content-type': 'text/event-stream; charset=utf-8',
                    'cache-control': 'no-cache'
                  }
                });
              }
              const gated = await gateMeaningfulSSEStream(sseStream, isMeaningfulOpenAISSELine);
              if (!gated.empty) {
                return new Response(gated.stream, {
                  status: 200,
                  headers: {
                    'content-type': 'text/event-stream; charset=utf-8',
                    'cache-control': 'no-cache'
                  }
                });
              }
              const waitState = await waitEmptyReplyBudget({ emptyAttempt, emptyStartMs, opts, signal });
              emptyAttempt += 1;
              if (waitState.retry) {
                lastErrorRes = null;
                lastErrorText = '';
                lastError = null;
                continue;
              }
              lastEmptyErrorMsg = `Antigravity returned an empty reply (candidatesTokenCount = 0) after ${waitState.elapsedMs} ms (emptyReplyMaxWaitMs=${opts.emptyReplyMaxWaitMs})`;
              break outer;
            }
            const rawJson = await res.json();
            const formatted = antigravityToOpenAIResponse(rawJson, {
              model: body.model || targetModel,
              signatureCache
            });
            signatureCache.flush();
            if (useEmptyGate && isOpenAIChatResponseEmpty(formatted)) {
              const waitState = await waitEmptyReplyBudget({ emptyAttempt, emptyStartMs, opts, signal });
              emptyAttempt += 1;
              if (waitState.retry) {
                lastErrorRes = null;
                lastErrorText = '';
                lastError = null;
                continue;
              }
              lastEmptyErrorMsg = `Antigravity returned an empty reply (candidatesTokenCount = 0) after ${waitState.elapsedMs} ms (emptyReplyMaxWaitMs=${opts.emptyReplyMaxWaitMs})`;
              break outer;
            }
            return Response.json(formatted);
          }

          lastErrorRes = res;
          lastErrorText = text;
          if (res.status === 429 || res.status === 503 || res.status === 403 || res.status === 401) {
            continue;
          }
          break outer;
        } catch (err) {
          if (err?.invalidGrant) sawInvalidGrant = true;
          lastError = err;
          if (req.signal.aborted) throw err;
          if (err?.name === 'TimeoutError') break outer;
        }
      }
      if (!useEmptyGate || lastErrorRes || lastError) {
        break;
      }
    }

    if (lastEmptyErrorMsg) {
      return makeOpenAIError(502, lastEmptyErrorMsg);
    }

    if (lastErrorRes) {
      const errText = lastErrorText || await lastErrorRes.text().catch(() => '');
      const retryAfter = lastErrorRes.headers?.get?.('retry-after');
      const extraHeaders = retryAfter ? { 'Retry-After': retryAfter } : {};
      if (lastErrorRes.status === 403) {
        const verifyMsg = formatVerifyRefusal(errText);
        if (verifyMsg) {
          return makeOpenAIError(403, verifyMsg, extraHeaders);
        }
      }
      if (lastErrorRes.status === 429) {
        // Long per-family quota exhaustion ("Individual quota reached ... Resets in XhYm") only
        // blocks that model pool (e.g. Claude), while Gemini/Argon may still have allowance.
        // Returning HTTP 429 causes Magpie to freeze the entire account across all models.
        if (isLongQuotaExhausted(lastErrorRes.status, errText)) {
          return makeOpenAIError(
            400,
            `该模型当前配额池已用尽，可切换其它模型池（如 Gemini / Claude）继续使用。上游返回: ${errText}`,
            extraHeaders
          );
        }
        return new Response(JSON.stringify({
          error: {
            message: errText || 'Rate limit exceeded',
            type: 'rate_limit_error',
            param: null,
            code: 'rate_limit_exceeded'
          }
        }), {
          status: 429,
          headers: { 'content-type': 'application/json', ...extraHeaders }
        });
      }
      return makeOpenAIError(lastErrorRes.status, errText || `Antigravity upstream HTTP ${lastErrorRes.status}`, extraHeaders);
    }
    if (sawInvalidGrant) {
      return makeOpenAIError(401, lastError?.message || 'Refresh Token 已失效，请重新登录');
    }
    if (timeoutController.signal.aborted || lastError?.name === 'TimeoutError') {
      return makeOpenAIError(504, lastError?.message || 'Gateway timeout: Antigravity request timed out');
    }
    return makeOpenAIError(502, lastError?.message || 'Failed to reach Antigravity backend');
  } finally {
    clearTimeout(timer);
  }
}

function buildSignInResult(accounts, opts, proxy) {
  if (accounts.length === 1) {
    const a = accounts[0];
    return {
      type: 'success',
      key: a.refreshToken,
      metadata: {
        mode: 'antigravity',
        baseURL: opts.baseURL,
        account: a.id,
        email: a.email,
        clientType: a.clientType,
        oauthClientKey: a.oauthClientKey,
        projectId: a.projectId,
        ...(proxy || a.proxy ? { proxy: proxy || a.proxy } : {})
      }
    };
  }
  return {
    type: 'success',
    key: accounts[0].refreshToken,
    metadata: {
      mode: 'antigravity',
      baseURL: opts.baseURL,
      email: accountGroupLabel(accounts),
      accounts: accounts.map(a => a.id),
      clientType: accounts[0].clientType,
      ...(proxy ? { proxy } : {})
    }
  };
}

const REFRESH_TOKEN_INSTRUCTIONS = [
  '请粘贴你的 Google OAuth Refresh Token（支持从 Antigravity Tools / Antigravity-Manager 导出的格式，支持批量）：',
  '1. 单个 Token：1//03...',
  '2. JSON 数组：[{"refresh_token":"1//..."}, ...]',
  '3. 包含 1//... Token 的任意文本（将自动提取并去重）',
  'Token 仅保存在本机，用于直接向 Google OAuth 换取短期 access_token 并访问 Antigravity 接口。'
].join('\n');

const IMPORT_FROM = {
  en: 'Choose or paste a Refresh Token export (Antigravity-Manager JSON, retired Antigravity plugin sign-in, or agy antigravity-oauth-token file). Each account is verified before it is added.',
  froms: {
    zh: '选择或粘贴 Refresh Token 导出文件（支持 Antigravity-Manager 导出的 JSON、已退役 Antigravity 插件的登录记录、或 agy 自己的令牌文件 antigravity-oauth-token）；每个账号先验证后再添加。',
    'zh-TW': '選擇或貼上 Refresh Token 匯出檔（支援 Antigravity-Manager JSON、已退役 Antigravity 外掛登入記錄、或 agy 自己的權杖檔 antigravity-oauth-token）；每個帳號先驗證後再加入。',
    ja: 'Refresh Token エクスポート（Antigravity-Manager JSON、旧 Antigravity プラグインのサインイン、または agy の antigravity-oauth-token）を選択または貼り付けてください。各アカウントは追加前に検証されます。'
  }
};

export const AntigravityPlugin = async (_input, options = {}) => {
  const opts = antigravitySettings(options);
  const inContainer = isContainerEnv();
  const uaWarmTimer = setTimeout(() => {
    try {
      resolveAntigravityUserAgents({
        dataDir: opts.dataDir,
        ...(opts.detectLocal !== undefined ? { detectLocal: opts.detectLocal } : {})
      });
    } catch {}
    if (opts.uaManifestUrl !== null && (!opts.fetchFn || opts.uaManifestUrl !== undefined)) {
      Promise.resolve(refreshRemoteHubVersion({
        dataDir: opts.dataDir,
        proxy: opts.proxy || undefined,
        ...(opts.uaManifestUrl !== undefined ? { manifestUrl: opts.uaManifestUrl } : {}),
        ...(opts.fetchFn ? { fetchFn: opts.fetchFn } : {})
      })).catch(() => {});
    }
  }, 0);
  if (typeof uaWarmTimer.unref === 'function') uaWarmTimer.unref();

  const importSignIns = async texts => {
    const list = Array.isArray(texts) ? texts : [texts];
    const allTokens = [];
    const seen = new Set();
    let customClientId = '';
    let customClientSecret = '';
    for (const raw of list) {
      try {
        const pkg = parseRefreshTokenPackage(String(raw ?? ''));
        for (const t of pkg.tokens) {
          if (!seen.has(t)) {
            seen.add(t);
            allTokens.push(t);
          }
        }
        if (pkg.clientId && pkg.clientSecret) {
          customClientId = pkg.clientId;
          customClientSecret = pkg.clientSecret;
        }
      } catch {}
    }
    if (allTokens.length === 0) {
      return { type: 'failed', error: '没有在导入内容中找到有效的 Antigravity Refresh Token（1//...）' };
    }
    const out = [];
    for (const rt of allTokens) {
      try {
        const acc = await verifyRefreshToken(rt, {
          ...opts,
          ...(customClientId && customClientSecret ? { customClientId, customClientSecret } : {})
        });
        const saved = saveAntigravityAccount(acc, opts.dataDir);
        out.push(buildSignInResult([saved], opts, opts.proxy));
      } catch (err) {
        out.push({ type: 'failed', error: err?.message || String(err) });
      }
    }
    if (customClientId && customClientSecret && out.some(r => r.type === 'success')) {
      saveOAuthClientCredentials({
        clientType: 'personal',
        clientId: customClientId,
        clientSecret: customClientSecret,
        dataDir: opts.dataDir
      });
    }
    return out;
  };

  const clientTypePrompt = {
    type: 'select',
    key: 'clientType',
    message: '选择账号类型（个人 Gmail 选 Personal；企业 / GCP 自费账号选 Enterprise）',
    options: [
      { label: '个人账号 (Personal)', value: 'personal', hint: '标准 Google / Gmail 账号' },
      { label: '企业 / GCP (Vertex AI)', value: 'enterprise', hint: 'Google Cloud / 企业账号' }
    ]
  };

  const proxyPrompt = {
    type: 'text',
    key: 'proxy',
    message: inContainer
      ? '访问 Google 的代理地址（容器 bridge 网络请填 http://host.docker.internal:<端口>；无需代理可留空）'
      : '访问 Google 的代理地址（无需代理或已设置环境变量 ANTIGRAVITY_PROXY 可留空）',
    placeholder: opts.proxy || (inContainer ? 'http://host.docker.internal:7890' : 'http://127.0.0.1:7890'),
    validate: value => {
      try {
        validateProxyURL(value);
      } catch (e) {
        return e.message;
      }
    }
  };

  const clientIdPrompt = {
    type: 'text',
    key: 'clientId',
    message: 'Google OAuth Client ID（若未通过环境变量或 oauth-clients.json 配置，请填写；也可直接在下方粘贴含 client_id 的 JSON 并留空此项）',
    placeholder: 'xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com'
  };

  const clientSecretPrompt = {
    type: 'text',
    key: 'clientSecret',
    message: 'Google OAuth Client Secret（填写后将保存到本机 oauth-clients.json，下次登录无需再填）',
    placeholder: 'OAuth client secret'
  };

  return {
    config: async cfg => {
      cfg.provider ??= {};
      cfg.provider[ANTIGRAVITY_ID] ??= {
        name: 'Antigravity (RT)',
        npm: '@ai-sdk/openai-compatible',
        api: opts.baseURL,
        models: {}
      };
    },
    auth: {
      provider: ANTIGRAVITY_ID,
      icon: PLUGIN_ICON,
      maxConcurrency: 2,
      importFrom: IMPORT_FROM.en,
      importFroms: IMPORT_FROM.froms,
      import: texts => importSignIns(Array.isArray(texts) ? texts : [texts]),
      methods: [
        {
          type: 'oauth',
          label: '通过 Refresh Token 登录（支持批量）',
          labels: {
            zh: '通过 Refresh Token 登录（支持批量）',
            'zh-TW': '透過 Refresh Token 登入（支援批次）',
            ja: 'Refresh Token でサインイン（一括対応）'
          },
          prompts: [clientTypePrompt, proxyPrompt, clientIdPrompt, clientSecretPrompt],
          ask(inputs) {
            if (!inputs || !('clientType' in inputs)) return clientTypePrompt;
            if (!('proxy' in inputs)) return proxyPrompt;
            const configured = hasConfiguredOAuthClient({ ...opts, clientType: inputs.clientType });
            if (!configured && !('clientId' in inputs)) return clientIdPrompt;
            if (!configured && inputs.clientId?.trim() && !('clientSecret' in inputs)) return clientSecretPrompt;
            return null;
          },
          async authorize(inputs) {
            const clientType = normalizeClientType(inputs?.clientType);
            const proxy = validateProxyURL(inputs?.proxy || opts.proxy || '');
            const inputClientId = typeof inputs?.clientId === 'string' ? inputs.clientId.trim() : '';
            const inputClientSecret = typeof inputs?.clientSecret === 'string' ? inputs.clientSecret.trim() : '';
            const hint = dockerProxyHint(proxy);
            return {
              url: '',
              method: 'code',
              instructions: REFRESH_TOKEN_INSTRUCTIONS + (hint ? `\n\n注意：${hint}` : ''),
              async callback(code) {
                try {
                  const pkg = parseRefreshTokenPackage(code);
                  const customClientId = inputClientId || pkg.clientId || '';
                  const customClientSecret = inputClientSecret || pkg.clientSecret || '';
                  const imported = [];
                  const errors = [];
                  for (const rt of pkg.tokens) {
                    try {
                      const acc = await verifyRefreshToken(rt, {
                        ...opts,
                        clientType,
                        ...(customClientId && customClientSecret ? { customClientId, customClientSecret } : {}),
                        proxy: proxy || undefined
                      });
                      const saved = saveAntigravityAccount(acc, opts.dataDir);
                      imported.push(saved);
                    } catch (err) {
                      errors.push(err?.message || String(err));
                    }
                  }
                  if (imported.length === 0) {
                    return {
                      type: 'failed',
                      error: (errors[0] || 'Refresh Token 验证失败') + (hint ? `\n${hint}` : '')
                    };
                  }
                  if (customClientId && customClientSecret) {
                    saveOAuthClientCredentials({
                      clientType,
                      clientId: customClientId,
                      clientSecret: customClientSecret,
                      dataDir: opts.dataDir
                    });
                  }
                  return buildSignInResult(imported, opts, proxy);
                } catch (err) {
                  return {
                    type: 'failed',
                    error: (err?.message || String(err)) + (hint ? `\n${hint}` : '')
                  };
                }
              }
            };
          }
        },
        {
          type: 'oauth',
          label: '添加本机已保存的 Antigravity 账号',
          labels: {
            zh: '添加本机已保存的 Antigravity 账号',
            'zh-TW': '新增本機已儲存的 Antigravity 帳號',
            ja: '保存済みの Antigravity アカウントを追加'
          },
          prompts: [{ type: 'select', key: 'account', message: '选择 Antigravity 账号', options: [] }],
          ask(inputs) {
            if (inputs?.account) return null;
            const list = loadAntigravityAccounts(opts.dataDir);
            if (list.length === 0) {
              throw new Error('本机还没有已保存的 Antigravity 账号：请先使用「通过 Refresh Token 登录」');
            }
            return {
              type: 'select',
              key: 'account',
              message: '选择 Antigravity 账号',
              placeholder: '',
              options: list.map(a => ({
                label: a.email || a.id,
                value: a.id,
                hint: [a.tier || 'FREE', a.clientType === 'enterprise' ? 'Enterprise' : 'Personal'].join(' · ')
              }))
            };
          },
          async authorize(inputs) {
            const list = loadAntigravityAccounts(opts.dataDir);
            const target = list.find(a => a.id === String(inputs?.account || '').toLowerCase());
            if (!target) {
              throw new Error(`本机没有找到 Antigravity 账号 ${inputs?.account}`);
            }
            return {
              url: '',
              method: 'auto',
              instructions: '',
              callback: async () => buildSignInResult([target], opts, target.proxy || opts.proxy)
            };
          }
        }
      ],
      async loader(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== 'api') return {};
        return {
          apiKey: 'antigravity-oauth',
          baseURL: opts.baseURL,
          fetch: (input, init) => forwardAntigravity(input, init, getAuth, opts)
        };
      },
      async usage(getAuth) {
        const auth = await getAuth();
        return antigravityUsage(auth, opts);
      }
    },
    provider: {
      id: ANTIGRAVITY_ID,
      async models(provider, { auth } = {}) {
        if (auth?.type !== 'api') return provider.models;
        return listAntigravityModels(auth, opts);
      }
    }
  };
};

export default AntigravityPlugin;
