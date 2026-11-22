import { createHash, randomUUID } from 'node:crypto';
import { makeOpenAIError, PLUGIN_ICON } from './backend.mjs';
import { validateProxyURL } from './setup.mjs';
import { isContainerEnv, dockerProxyHint } from './proc.mjs';
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
  openAIToAntigravityRequest,
  resolveAntigravityModel,
  unwrapGeminiNativeSSE,
  wrapGeminiNativeRequest
} from './antigravity-mapper.mjs';

export const ANTIGRAVITY_ID = 'antigravity-rt';
export const ANTIGRAVITY_BASE = 'https://antigravity.local/v1';

const SKIP_USER_PROJECT = new Set(['aicode-consumers', 'test-project', 'project-id']);
const TIER_SUFFIX_RE = /^(.*)-(low|medium|high|xhigh)$/i;
const GEMINI_CALL_RE = /^\/models\/([^/:]+):(generateContent|streamGenerateContent)$/;
const IGNORED_MODEL_RE = /^(?:tab_|chat_)|(?:[-_]disabled)$|^gemini-flash-worker-agy$|^gemini-2\.5-/i;

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
  'modelTimeoutMs'
]);

const signatureCache = new Map();
const MAX_SIGNATURE_CACHE = 2000;

function cacheSignature(callId, sig) {
  if (!callId || !sig) return;
  if (signatureCache.size >= MAX_SIGNATURE_CACHE) {
    const firstKey = signatureCache.keys().next().value;
    if (firstKey !== undefined) signatureCache.delete(firstKey);
  }
  signatureCache.set(callId, sig);
}

const boundedSignatureCache = {
  get: key => signatureCache.get(key),
  set: cacheSignature
};

const catalogCache = new Map();
const CATALOG_CACHE_MS = 5 * 60 * 1000;

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

function contextLimitForModel(id) {
  if (/^claude-/i.test(id)) return 200000;
  if (/^gpt-oss-/i.test(id)) return 128000;
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
    // Redundant tiered duplicates share the same displayName as the canonical variants.
    if (/-tiered-(?:low|medium|high|xhigh)$/i.test(id) && modelsMap[id.replace(/-tiered-/i, '-')]) {
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
    const rawContext = contextLimitForModel(id);
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
      const order = { low: 0, medium: 1, high: 2, xhigh: 3 };
      items.sort((a, b) => (order[a.tier] ?? 9) - (order[b.tier] ?? 9));
      const variants = {};
      for (const item of items) variants[item.tier] = {};
      const rep = items.find(i => i.tier === 'medium') || items[0];
      addModel(base, cleanDisplayName(rep.info.displayName, base), rep.info, variants, false);
    } else {
      const only = items[0];
      addModel(only.id, only.info.displayName || only.id, only.info, {}, false);
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

function summarizeGroupWindowName(groupName, windowType) {
  const g = String(groupName || '').toLowerCase();
  const suffix = windowType === 'weekly' ? '7d' : '5h';
  if (g.includes('argon')) return `Argon ${suffix}`;
  if (g.includes('claude') || g.includes('gpt') || g.includes('3p')) return `Claude ${suffix}`;
  if (g.includes('gemini')) return `Gemini ${suffix}`;
  return `${groupName || 'Quota'} ${suffix}`;
}

// Magpie renders at most 2 bars in the provider modal and 3 rings in the tray panel,
// so place one representative bottleneck window per quota group (Gemini, Claude, Argon)
// in the first 3 slots, followed by the remaining secondary windows.
function orderSummaryWindows(groupedWindows) {
  const primary = [];
  const secondary = [];
  for (const entries of groupedWindows) {
    if (!entries.length) continue;
    const sorted = [...entries].sort((a, b) => {
      if (a.span !== b.span) {
        if (b.used !== a.used) return b.used - a.used;
        return a.span - b.span;
      }
      return 0;
    });
    primary.push(sorted[0]);
    secondary.push(...sorted.slice(1));
  }
  return [...primary, ...secondary];
}

/**
 * Magpie locks an entire provider account whenever any reported usage window reaches `used: 100`.
 * Antigravity splits quota across independent model families (Gemini, Claude, Argon), so keep an
 * exhausted pool at 99% while at least one other pool still has remaining allowance.
 */
function preventPartialExhaustionLock(windows) {
  if (!Array.isArray(windows) || windows.length === 0) return windows;
  const hasRemaining = windows.some(w => typeof w?.used === 'number' && w.used < 100);
  if (!hasRemaining) return windows;
  return windows.map(w => (typeof w?.used === 'number' && w.used >= 100 ? { ...w, used: 99 } : w));
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
      const summary = await fetchQuotaSummary(fresh.accessToken, fresh.projectId, {
        ...opts,
        proxy: opts.proxy || fresh.proxy,
        timeoutMs: opts.modelTimeoutMs
      });
      let windows = [];
      if (Array.isArray(summary?.groups)) {
        const grouped = [];
        for (const group of summary.groups) {
          const groupEntries = [];
          for (const bucket of group.buckets || []) {
            if (typeof bucket?.remainingFraction !== 'number') continue;
            const used = Math.max(0, Math.min(100, Math.round((1 - bucket.remainingFraction) * 100)));
            const w = {
              name: summarizeGroupWindowName(group.displayName, bucket.window),
              used,
              span: bucket.window === 'weekly' ? 7 * 24 * 3600 : 5 * 3600
            };
            if (bucket.resetTime) w.resetsAt = bucket.resetTime;
            groupEntries.push(w);
          }
          if (groupEntries.length) grouped.push(groupEntries);
        }
        windows = orderSummaryWindows(grouped);
      }
      if (windows.length === 0) {
        const catalog = await fetchAvailableModels(fresh.accessToken, fresh.projectId, {
          ...opts,
          proxy: opts.proxy || fresh.proxy,
          timeoutMs: opts.modelTimeoutMs
        });
        const models = catalog?.models || {};
        const rep = models['gemini-4-hydrogen-high'] || models['gemini-3.8-flash-high'] || Object.values(models)[0];
        if (typeof rep?.quotaInfo?.remainingFraction === 'number') {
          windows.push({
            name: 'Gemini 5h',
            used: Math.max(0, Math.min(100, Math.round((1 - rep.quotaInfo.remainingFraction) * 100))),
            span: 5 * 3600,
            ...(rep.quotaInfo.resetTime ? { resetsAt: rep.quotaInfo.resetTime } : {})
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
    return {
      user,
      error: firstErr?.message || '无法读取 Antigravity 额度',
      windows: [],
      signIn: firstErr?.invalidGrant ? 'expired' : 'kept'
    };
  }

  const plan = ok[0].account.tier;
  if (ok.length === 1) {
    return { user, ...(plan ? { plan } : {}), windows: preventPartialExhaustionLock(ok[0].windows), signIn: 'kept' };
  }

  // Aggregate across multiple accounts in a batch card using the tightest window.
  const byName = new Map();
  for (const r of ok) {
    for (const w of r.windows) {
      const list = byName.get(w.name) || [];
      list.push({ ...w, email: r.account.email });
      byName.set(w.name, list);
    }
  }
  const windows = [];
  for (const [name, entries] of byName.entries()) {
    const tightest = entries.reduce((a, b) => (b.used > a.used ? b : a));
    const summaryParts = entries.map(e => `${String(e.email || '').replace(/@gmail\.com$/i, '')} ${e.used}%`);
    const { email: _e, ...rest } = tightest;
    windows.push({ ...rest, name, display: `各账号已用 ${summaryParts.join('，')}` });
  }
  return { user, ...(plan ? { plan } : {}), windows: preventPartialExhaustionLock(windows), signIn: 'kept' };
}

function buildInferenceHeaders(accessToken, projectId, targetModel) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'User-Agent': currentEgressUserAgent()
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
    const traj = randomUUID().replace(/-/g, '').slice(0, 8);
    return `agent/${parts[1]}/${Date.now()}/${traj}/${parts[4]}`;
  }
  return prevId;
}

async function callV1Internal({ account, method, envelope, targetModel, opts, signal }) {
  let fresh = await ensureFreshAccountToken(account, opts);
  let forceRefreshed = false;
  let lastRes = null;
  let lastText = '';
  let lastErr = null;
  const maxRateRetries = Number.isInteger(opts.rateLimitRetries) ? opts.rateLimitRetries : 2;
  const maxRetryDelayMs = Number.isInteger(opts.maxRetryDelayMs) ? opts.maxRetryDelayMs : 6000;

  for (let rateTry = 0; rateTry <= maxRateRetries; rateTry++) {
    if (rateTry > 0 && envelope?.requestId) {
      envelope.requestId = nextRetryRequestId(envelope.requestId);
    }

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
            headers: buildInferenceHeaders(fresh.accessToken, fresh.projectId, targetModel),
            body: JSON.stringify(envelope),
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

        if (shouldFallbackEndpoint(res.status, url)) {
          break;
        }
        return { res: lastRes, text: lastText, account: fresh };
      }
    }

    if (lastRes && (lastRes.status === 429 || lastRes.status === 503) && rateTry < maxRateRetries) {
      const parsedDelay = parseRetryDelayMs(lastRes, lastText);
      const waitMs = parsedDelay !== null
        ? parsedDelay + 150
        : (opts.rateLimitBackoffMs ?? (1200 * (rateTry + 1)));
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
    let lastErrorRes = null;
    let lastErrorText = '';
    let lastError = null;
    let sawInvalidGrant = false;

    for (const acc of accounts) {
      let catalog = catalogCache.get(acc.id)?.catalog;
      if (!catalog) {
        try {
          catalog = await getAccountCatalog(acc, opts);
        } catch {
          catalog = {};
        }
      }

      if (geminiMatch) {
        const targetModel = resolveAntigravityModel(decodeURIComponent(geminiMatch[1]), null, catalog);
        const method = geminiMatch[2];
        const envelope = wrapGeminiNativeRequest(body, {
          targetModel,
          projectId: acc.projectId,
          email: acc.email,
          clientType: acc.clientType,
          sessionId: auth.metadata?.account || acc.id
        });
        try {
          const { res, text } = await callV1Internal({ account: acc, method, envelope, targetModel, opts, signal });
          if (res.ok) {
            if (method === 'streamGenerateContent') {
              return new Response(unwrapGeminiNativeSSE(res.body), {
                status: 200,
                headers: { 'content-type': 'text/event-stream; charset=utf-8' }
              });
            }
            const json = await res.json();
            return Response.json(json?.response || json);
          }
          lastErrorRes = res;
          lastErrorText = text;
          if (res.status === 429 || res.status === 503 || res.status === 403 || res.status === 401) continue;
          break;
        } catch (err) {
          if (err?.invalidGrant) sawInvalidGrant = true;
          lastError = err;
          if (req.signal.aborted) throw err;
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
        signatureCache: boundedSignatureCache,
        sessionId: body.session_id || auth.metadata?.account || acc.id
      });

      try {
        const method = stream ? 'streamGenerateContent' : 'generateContent';
        const { res, text } = await callV1Internal({ account: acc, method, envelope, targetModel, opts, signal });

        if (res.ok) {
          if (stream) {
            const sseStream = antigravitySSEToOpenAIStream(res.body, {
              model: body.model || targetModel,
              includeUsage,
              signatureCache: boundedSignatureCache
            });
            return new Response(sseStream, {
              status: 200,
              headers: {
                'content-type': 'text/event-stream; charset=utf-8',
                'cache-control': 'no-cache'
              }
            });
          }
          const rawJson = await res.json();
          return Response.json(antigravityToOpenAIResponse(rawJson, {
            model: body.model || targetModel,
            signatureCache: boundedSignatureCache
          }));
        }

        lastErrorRes = res;
        lastErrorText = text;
        if (res.status === 429 || res.status === 503 || res.status === 403 || res.status === 401) {
          continue;
        }
        break;
      } catch (err) {
        if (err?.invalidGrant) sawInvalidGrant = true;
        lastError = err;
        if (req.signal.aborted) throw err;
      }
    }

    if (lastErrorRes) {
      const errText = lastErrorText || await lastErrorRes.text().catch(() => '');
      const retryAfter = lastErrorRes.headers?.get?.('retry-after');
      const extraHeaders = retryAfter ? { 'Retry-After': retryAfter } : {};
      if (lastErrorRes.status === 429) {
        // Long per-family quota exhaustion ("Individual quota reached ... Resets in XhYm") only
        // blocks that model pool (e.g. Claude), while Gemini/Argon may still have allowance.
        // Returning HTTP 429 causes Magpie to freeze the entire account across all models.
        const isFamilyQuotaExhausted = /Individual quota reached|quota.*exhausted/i.test(errText)
          && /Resets in \d+[hm]/i.test(errText);
        if (isFamilyQuotaExhausted) {
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
    if (timeoutController.signal.aborted) {
      return makeOpenAIError(504, 'Gateway timeout: Antigravity request timed out');
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

export const AntigravityPlugin = async (_input, options = {}) => {
  const opts = antigravitySettings(options);
  const inContainer = isContainerEnv();

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
      methods: [
        {
          type: 'oauth',
          label: '通过 Refresh Token 登录（支持批量）',
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
