import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import bundledManifest from './antigravity-ua.json' with { type: 'json' };
import { fetchWithProxy } from './antigravity-oauth.mjs';
import { validateProxyURL } from './setup.mjs';

const FALLBACK_HUB_VERSION = '2.35.1';
const FALLBACK_HUB_CL = '1029194470';
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/;
const SEMVER_CORE_RE = /^\d+\.\d+\.\d+$/;
const CL_RE = /^\d{6,}$/;

export const HUB_VERSION_FILENAME = 'hub-version.json';
export const DEFAULT_UA_MANIFEST_URL = 'https://raw.githubusercontent.com/P4rfa1t/magpie-gemini-web/main/lib/antigravity-ua.json';
export const OFFICIAL_HUB_VERSION = typeof bundledManifest?.version === 'string' && VERSION_RE.test(bundledManifest.version.trim())
  ? bundledManifest.version.trim()
  : FALLBACK_HUB_VERSION;
export const OFFICIAL_HUB_CL = typeof bundledManifest?.cl === 'string' && CL_RE.test(bundledManifest.cl.trim())
  ? bundledManifest.cl.trim()
  : FALLBACK_HUB_CL;
export const NATIVE_OAUTH_USER_AGENT = typeof bundledManifest?.oauthUserAgent === 'string' && bundledManifest.oauthUserAgent.trim()
  ? bundledManifest.oauthUserAgent.trim()
  : 'vscode/1.99.0 (Antigravity/4.3.0)';

const REMOTE_MANIFEST_TTL_MS = 12 * 60 * 60 * 1000;
const REMOTE_FAILURE_TTL_MS = 30 * 60 * 1000;
const MAX_REMOTE_CACHE_ENTRIES = 32;
const remoteSyncState = new Map();
const remoteInFlight = new Map();
const DISABLED_MANIFEST_RE = /^(?:0|false|off|no|none)$/i;
const HUB_PREFIX_RE = /antigravity\/hub\/(\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?)/g;
const CL_TOKEN_RE = /\bcl=(\d{6,})/;
const VSCODE_UA_RE = /vscode\/(\d+\.\d+\.\d+)\s*\(Antigravity\/(\d+\.\d+\.\d+)\)/;
const BLAZE_MINT_RE = /changelist (\d{6,}) with baseline \d{6,} in a mint client based on \/\/depot\/branches\/[^\r\n\0]*antigravity/i;
const BLAZE_GOOGLEFILE_RE = /googlefile:\/google_src\/files\/(\d{6,})\/depot\/branches\/[^\r\n\0]*antigravity/i;
const DOWNLOAD_LINK_RE = /https:\/\/storage\.googleapis\.com\/antigravity-public\/antigravity-hub\/(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)\/([^\s"'<>\\]+)/g;
const IDE_DOWNLOAD_LINK_RE = /https:\/\/(?:edgedl\.me\.gvt1\.com|dl\.google\.com)\/edgedl\/release2\/[^/]+\/antigravity\/stable\/(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)\/([^\s"'<>\\]+)/g;

const OVERLAP_BYTES = 1024;
const READ_CHUNK_BYTES = 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_ASAR_HEADER_BYTES = 16 * 1024 * 1024;
const LOCAL_PROBE_TTL_MS = 10 * 60 * 1000;
const LOCAL_CACHE_STALE_MS = 24 * 60 * 60 * 1000;
const MAX_PROBE_CACHE_ENTRIES = 64;

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'locales',
  'icons',
  'themes',
  '__mocks__'
]);

const SKIP_ASSET_EXT_RE = /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|css|map|pak|dat|bin|dll|so(?:\.\d+)*|dylib|node|icns|txt|html|md|yml|yaml)$/i;

const localProbeCache = new Map();

function trimString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function toLatin1(chunk) {
  if (typeof chunk === 'string') return chunk;
  if (Buffer.isBuffer(chunk)) return chunk.toString('latin1');
  if (chunk instanceof Uint8Array) return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength).toString('latin1');
  return String(chunk ?? '');
}

function isValidVersion(value) {
  return typeof value === 'string' && VERSION_RE.test(value);
}

function isValidCl(value) {
  return typeof value === 'string' && CL_RE.test(value);
}

function validateCacheEntry(entry, { defaultDetectedAt = false } = {}) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const version = typeof entry.version === 'string' ? entry.version.trim() : '';
  const cl = typeof entry.cl === 'string' ? entry.cl.trim() : '';
  const source = typeof entry.source === 'string' ? entry.source.trim() : '';
  if (!isValidVersion(version) || !isValidCl(cl) || !source) return null;

  const detectedAt = entry.detectedAt === undefined && defaultDetectedAt
    ? Date.now()
    : entry.detectedAt;
  if (typeof detectedAt !== 'number' || !Number.isFinite(detectedAt)) return null;

  let oauthUserAgent;
  if (entry.oauthUserAgent !== undefined) {
    if (typeof entry.oauthUserAgent !== 'string' || !entry.oauthUserAgent.trim()) return null;
    oauthUserAgent = entry.oauthUserAgent.trim();
  }

  const out = {
    version,
    cl,
    source,
    detectedAt
  };
  if (oauthUserAgent !== undefined) out.oauthUserAgent = oauthUserAgent;
  if (typeof entry.binaryPath === 'string' && entry.binaryPath.trim()) out.binaryPath = entry.binaryPath.trim();
  if (typeof entry.archiveUrl === 'string' && entry.archiveUrl.trim()) out.archiveUrl = entry.archiveUrl.trim();
  if (typeof entry.vscodeVersion === 'string' && SEMVER_CORE_RE.test(entry.vscodeVersion.trim())) {
    out.vscodeVersion = entry.vscodeVersion.trim();
  }
  if (typeof entry.ideVersion === 'string' && SEMVER_CORE_RE.test(entry.ideVersion.trim())) {
    out.ideVersion = entry.ideVersion.trim();
  }
  return out;
}

export function formatEgressUserAgent(hubVersion, hubCl, platform = process.platform, arch = process.arch) {
  const osType = platform === 'darwin'
    ? 'darwin'
    : platform === 'win32'
      ? 'windows'
      : 'linux';
  const normArch = arch === 'x64'
    ? 'amd64'
    : arch === 'arm64'
      ? 'arm64'
      : arch;
  return `antigravity/hub/${hubVersion} (aidev_client; os_type=${osType}; arch=${normArch}; cl=${hubCl})`;
}

export function readCachedHubVersion(dataDir) {
  const dir = trimString(dataDir);
  if (!dir) return null;
  const file = path.join(dir, HUB_VERSION_FILENAME);
  if (!fs.existsSync(file)) return null;
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    return validateCacheEntry(parsed, { defaultDetectedAt: false });
  } catch {
    return null;
  }
}

export function writeCachedHubVersion(dataDir, entry) {
  const dir = trimString(dataDir);
  if (!dir) {
    throw new Error('dataDir must be a non-empty path');
  }
  const validated = validateCacheEntry(entry, { defaultDetectedAt: true });
  if (!validated) {
    throw new Error('Invalid hub-version entry: requires paired valid version, numeric cl (>=6 digits), source, and finite detectedAt');
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, HUB_VERSION_FILENAME);
  const tmp = path.join(dir, `${HUB_VERSION_FILENAME}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2, 8)}`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(validated, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  return validated;
}

function findPairedHubMatches(text) {
  const matches = [];
  HUB_PREFIX_RE.lastIndex = 0;
  let m;
  while ((m = HUB_PREFIX_RE.exec(text)) !== null) {
    const version = m[1];
    const start = m.index + m[0].length;
    const windowEnd = Math.min(text.length, start + 512);
    let end = windowEnd;
    for (let i = start; i < windowEnd; i++) {
      const ch = text[i];
      if (ch === ')' || ch === '\r' || ch === '\n' || ch === '\0') {
        end = i;
        break;
      }
    }
    const nextHub = text.indexOf('antigravity/hub/', start);
    if (nextHub !== -1 && nextHub < end) {
      end = nextHub;
    }
    const segment = text.slice(start, end);
    const clMatch = CL_TOKEN_RE.exec(segment);
    if (clMatch && isValidVersion(version) && isValidCl(clMatch[1])) {
      matches.push({ version, cl: clMatch[1] });
    }
  }
  return matches;
}

function extractVscodeUa(text) {
  const m = VSCODE_UA_RE.exec(text);
  if (!m) return null;
  const vscodeVersion = m[1];
  const ideVersion = m[2];
  return {
    vscodeVersion,
    ideVersion,
    oauthUserAgent: `vscode/${vscodeVersion} (Antigravity/${ideVersion})`
  };
}

function extractBlazeCl(text) {
  const m = BLAZE_MINT_RE.exec(text) || BLAZE_GOOGLEFILE_RE.exec(text);
  return m && isValidCl(m[1]) ? m[1] : null;
}

export function extractHubFingerprintFromTextOrBuffer(chunk) {
  const text = toLatin1(chunk);
  if (!text) return null;
  const pairs = findPairedHubMatches(text);
  if (pairs.length === 0) return null;
  const pair = pairs[0];
  const ua = extractVscodeUa(text);
  return {
    version: pair.version,
    cl: pair.cl,
    ...(ua ? ua : {})
  };
}

export function createHubFingerprintScanner({ expectedVersion, includeBlazeCl = false } = {}) {
  const expectedCore = trimString(expectedVersion).split('-')[0];
  let tail = '';
  let oauthHint = null;
  let blazeCl = null;

  return {
    get oauthHint() {
      return oauthHint;
    },
    get blazeCl() {
      return blazeCl;
    },
    resetFile() {
      tail = '';
    },
    push(chunk) {
      const text = toLatin1(chunk);
      if (!text) return null;
      const combined = tail ? tail + text : text;

      if (!oauthHint) {
        oauthHint = extractVscodeUa(combined);
      }
      if (includeBlazeCl && !blazeCl) {
        blazeCl = extractBlazeCl(combined);
      }

      const pairs = findPairedHubMatches(combined);
      if (pairs.length > 0) {
        const preferred = expectedCore
          ? pairs.find(p => p.version === expectedVersion || p.version.split('-')[0] === expectedCore) || pairs[0]
          : pairs[0];
        const ua = oauthHint || extractVscodeUa(combined);
        return {
          version: preferred.version,
          cl: preferred.cl,
          ...(ua ? ua : {})
        };
      }

      tail = combined.length > OVERLAP_BYTES ? combined.slice(-OVERLAP_BYTES) : combined;
      return null;
    }
  };
}

function extractAppMetadataFromJsonObjects(productObj, packageObj) {
  let version = null;
  let oauthUa = null;

  for (const obj of [productObj, packageObj]) {
    if (!obj || typeof obj !== 'object') continue;
    if (typeof obj.userAgent === 'string') {
      const ua = extractVscodeUa(obj.userAgent);
      if (ua) oauthUa = ua;
    }
  }

  const isAntigravityPkg = packageObj && typeof packageObj === 'object' && (
    String(packageObj.name || '').toLowerCase() === 'antigravity' ||
    /antigravity/i.test(String(packageObj.productName || ''))
  );
  const isAntigravityProduct = productObj && typeof productObj === 'object' && (
    /antigravity/i.test(String(productObj.nameShort || productObj.nameLong || productObj.applicationName || productObj.dataFolderName || '')) ||
    typeof productObj.ideVersion === 'string' ||
    typeof productObj.antigravityVersion === 'string'
  );

  // Hub version lives in package.json (name: 'antigravity') or explicit hubVersion;
  // product.json ideVersion / antigravityVersion / version is the IDE version (e.g. 4.x),
  // which must never be paired as a Hub version with Blaze CL.
  if (isAntigravityPkg) {
    const rawVer = trimString(packageObj.version);
    if (isValidVersion(rawVer)) version = rawVer;
  }
  if (!version && isAntigravityProduct) {
    const rawVer = trimString(productObj.hubVersion);
    if (isValidVersion(rawVer)) version = rawVer;
  }

  if (!oauthUa) {
    const vscodeVer = trimString(
      productObj?.vscodeVersion ||
      packageObj?.vscodeVersion ||
      (isAntigravityProduct ? packageObj?.version : '')
    );
    const ideVer = trimString(
      productObj?.ideVersion ||
      productObj?.antigravityVersion ||
      (isAntigravityProduct ? productObj?.version : '')
    );
    if (SEMVER_CORE_RE.test(vscodeVer) && SEMVER_CORE_RE.test(ideVer)) {
      oauthUa = {
        vscodeVersion: vscodeVer,
        ideVersion: ideVer,
        oauthUserAgent: `vscode/${vscodeVer} (Antigravity/${ideVer})`
      };
    }
  }

  return { version, oauthUa };
}

function parseAsarHeader(buf) {
  if (!buf || buf.length < 16) return null;
  if (buf.readUInt32LE(0) !== 4) return null;
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  if (jsonLen < 2 || jsonLen > MAX_ASAR_HEADER_BYTES || headerSize < jsonLen) return null;
  const dataStart = 8 + headerSize;
  if (buf.length < 16 + jsonLen) return null;
  try {
    const header = JSON.parse(buf.subarray(16, 16 + jsonLen).toString('utf8'));
    return { header, dataStart };
  } catch {
    return null;
  }
}

function findAsarFileEntry(header, targetName) {
  const rootFiles = header?.files;
  if (!rootFiles || typeof rootFiles !== 'object') return null;
  if (rootFiles[targetName]?.offset !== undefined && Number.isInteger(rootFiles[targetName]?.size)) {
    return rootFiles[targetName];
  }
  const nested = rootFiles.resources?.files?.app?.files?.[targetName];
  if (nested?.offset !== undefined && Number.isInteger(nested?.size)) {
    return nested;
  }
  return null;
}

function readMetadataFromAsarFile(asarPath) {
  let fd;
  try {
    fd = fs.openSync(asarPath, 'r');
    const stat = fs.fstatSync(fd);
    if (stat.size < 16) return null;

    const pre = Buffer.allocUnsafe(16);
    if (fs.readSync(fd, pre, 0, 16, 0) < 16) return null;
    if (pre.readUInt32LE(0) !== 4) return null;
    const headerSize = pre.readUInt32LE(4);
    const jsonLen = pre.readUInt32LE(12);
    if (jsonLen < 2 || jsonLen > MAX_ASAR_HEADER_BYTES || headerSize < jsonLen) return null;
    const dataStart = 8 + headerSize;
    if (dataStart > stat.size) return null;

    const jsonBuf = Buffer.allocUnsafe(jsonLen);
    if (fs.readSync(fd, jsonBuf, 0, jsonLen, 16) < jsonLen) return null;
    const header = JSON.parse(jsonBuf.toString('utf8'));

    const readJsonEntry = name => {
      const entry = findAsarFileEntry(header, name);
      if (!entry || entry.size <= 0 || entry.size > 2 * 1024 * 1024) return null;
      const offset = Number(entry.offset);
      if (!Number.isFinite(offset) || dataStart + offset + entry.size > stat.size) return null;
      const buf = Buffer.allocUnsafe(entry.size);
      const read = fs.readSync(fd, buf, 0, entry.size, dataStart + offset);
      if (read < entry.size) return null;
      try {
        return JSON.parse(buf.toString('utf8'));
      } catch {
        return null;
      }
    };

    const productObj = readJsonEntry('product.json');
    const packageObj = readJsonEntry('package.json');
    return extractAppMetadataFromJsonObjects(productObj, packageObj);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function readMetadataFromAsarBuffer(buf) {
  const parsed = parseAsarHeader(buf);
  if (!parsed) return null;
  const { header, dataStart } = parsed;
  const readJsonEntry = name => {
    const entry = findAsarFileEntry(header, name);
    if (!entry || entry.size <= 0 || entry.size > 2 * 1024 * 1024) return null;
    const offset = Number(entry.offset);
    if (!Number.isFinite(offset) || dataStart + offset + entry.size > buf.length) return null;
    try {
      return JSON.parse(buf.subarray(dataStart + offset, dataStart + offset + entry.size).toString('utf8'));
    } catch {
      return null;
    }
  };
  const productObj = readJsonEntry('product.json');
  const packageObj = readJsonEntry('package.json');
  return extractAppMetadataFromJsonObjects(productObj, packageObj);
}

function safeReadJsonFile(filePath, maxBytes = 1024 * 1024) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size <= 0 || stat.size > maxBytes) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function candidateInstallRoots({ env = process.env, platform = process.platform, installDir } = {}) {
  const explicit = trimString(installDir) || trimString(env?.ANTIGRAVITY_INSTALL_DIR);
  const explicitIde = trimString(env?.ANTIGRAVITY_IDE_INSTALL_DIR);
  if (explicit) {
    return explicitIde ? [path.resolve(explicit), path.resolve(explicitIde)] : [path.resolve(explicit)];
  }

  const home = trimString(env?.HOME) || trimString(env?.USERPROFILE) || os.homedir();
  const candidates = [];
  if (explicitIde) {
    candidates.push(path.resolve(explicitIde));
  }

  if (platform === 'win32') {
    const localAppData = trimString(env?.LOCALAPPDATA) || path.join(home, 'AppData', 'Local');
    const programFiles = trimString(env?.ProgramFiles) || 'C:\\Program Files';
    const programFilesX86 = trimString(env?.['ProgramFiles(x86)']);
    candidates.push(
      path.join(localAppData, 'Programs', 'Antigravity'),
      path.join(localAppData, 'Programs', 'antigravity'),
      path.join(localAppData, 'Programs', 'Antigravity IDE'),
      path.join(localAppData, 'Programs', 'antigravity-ide'),
      path.join(programFiles, 'Antigravity'),
      path.join(programFiles, 'antigravity'),
      path.join(programFiles, 'Antigravity IDE')
    );
    if (programFilesX86) {
      candidates.push(
        path.join(programFilesX86, 'Antigravity'),
        path.join(programFilesX86, 'Antigravity IDE')
      );
    }
    candidates.push(
      path.join(home, '.antigravity'),
      path.join(home, '.local', 'share', 'antigravity')
    );
  } else if (platform === 'darwin') {
    candidates.push(
      '/Applications/Antigravity.app/Contents/Resources/app',
      '/Applications/Antigravity.app',
      '/Applications/Antigravity IDE.app/Contents/Resources/app',
      '/Applications/Antigravity IDE.app',
      path.join(home, 'Applications', 'Antigravity.app', 'Contents', 'Resources', 'app'),
      path.join(home, 'Applications', 'Antigravity.app'),
      path.join(home, 'Applications', 'Antigravity IDE.app', 'Contents', 'Resources', 'app'),
      path.join(home, 'Applications', 'Antigravity IDE.app'),
      path.join(home, '.antigravity'),
      path.join(home, '.local', 'share', 'antigravity'),
      '/opt/homebrew/Caskroom/antigravity'
    );
  } else {
    candidates.push(
      '/usr/share/antigravity/resources/app',
      '/usr/share/antigravity',
      '/usr/share/antigravity-ide/resources/app',
      '/usr/share/antigravity-ide',
      '/opt/antigravity/resources/app',
      '/opt/antigravity',
      '/opt/antigravity-ide/resources/app',
      '/opt/antigravity-ide',
      '/usr/lib/antigravity',
      path.join(home, '.local', 'share', 'antigravity'),
      path.join(home, '.local', 'bin'),
      path.join(home, '.antigravity')
    );
  }

  const seen = new Set();
  const out = [];
  for (const c of candidates) {
    const resolved = path.resolve(c);
    const key = platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(resolved);
    }
  }
  return out;
}

function collectCandidateFiles(rootPath) {
  const metadataFiles = [];
  const asarFiles = [];
  const binaryFiles = [];

  let rootStat;
  try {
    rootStat = fs.statSync(rootPath);
  } catch {
    return { metadataFiles, asarFiles, binaryFiles };
  }

  if (rootStat.isFile()) {
    binaryFiles.push(rootPath);
    return { metadataFiles, asarFiles, binaryFiles };
  }
  if (!rootStat.isDirectory()) {
    return { metadataFiles, asarFiles, binaryFiles };
  }

  const queue = [{ dir: rootPath, depth: 0 }];
  while (queue.length > 0) {
    const { dir, depth } = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const lower = entry.name.toLowerCase();

      if (entry.isDirectory()) {
        if (depth < 5 && !SKIP_DIRS.has(lower)) {
          queue.push({ dir: full, depth: depth + 1 });
        }
        continue;
      }
      if (!entry.isFile()) continue;

      if (lower === 'product.json' || lower === 'package.json') {
        metadataFiles.push(full);
      } else if (lower === 'app.asar') {
        asarFiles.push(full);
      } else if (/^language_server/i.test(lower) || /^antigravity(?:\.exe)?$/i.test(lower)) {
        binaryFiles.push(full);
      } else if (
        (dir.toLowerCase().endsWith(`${path.sep}bin`) || /extensions[\\/]+antigravity/i.test(dir)) &&
        !SKIP_ASSET_EXT_RE.test(lower)
      ) {
        binaryFiles.push(full);
      }
    }
  }

  const priority = filePath => {
    const base = path.basename(filePath).toLowerCase();
    if (base.startsWith('language_server')) return 0;
    if (base === 'antigravity' || base === 'antigravity.exe') return 1;
    return 2;
  };
  binaryFiles.sort((a, b) => priority(a) - priority(b) || a.localeCompare(b));

  return { metadataFiles, asarFiles, binaryFiles };
}

function scanFileBoundedSync(filePath, scanner, maxFileBytes) {
  const limit = Number.isFinite(maxFileBytes) && maxFileBytes >= 0 ? maxFileBytes : DEFAULT_MAX_FILE_BYTES;
  if (limit === 0) return null;

  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(fd);
    const totalToRead = Math.min(stat.size, limit);
    const buf = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, Math.max(1, totalToRead)));
    let pos = 0;

    scanner.resetFile();
    while (pos < totalToRead) {
      const toRead = Math.min(buf.length, totalToRead - pos);
      const bytesRead = fs.readSync(fd, buf, 0, toRead, pos);
      if (bytesRead <= 0) break;
      const match = scanner.push(buf.subarray(0, bytesRead));
      if (match) return match;
      pos += bytesRead;
    }
    return null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function extractRootMetadata(root) {
  const { metadataFiles, asarFiles, binaryFiles } = collectCandidateFiles(root);
  let hintVersion = null;
  let hintOAuth = null;

  const productByDir = new Map();
  const packageByDir = new Map();
  for (const metaPath of metadataFiles) {
    const dir = path.dirname(metaPath);
    const name = path.basename(metaPath).toLowerCase();
    const json = safeReadJsonFile(metaPath);
    if (!json) continue;
    if (name === 'product.json') productByDir.set(dir, json);
    else if (name === 'package.json') packageByDir.set(dir, json);
  }

  const dirs = new Set([...productByDir.keys(), ...packageByDir.keys()]);
  for (const dir of dirs) {
    const meta = extractAppMetadataFromJsonObjects(productByDir.get(dir), packageByDir.get(dir));
    if (!hintVersion && meta.version) hintVersion = meta.version;
    if (!hintOAuth && meta.oauthUa) hintOAuth = meta.oauthUa;
  }

  if (!hintVersion || !hintOAuth) {
    for (const asarPath of asarFiles) {
      const meta = readMetadataFromAsarFile(asarPath);
      if (meta) {
        if (!hintVersion && meta.version) hintVersion = meta.version;
        if (!hintOAuth && meta.oauthUa) hintOAuth = meta.oauthUa;
      }
    }
  }

  return { metadataFiles, asarFiles, binaryFiles, hintVersion, hintOAuth };
}

function findOAuthUserAgentAcrossRoots(roots, startIdx = 0, maxFileBytes) {
  for (let i = startIdx; i < roots.length; i++) {
    const root = roots[i];
    if (!fs.existsSync(root)) continue;
    const { hintOAuth, binaryFiles } = extractRootMetadata(root);
    if (hintOAuth?.oauthUserAgent) return hintOAuth.oauthUserAgent;
    const scanner = createHubFingerprintScanner({ includeBlazeCl: false });
    for (const binPath of binaryFiles) {
      scanFileBoundedSync(binPath, scanner, maxFileBytes);
      if (scanner.oauthHint?.oauthUserAgent) {
        return scanner.oauthHint.oauthUserAgent;
      }
    }
  }
  return undefined;
}

export function detectLocalAntigravityFingerprint(options = {}) {
  const {
    dataDir,
    env = process.env,
    platform = process.platform,
    installDir,
    persist = true,
    maxFileBytes
  } = options;

  const roots = candidateInstallRoots({ env, platform, installDir });
  for (let rootIdx = 0; rootIdx < roots.length; rootIdx++) {
    const root = roots[rootIdx];
    if (!fs.existsSync(root)) continue;
    const { binaryFiles, hintVersion, hintOAuth } = extractRootMetadata(root);

    const scanner = createHubFingerprintScanner({ includeBlazeCl: true });
    let blazeBinaryPath = null;

    for (const binPath of binaryFiles) {
      const match = scanFileBoundedSync(binPath, scanner, maxFileBytes);
      let oauthUa = match?.oauthUserAgent || hintOAuth?.oauthUserAgent || scanner.oauthHint?.oauthUserAgent;
      if (match) {
        if (!oauthUa) {
          oauthUa = findOAuthUserAgentAcrossRoots(roots, rootIdx + 1, maxFileBytes);
        }
        const detectedAt = Date.now();
        const result = {
          version: match.version,
          cl: match.cl,
          ...(oauthUa ? { oauthUserAgent: oauthUa } : {}),
          source: 'local',
          detectedAt,
          binaryPath: binPath
        };
        if (persist !== false && trimString(dataDir)) {
          writeCachedHubVersion(dataDir, result);
        }
        return result;
      }
      if (scanner.blazeCl && !blazeBinaryPath) {
        blazeBinaryPath = binPath;
      }
    }

    // Real Antigravity Desktop binary embeds Blaze CL in language_server* and
    // app version in resources/app.asar (or product.json/package.json). Pair them
    // ONLY when both came from this same installation root.
    if (hintVersion && scanner.blazeCl && blazeBinaryPath) {
      const detectedAt = Date.now();
      let oauthUa = hintOAuth?.oauthUserAgent || scanner.oauthHint?.oauthUserAgent;
      if (!oauthUa) {
        oauthUa = findOAuthUserAgentAcrossRoots(roots, rootIdx + 1, maxFileBytes);
      }
      const result = {
        version: hintVersion,
        cl: scanner.blazeCl,
        ...(oauthUa ? { oauthUserAgent: oauthUa } : {}),
        source: 'local',
        detectedAt,
        binaryPath: blazeBinaryPath
      };
      if (persist !== false && trimString(dataDir)) {
        writeCachedHubVersion(dataDir, result);
      }
      return result;
    }
  }

  return null;
}

function setLocalProbeCache(key, value) {
  if (localProbeCache.has(key)) {
    localProbeCache.delete(key);
  } else if (localProbeCache.size >= MAX_PROBE_CACHE_ENTRIES) {
    const oldest = localProbeCache.keys().next().value;
    if (oldest !== undefined) localProbeCache.delete(oldest);
  }
  localProbeCache.set(key, value);
}

function parseVersionTuple(ver) {
  const s = trimString(ver);
  if (!isValidVersion(s)) return null;
  const dash = s.indexOf('-');
  const core = (dash === -1 ? s : s.slice(0, dash)).split('.').map(n => Number(n));
  const pre = dash === -1 ? '' : s.slice(dash + 1);
  return { core, pre };
}

export function compareHubVersions(a, b) {
  const pa = parseVersionTuple(a);
  const pb = parseVersionTuple(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa.core[i] !== pb.core[i]) return pa.core[i] > pb.core[i] ? 1 : -1;
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre > pb.pre ? 1 : -1;
}

export function resolveUaManifestUrl({ manifestUrl, env = process.env, strict = false } = {}) {
  const hasExplicit = manifestUrl !== undefined && manifestUrl !== null;
  const raw = trimString(hasExplicit ? String(manifestUrl) : env?.ANTIGRAVITY_UA_MANIFEST_URL);
  if (DISABLED_MANIFEST_RE.test(raw)) return null;
  if (!raw) return DEFAULT_UA_MANIFEST_URL;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      if (strict) throw new Error('Invalid UA manifest URL: only http:// and https:// are supported');
      return null;
    }
    return parsed.toString();
  } catch {
    if (strict) throw new Error(`Invalid UA manifest URL: ${raw}`);
    return null;
  }
}

export function resolveAntigravityUserAgents(options = {}) {
  const {
    dataDir,
    env = process.env,
    baselineVersion = OFFICIAL_HUB_VERSION,
    baselineCl = OFFICIAL_HUB_CL,
    baselineOAuthUa = NATIVE_OAUTH_USER_AGENT,
    detectLocal = true,
    platform = process.platform,
    arch = process.arch
  } = options;

  const envOAuthUa = trimString(env?.ANTIGRAVITY_OAUTH_USER_AGENT);
  const resolveOAuth = detectedUa => envOAuthUa || detectedUa || baselineOAuthUa || NATIVE_OAUTH_USER_AGENT;

  // Priority 1: Explicit env override — require BOTH valid version AND valid cl
  // so partial env overrides never create a mismatched Frankenstein UA.
  const envVer = trimString(env?.ANTIGRAVITY_HUB_VERSION);
  const envCl = trimString(env?.ANTIGRAVITY_HUB_CL);
  if (isValidVersion(envVer) && isValidCl(envCl)) {
    return {
      hubVersion: envVer,
      hubCl: envCl,
      oauthUserAgent: resolveOAuth(undefined),
      egressUserAgent: formatEgressUserAgent(envVer, envCl, platform, arch),
      source: 'env'
    };
  }

  // Priority 2: Cached ${dataDir}/hub-version.json + throttled local probe.
  // Never serve an older disk cache once the packaged manifest/baseline advances.
  const normDir = trimString(dataDir) ? path.resolve(trimString(dataDir)) : '';
  const rawCached = normDir ? readCachedHubVersion(normDir) : null;
  const cached = rawCached && (!isValidVersion(baselineVersion) || compareHubVersions(rawCached.version, baselineVersion) >= 0)
    ? rawCached
    : null;
  const now = Date.now();

  if (cached && (!detectLocal || now - cached.detectedAt < LOCAL_CACHE_STALE_MS)) {
    return {
      hubVersion: cached.version,
      hubCl: cached.cl,
      oauthUserAgent: resolveOAuth(cached.oauthUserAgent),
      egressUserAgent: formatEgressUserAgent(cached.version, cached.cl, platform, arch),
      source: cached.source
    };
  }

  if (detectLocal) {
    const probeKey = [
      normDir,
      trimString(env?.ANTIGRAVITY_INSTALL_DIR),
      trimString(env?.LOCALAPPDATA),
      trimString(env?.ProgramFiles),
      trimString(env?.HOME || env?.USERPROFILE),
      platform
    ].join('|');

    const throttled = localProbeCache.get(probeKey);
    let localResult;
    if (throttled && now - throttled.at < LOCAL_PROBE_TTL_MS) {
      localResult = throttled.result;
    } else {
      try {
        localResult = detectLocalAntigravityFingerprint({
          dataDir: normDir || undefined,
          env,
          platform,
          persist: false
        });
      } catch {
        localResult = null;
      }
      setLocalProbeCache(probeKey, { at: now, result: localResult });
      const localBetter = localResult &&
        (!isValidVersion(baselineVersion) || compareHubVersions(localResult.version, baselineVersion) >= 0) &&
        (!cached ||
          compareHubVersions(localResult.version, cached.version) > 0 ||
          (cached.source === 'local' && compareHubVersions(localResult.version, cached.version) === 0));
      if (localBetter && normDir) {
        try { writeCachedHubVersion(normDir, localResult); } catch {}
      }
    }

    const useLocal = localResult &&
      (!isValidVersion(baselineVersion) || compareHubVersions(localResult.version, baselineVersion) >= 0) &&
      (!cached ||
        compareHubVersions(localResult.version, cached.version) > 0 ||
        (cached.source === 'local' && compareHubVersions(localResult.version, cached.version) === 0));

    if (useLocal) {
      return {
        hubVersion: localResult.version,
        hubCl: localResult.cl,
        oauthUserAgent: resolveOAuth(localResult.oauthUserAgent),
        egressUserAgent: formatEgressUserAgent(localResult.version, localResult.cl, platform, arch),
        source: localResult.source
      };
    }
  }

  if (cached) {
    return {
      hubVersion: cached.version,
      hubCl: cached.cl,
      oauthUserAgent: resolveOAuth(cached.oauthUserAgent),
      egressUserAgent: formatEgressUserAgent(cached.version, cached.cl, platform, arch),
      source: cached.source
    };
  }

  // Priority 3: Paired built-in baseline.
  return {
    hubVersion: baselineVersion,
    hubCl: baselineCl,
    oauthUserAgent: resolveOAuth(undefined),
    egressUserAgent: formatEgressUserAgent(baselineVersion, baselineCl, platform, arch),
    source: 'baseline'
  };
}

function setRemoteSyncState(key, state) {
  if (remoteSyncState.has(key)) remoteSyncState.delete(key);
  else if (remoteSyncState.size >= MAX_REMOTE_CACHE_ENTRIES) {
    const oldest = remoteSyncState.keys().next().value;
    if (oldest !== undefined) remoteSyncState.delete(oldest);
  }
  remoteSyncState.set(key, state);
}

export async function refreshRemoteHubVersion(options = {}) {
  const {
    dataDir,
    env = process.env,
    proxy,
    fetchFn = fetchWithProxy,
    manifestUrl,
    force = false,
    persist = true,
    timeoutMs = 10000
  } = options;

  const targetUrl = resolveUaManifestUrl({ manifestUrl, env });
  if (!targetUrl) return null;

  const resolvedProxy = trimString(proxy ?? env?.ANTIGRAVITY_PROXY);
  if (resolvedProxy) validateProxyURL(resolvedProxy);

  const normDir = trimString(dataDir) ? path.resolve(trimString(dataDir)) : '';
  const now = Date.now();
  const cached = normDir ? readCachedHubVersion(normDir) : null;

  if (!force && cached?.source === 'remote-manifest' && now - cached.detectedAt < REMOTE_MANIFEST_TTL_MS) {
    return cached;
  }

  const stateKey = `${normDir}|${targetUrl}|${resolvedProxy}`;
  if (!force) {
    const prev = remoteSyncState.get(stateKey);
    if (prev) {
      const ttl = prev.ok ? REMOTE_MANIFEST_TTL_MS : REMOTE_FAILURE_TTL_MS;
      if (now - prev.at < ttl) return prev.result || null;
    }
  }

  if (!force && remoteInFlight.has(stateKey)) {
    return remoteInFlight.get(stateKey);
  }

  const work = (async () => {
    try {
      const customFetch = fetchFn === fetchWithProxy ? undefined : fetchFn;
      const res = await fetchWithProxy(targetUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' }
      }, {
        ...(resolvedProxy ? { proxy: resolvedProxy } : {}),
        ...(customFetch ? { fetchFn: customFetch } : {}),
        timeoutMs
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const raw = await res.json();
      const validated = validateCacheEntry({
        version: raw?.version,
        cl: raw?.cl,
        ...(raw?.oauthUserAgent !== undefined ? { oauthUserAgent: raw.oauthUserAgent } : {}),
        source: 'remote-manifest',
        detectedAt: Date.now()
      }, { defaultDetectedAt: true });
      if (!validated) {
        throw new Error('Invalid remote UA manifest payload (requires paired valid version and cl)');
      }
      validated.manifestUrl = targetUrl;

      const currentBest = cached && compareHubVersions(cached.version, OFFICIAL_HUB_VERSION) >= 0
        ? cached
        : { version: OFFICIAL_HUB_VERSION, cl: OFFICIAL_HUB_CL, source: 'baseline' };

      const cmpCurrent = compareHubVersions(validated.version, currentBest.version);
      if (!force && cmpCurrent < 0) {
        setRemoteSyncState(stateKey, { ok: true, at: Date.now(), result: currentBest });
        return currentBest;
      }

      const shouldPersist = persist !== false && normDir && (
        force ||
        !cached ||
        cmpCurrent > 0 ||
        (cached.source === 'remote-manifest' && (validated.cl !== cached.cl || validated.oauthUserAgent !== cached.oauthUserAgent))
      );

      const finalEntry = shouldPersist
        ? writeCachedHubVersion(normDir, validated)
        : (cmpCurrent === 0 && cached && !force ? cached : validated);

      setRemoteSyncState(stateKey, { ok: true, at: Date.now(), result: finalEntry });
      return finalEntry;
    } catch (err) {
      setRemoteSyncState(stateKey, { ok: false, at: Date.now(), result: null });
      if (force) throw err;
      return null;
    } finally {
      remoteInFlight.delete(stateKey);
    }
  })();

  if (!force) {
    remoteInFlight.set(stateKey, work);
  }
  return work;
}

export function parseOfficialDownloadPage(html) {
  if (typeof html !== 'string' || !html) return null;
  const normalized = html
    .replace(/\\u002[fF]/g, '/')
    .replace(/\\\//g, '/')
    .replace(/&amp;/g, '&');

  const seen = new Set();
  const entries = [];
  DOWNLOAD_LINK_RE.lastIndex = 0;
  let m;
  while ((m = DOWNLOAD_LINK_RE.exec(normalized)) !== null) {
    const rawUrl = m[0].replace(/[),.;'"`\\]+$/, '');
    if (seen.has(rawUrl)) continue;
    seen.add(rawUrl);

    const releaseTag = m[1];
    const dashIdx = releaseTag.indexOf('-');
    const version = dashIdx === -1 ? releaseTag : releaseTag.slice(0, dashIdx);
    const build = dashIdx === -1 ? '' : releaseTag.slice(dashIdx + 1);
    const targetPath = m[2].replace(/[),.;'"`\\]+$/, '');
    entries.push({ url: rawUrl, releaseTag, version, build, targetPath });
  }

  const ideSeen = new Set();
  const ideEntries = [];
  IDE_DOWNLOAD_LINK_RE.lastIndex = 0;
  while ((m = IDE_DOWNLOAD_LINK_RE.exec(normalized)) !== null) {
    const rawUrl = m[0].replace(/[),.;'"`\\]+$/, '');
    if (ideSeen.has(rawUrl)) continue;
    ideSeen.add(rawUrl);

    const releaseTag = m[1];
    const dashIdx = releaseTag.indexOf('-');
    const version = dashIdx === -1 ? releaseTag : releaseTag.slice(0, dashIdx);
    const build = dashIdx === -1 ? '' : releaseTag.slice(dashIdx + 1);
    const targetPath = m[2].replace(/[),.;'"`\\]+$/, '');
    ideEntries.push({ url: rawUrl, releaseTag, version, build, targetPath });
  }

  if (entries.length === 0) return null;

  const preferred =
    entries.find(e => /(?:^|\/)linux-x64\/Antigravity\.tar\.gz$/i.test(e.targetPath)) ||
    entries.find(e => /(?:^|\/)linux-x64\/[^/]+\.tar\.gz$/i.test(e.targetPath)) ||
    entries.find(e => /(?:^|\/)linux-[^/]+\/[^/]+\.tar\.gz$/i.test(e.targetPath)) ||
    entries.find(e => /\.tar\.gz$/i.test(e.targetPath)) ||
    null;

  const idePreferred =
    ideEntries.find(e => /(?:^|\/)linux-x64\/Antigravity(?:%20|\s|\.)*IDE\.tar\.gz$/i.test(e.targetPath)) ||
    ideEntries.find(e => /(?:^|\/)linux-x64\/[^/]+\.tar\.gz$/i.test(e.targetPath)) ||
    ideEntries.find(e => /\.tar\.gz$/i.test(e.targetPath)) ||
    null;

  const meta = preferred || entries[0];
  return {
    preferredUrl: preferred ? preferred.url : null,
    archiveUrl: preferred ? preferred.url : null,
    version: meta.version,
    build: meta.build,
    releaseTag: meta.releaseTag,
    urls: entries.map(e => e.url),
    ...(idePreferred ? {
      idePreferredUrl: idePreferred.url,
      ideVersion: idePreferred.version,
      ideReleaseTag: idePreferred.releaseTag
    } : {}),
    ...(ideEntries.length > 0 ? { ideUrls: ideEntries.map(e => e.url) } : {})
  };
}

function parseTarOctalOrBase256(buf, start, end) {
  if ((buf[start] & 0x80) !== 0) {
    let val = 0n;
    for (let i = start + 1; i < end; i++) {
      val = (val << 8n) | BigInt(buf[i]);
    }
    return Number(val);
  }
  const str = buf.subarray(start, end).toString('ascii').replace(/\0.*$/, '').trim();
  if (!str) return 0;
  const parsed = Number.parseInt(str, 8);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function parsePaxRecords(text) {
  const records = {};
  let idx = 0;
  while (idx < text.length) {
    const sp = text.indexOf(' ', idx);
    if (sp === -1) break;
    const len = Number.parseInt(text.slice(idx, sp), 10);
    if (!Number.isFinite(len) || len <= 0 || idx + len > text.length) break;
    const line = text.slice(sp + 1, idx + len).replace(/\n$/, '');
    const eq = line.indexOf('=');
    if (eq !== -1) {
      records[line.slice(0, eq)] = line.slice(eq + 1);
    }
    idx += len;
  }
  return records;
}

function isZeroTarBlock(block) {
  for (let i = 0; i < block.length; i++) {
    if (block[i] !== 0) return false;
  }
  return true;
}

function classifyTarCandidate(entryPath) {
  const posix = String(entryPath || '').replace(/^\.\//, '');
  const lower = posix.toLowerCase();
  const base = path.posix.basename(lower);
  if (!posix || lower.includes('node_modules/')) {
    return 'skip';
  }
  if ((base === 'product.json' || base === 'package.json') && !lower.includes('/locales/')) {
    return 'json';
  }
  if (base === 'app.asar') {
    return 'asar';
  }
  if (
    base.startsWith('language_server') ||
    base === 'antigravity' ||
    base === 'antigravity.exe' ||
    (!SKIP_ASSET_EXT_RE.test(base) && !lower.startsWith('locales/'))
  ) {
    return 'scan';
  }
  return 'skip';
}

function createStreamingTarScanner({ expectedVersion, oauthOnly = false, onMatch }) {
  let buffer = Buffer.alloc(0);
  let state = 'header'; // 'header' | 'payload' | 'pad' | 'eof'
  let remainingPayload = 0;
  let remainingPad = 0;
  let currentMode = 'skip'; // 'skip' | 'json' | 'asar' | 'scan'
  let currentName = '';
  let currentType = '0';
  let collectChunks = [];
  let collectBytes = 0;
  let gnuLongName = null;
  let paxOverrides = null;

  let hintVersion = null;
  let hintOAuth = null;
  let blazeCl = null;
  let finished = false;
  const productByDir = new Map();
  const packageByDir = new Map();
  const scanner = createHubFingerprintScanner({ expectedVersion, includeBlazeCl: !oauthOnly });

  const expectedCore = trimString(expectedVersion).split('-')[0];
  const tryEmitMatch = () => {
    if (finished) return;
    const oauthUa = hintOAuth?.oauthUserAgent || scanner.oauthHint?.oauthUserAgent;
    if (oauthOnly) {
      if (oauthUa) {
        finished = true;
        onMatch({ oauthUserAgent: oauthUa });
      }
      return;
    }
    if (!blazeCl) return;
    const coherentHint = hintVersion && (!expectedCore || hintVersion.split('-')[0] === expectedCore)
      ? hintVersion
      : null;
    const hubVer = coherentHint || (isValidVersion(expectedVersion) ? expectedVersion : null);
    if (!hubVer) return;
    finished = true;
    onMatch({
      version: hubVer,
      cl: blazeCl,
      ...(oauthUa ? { oauthUserAgent: oauthUa } : {})
    });
  };

  const finishEntryPayload = () => {
    if (currentType === 'L') {
      gnuLongName = Buffer.concat(collectChunks).toString('utf8').replace(/\0+$/, '');
    } else if (currentType === 'x') {
      paxOverrides = parsePaxRecords(Buffer.concat(collectChunks).toString('utf8'));
    } else if (currentMode === 'json' && collectBytes > 0) {
      try {
        const obj = JSON.parse(Buffer.concat(collectChunks).toString('utf8'));
        const dir = path.posix.dirname(currentName);
        const base = path.posix.basename(currentName).toLowerCase();
        if (base === 'product.json') productByDir.set(dir, obj);
        else if (base === 'package.json') packageByDir.set(dir, obj);
        const meta = extractAppMetadataFromJsonObjects(productByDir.get(dir), packageByDir.get(dir));
        if (!hintVersion && meta.version) hintVersion = meta.version;
        if (!hintOAuth && meta.oauthUa) hintOAuth = meta.oauthUa;
        tryEmitMatch();
      } catch {}
    } else if (currentMode === 'asar' && collectBytes > 0) {
      const meta = readMetadataFromAsarBuffer(Buffer.concat(collectChunks));
      if (meta) {
        if (!hintVersion && meta.version) hintVersion = meta.version;
        if (!hintOAuth && meta.oauthUa) hintOAuth = meta.oauthUa;
        tryEmitMatch();
      }
    }
    collectChunks = [];
    collectBytes = 0;
  };

  const push = chunk => {
    if (finished || state === 'eof' || !chunk || chunk.length === 0) return;
    buffer = buffer.length > 0 ? Buffer.concat([buffer, chunk]) : Buffer.from(chunk);

    while (!finished && state !== 'eof') {
      if (state === 'header') {
        if (buffer.length < 512) break;
        const header = buffer.subarray(0, 512);
        buffer = buffer.subarray(512);

        if (isZeroTarBlock(header)) {
          state = 'eof';
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
        collectChunks = [];
        collectBytes = 0;

        if (typeflag === 'L' || typeflag === 'x') {
          currentMode = 'collect-meta';
        } else if (typeflag === '0' || typeflag === '\0') {
          currentMode = classifyTarCandidate(fullName);
          if (currentMode === 'scan') scanner.resetFile();
        } else {
          currentMode = 'skip';
        }

        if (remainingPayload > 0) {
          state = 'payload';
        } else {
          finishEntryPayload();
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

        if (currentMode === 'collect-meta' || (currentMode === 'json' && collectBytes < 1024 * 1024)) {
          collectChunks.push(Buffer.from(slice));
          collectBytes += slice.length;
        } else if (currentMode === 'asar' && collectBytes < MAX_ASAR_HEADER_BYTES) {
          collectChunks.push(Buffer.from(slice));
          collectBytes += slice.length;
        } else if (currentMode === 'scan') {
          const match = scanner.push(slice);
          if (oauthOnly) {
            if (scanner.oauthHint?.oauthUserAgent) {
              tryEmitMatch();
              break;
            }
          } else if (match) {
            const oauthUa = match.oauthUserAgent || hintOAuth?.oauthUserAgent || scanner.oauthHint?.oauthUserAgent;
            finished = true;
            onMatch({
              version: match.version,
              cl: match.cl,
              ...(oauthUa ? { oauthUserAgent: oauthUa } : {})
            });
            break;
          }
          if (!oauthOnly && scanner.blazeCl && !blazeCl) {
            blazeCl = scanner.blazeCl;
            tryEmitMatch();
          }
        }

        if (remainingPayload === 0) {
          finishEntryPayload();
          state = remainingPad > 0 ? 'pad' : 'header';
        }
        continue;
      }

      if (state === 'pad') {
        if (buffer.length === 0) break;
        const skip = Math.min(buffer.length, remainingPad);
        buffer = buffer.subarray(skip);
        remainingPad -= skip;
        if (remainingPad === 0) {
          state = 'header';
        }
      }
    }
  };

  return {
    push,
    get blazeCl() {
      return blazeCl;
    },
    get hintVersion() {
      return hintVersion;
    },
    get oauthHint() {
      return hintOAuth || scanner.oauthHint;
    }
  };
}

class EarlyStopError extends Error {
  constructor() {
    super('Early stop: fingerprint extracted');
    this.name = 'EarlyStopError';
  }
}

async function scanRemoteTarGzStream({ archiveUrl, doFetch, timeoutSignal, expectedVersion, oauthOnly = false }) {
  const earlyController = new AbortController();
  const archiveSignal = timeoutSignal
    ? AbortSignal.any([timeoutSignal, earlyController.signal])
    : earlyController.signal;

  const archiveRes = await doFetch(archiveUrl, { method: 'GET' }, archiveSignal);
  if (!archiveRes.ok) {
    throw new Error(`Failed to fetch official Antigravity archive (${archiveUrl}): HTTP ${archiveRes.status}`);
  }
  if (!archiveRes.body) {
    throw new Error(`Official archive response had no body (${archiveUrl})`);
  }

  let matched = null;
  let earlyStopped = false;
  const gunzip = zlib.createGunzip();
  let reader = null;

  const stopEarly = found => {
    if (matched) return;
    matched = found;
    earlyStopped = true;
    try { earlyController.abort(new EarlyStopError()); } catch {}
    try { gunzip.destroy(); } catch {}
    try { reader?.cancel?.().catch(() => {}); } catch {}
  };

  const tarScanner = createStreamingTarScanner({
    expectedVersion,
    oauthOnly,
    onMatch: stopEarly
  });

  await new Promise((resolve, reject) => {
    let settled = false;
    const done = fn => arg => {
      if (settled) return;
      settled = true;
      fn(arg);
    };
    const finishOk = done(resolve);
    const finishErr = done(reject);

    gunzip.on('data', chunk => {
      if (earlyStopped) return;
      try {
        tarScanner.push(chunk);
      } catch (err) {
        finishErr(err);
      }
    });

    gunzip.on('end', () => {
      finishOk();
    });

    gunzip.on('close', () => {
      if (earlyStopped) finishOk();
    });

    gunzip.on('error', err => {
      if (earlyStopped) finishOk();
      else finishErr(err);
    });

    (async () => {
      try {
        reader = archiveRes.body.getReader();
        while (!earlyStopped) {
          const { done: streamDone, value } = await reader.read();
          if (streamDone || earlyStopped) break;
          if (value && value.byteLength > 0) {
            if (!gunzip.write(value) && !earlyStopped) {
              await new Promise(drainResolve => {
                const onDrain = () => {
                  gunzip.off('close', onDrain);
                  drainResolve();
                };
                gunzip.once('drain', onDrain);
                gunzip.once('close', onDrain);
              });
            }
          }
        }
        if (!earlyStopped) {
          gunzip.end();
        }
      } catch (err) {
        if (earlyStopped || err instanceof EarlyStopError) {
          finishOk();
        } else {
          try { gunzip.destroy(err); } catch {}
          finishErr(err);
        }
      }
    })();
  });

  return { matched, tarScanner };
}

export async function syncHubVersionFromOfficial(options = {}) {
  const {
    dataDir,
    env = process.env,
    proxy,
    fetchFn = fetchWithProxy,
    downloadUrl = 'https://antigravity.google/download',
    timeoutMs = 45000,
    syncIdeOAuthUa = false
  } = options;

  const resolvedProxy = trimString(proxy ?? env?.ANTIGRAVITY_PROXY);
  if (resolvedProxy) validateProxyURL(resolvedProxy);

  const timeoutSignal = timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined;
  const doFetch = (url, init = {}, signal = timeoutSignal) => {
    const customFetch = fetchFn === fetchWithProxy ? undefined : fetchFn;
    return fetchWithProxy(url, init, {
      ...(resolvedProxy ? { proxy: resolvedProxy } : {}),
      ...(customFetch ? { fetchFn: customFetch } : {}),
      signal
    });
  };

  const pageRes = await doFetch(downloadUrl, {
    method: 'GET',
    headers: { Accept: 'text/html,application/xhtml+xml,*/*' }
  });
  if (!pageRes.ok) {
    throw new Error(`Failed to fetch official download page (${downloadUrl}): HTTP ${pageRes.status}`);
  }
  const html = await pageRes.text();
  const parsed = parseOfficialDownloadPage(html);
  if (!parsed || !parsed.preferredUrl) {
    throw new Error(`Could not find linux-x64/Antigravity.tar.gz download link on ${downloadUrl}`);
  }

  const archiveUrl = parsed.preferredUrl;
  const { matched: primaryMatched, tarScanner } = await scanRemoteTarGzStream({
    archiveUrl,
    doFetch,
    timeoutSignal,
    expectedVersion: parsed.version,
    oauthOnly: false
  });
  let matched = primaryMatched;

  if (!matched && tarScanner.blazeCl) {
    const parsedCore = trimString(parsed.version).split('-')[0];
    const coherentHint = tarScanner.hintVersion && (!parsedCore || tarScanner.hintVersion.split('-')[0] === parsedCore)
      ? tarScanner.hintVersion
      : null;
    const ver = coherentHint || (isValidVersion(parsed.version) ? parsed.version : null);
    if (ver) {
      const oauthUa = tarScanner.oauthHint?.oauthUserAgent;
      matched = {
        version: ver,
        cl: tarScanner.blazeCl,
        ...(oauthUa ? { oauthUserAgent: oauthUa } : {})
      };
    }
  }

  if (!matched || !isValidVersion(matched.version) || !isValidCl(matched.cl)) {
    throw new Error(`Official archive (${archiveUrl}) did not contain a valid paired Antigravity hub version and cl`);
  }

  if (!matched.oauthUserAgent && syncIdeOAuthUa && parsed.idePreferredUrl) {
    try {
      const { matched: ideMatch, tarScanner: ideScanner } = await scanRemoteTarGzStream({
        archiveUrl: parsed.idePreferredUrl,
        doFetch,
        timeoutSignal,
        expectedVersion: parsed.ideVersion,
        oauthOnly: true
      });
      const extractedOAuth = ideMatch?.oauthUserAgent || ideScanner.oauthHint?.oauthUserAgent;
      if (extractedOAuth) {
        matched = { ...matched, oauthUserAgent: extractedOAuth };
      }
    } catch {}
  }

  const detectedAt = Date.now();
  const result = {
    version: matched.version,
    cl: matched.cl,
    ...(matched.oauthUserAgent ? { oauthUserAgent: matched.oauthUserAgent } : {}),
    source: 'official-sync',
    archiveUrl,
    detectedAt
  };

  if (options.persist !== false && trimString(dataDir)) {
    writeCachedHubVersion(dataDir, result);
  }

  return result;
}
