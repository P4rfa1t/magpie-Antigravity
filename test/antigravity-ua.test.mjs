import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import {
  NATIVE_OAUTH_USER_AGENT,
  OFFICIAL_HUB_CL,
  OFFICIAL_HUB_VERSION
} from '../lib/antigravity-oauth.mjs';
import {
  DEFAULT_UA_MANIFEST_URL,
  HUB_VERSION_FILENAME,
  compareHubVersions,
  detectLocalAntigravityFingerprint,
  extractHubFingerprintFromTextOrBuffer,
  parseOfficialDownloadPage,
  readCachedHubVersion,
  refreshRemoteHubVersion,
  resolveAntigravityUserAgents,
  resolveUaManifestUrl,
  syncHubVersionFromOfficial,
  writeCachedHubVersion
} from '../lib/antigravity-ua.mjs';
import { antigravitySettings } from '../lib/antigravity.mjs';
import {
  extractStaticProtocolSignals,
  isSameProtocolSnapshot,
  summarizeCapturedExchanges
} from '../scripts/sync-antigravity-protocol.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'scripts', 'antigravity.mjs');

function makeTempDir(prefix = 'magpie-antigravity-ua-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeTarHeader(name, size) {
  const header = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(header, 0, 0, 100);
  Buffer.from('0000755\0', 'ascii').copy(header, 100);
  Buffer.from('0000000\0', 'ascii').copy(header, 108);
  Buffer.from('0000000\0', 'ascii').copy(header, 116);
  Buffer.from(`${size.toString(8).padStart(11, '0')}\0`, 'ascii').copy(header, 124);
  Buffer.from('00000000000\0', 'ascii').copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = 0x30; // '0' regular file
  Buffer.from('ustar\0', 'ascii').copy(header, 257);
  Buffer.from('00', 'ascii').copy(header, 263);

  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  Buffer.from(`${sum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(header, 148);
  return header;
}

function buildTarGzArchive(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    chunks.push(writeTarHeader(entry.name, data.length));
    chunks.push(data);
    const rem = data.length % 512;
    if (rem !== 0) chunks.push(Buffer.alloc(512 - rem, 0));
  }
  chunks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(chunks));
}

function makeBoundaryBinary(hubText, oauthText = '', boundaryOffset = 262144) {
  const hubBuf = Buffer.from(hubText, 'utf8');
  const oauthBuf = oauthText ? Buffer.from(`\0${oauthText}\0`, 'utf8') : Buffer.alloc(0);
  const start = Math.max(0, boundaryOffset - 16);
  const buf = Buffer.alloc(start + hubBuf.length + oauthBuf.length + 1024, 0);
  hubBuf.copy(buf, start);
  if (oauthBuf.length > 0) oauthBuf.copy(buf, start + hubBuf.length + 64);
  return buf;
}

function makeSyntheticInstallDir(rootDir, { version = '2.36.0', cl = '1050000123', oauthUa = 'vscode/1.100.0 (Antigravity/4.4.1)', includeBinary = true, includeCl = true } = {}) {
  const appDir = path.join(rootDir, 'resources', 'app');
  const binDir = path.join(appDir, 'extensions', 'antigravity', 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(appDir, 'product.json'), JSON.stringify({
    nameShort: 'Antigravity',
    version: '4.4.1',
    vscodeVersion: '1.100.0'
  }, null, 2) + '\n', 'utf8');

  if (includeBinary) {
    const hubLine = includeCl
      ? `antigravity/hub/${version} (aidev_client; os_type=linux; arch=amd64; cl=${cl})`
      : `antigravity/hub/${version} (aidev_client; os_type=linux; arch=amd64)`;
    const binBuf = makeBoundaryBinary(hubLine, oauthUa);
    fs.writeFileSync(path.join(binDir, 'language_server_linux_x64'), binBuf);
  }
  return rootDir;
}

describe('Antigravity UA cache & validation', () => {
  it('writes and reads a valid paired hub-version.json', () => {
    const dataDir = makeTempDir();
    const entry = {
      version: '2.35.1',
      cl: '1042000123',
      oauthUserAgent: 'vscode/1.99.2 (Antigravity/4.4.0)',
      source: 'local',
      detectedAt: 1764000000000
    };
    writeCachedHubVersion(dataDir, entry);

    const cachePath = path.join(dataDir, HUB_VERSION_FILENAME);
    assert.equal(fs.existsSync(cachePath), true);
    const loaded = readCachedHubVersion(dataDir);
    assert.ok(loaded);
    assert.equal(loaded.version, '2.35.1');
    assert.equal(loaded.cl, '1042000123');
    assert.equal(loaded.oauthUserAgent, 'vscode/1.99.2 (Antigravity/4.4.0)');
    assert.equal(loaded.source, 'local');
    assert.equal(loaded.detectedAt, 1764000000000);
  });

  it('rejects malformed or partial Frankenstein entries on read and write', () => {
    const dataDir = makeTempDir();
    const valid = {
      version: '2.35.1',
      cl: '1042000123',
      source: 'local',
      detectedAt: 1764000000000
    };
    writeCachedHubVersion(dataDir, valid);

    for (const bad of [
      { version: '2.36.0', source: 'local', detectedAt: 1764000000000 },
      { version: '2.36.0', cl: 'not-numeric', source: 'local', detectedAt: 1764000000000 },
      { version: '2.36.0', cl: '12345', source: 'local', detectedAt: 1764000000000 },
      { version: '2.36', cl: '1042000123', source: 'local', detectedAt: 1764000000000 },
      { version: 'latest', cl: '1042000123', source: 'local', detectedAt: 1764000000000 }
    ]) {
      assert.throws(() => writeCachedHubVersion(dataDir, bad));
    }
    // Existing valid cache remains intact after rejected writes.
    assert.equal(readCachedHubVersion(dataDir)?.version, '2.35.1');

    const cachePath = path.join(dataDir, HUB_VERSION_FILENAME);
    for (const raw of [
      '{not-json',
      JSON.stringify({ version: '2.36.0', source: 'local', detectedAt: 1 }),
      JSON.stringify({ version: '2.36.0', cl: 'abc', source: 'local', detectedAt: 1 }),
      JSON.stringify({ version: '2.36', cl: '1042000123', source: 'local', detectedAt: 1 }),
      JSON.stringify({ version: '2.36.0', cl: '1042000123', oauthUserAgent: '', source: 'local', detectedAt: 1 }),
      JSON.stringify({ version: '2.36.0', cl: '1042000123', source: 'local', detectedAt: 'bad' })
    ]) {
      fs.writeFileSync(cachePath, raw, 'utf8');
      assert.equal(readCachedHubVersion(dataDir), null);
    }
  });
});

describe('Antigravity fingerprint extraction & local detection', () => {
  it('extracts paired version/cl and optional OAuth UA, rejecting partial matches', () => {
    const sample = Buffer.from(
      'noise\0antigravity/hub/2.35.1 (aidev_client; os_type=linux; arch=amd64; cl=1042000123)\0vscode/1.99.2 (Antigravity/4.4.0)\0',
      'utf8'
    );
    const hit = extractHubFingerprintFromTextOrBuffer(sample);
    assert.ok(hit);
    assert.equal(hit.version, '2.35.1');
    assert.equal(hit.cl, '1042000123');
    assert.equal(hit.oauthUserAgent, 'vscode/1.99.2 (Antigravity/4.4.0)');

    assert.equal(extractHubFingerprintFromTextOrBuffer('antigravity/hub/2.35.1 (aidev_client; os_type=linux)'), null);
    assert.equal(extractHubFingerprintFromTextOrBuffer('cl=1042000123 without hub prefix'), null);
  });

  it('detects paired fingerprint across 256 KiB chunk boundary in synthetic install dir', async () => {
    const installDir = makeTempDir('magpie-agy-install-');
    const dataDir = makeTempDir('magpie-agy-data-');
    makeSyntheticInstallDir(installDir, {
      version: '2.36.0',
      cl: '1050000123',
      oauthUa: 'vscode/1.100.0 (Antigravity/4.4.1)'
    });

    const dry = await detectLocalAntigravityFingerprint({
      dataDir,
      installDir,
      persist: false
    });
    assert.ok(dry);
    assert.equal(dry.version, '2.36.0');
    assert.equal(dry.cl, '1050000123');
    assert.equal(dry.source, 'local');
    assert.equal(readCachedHubVersion(dataDir), null);

    const saved = await detectLocalAntigravityFingerprint({
      dataDir,
      installDir,
      persist: true
    });
    assert.ok(saved);
    assert.equal(saved.version, '2.36.0');
    assert.equal(saved.cl, '1050000123');
    assert.equal(saved.source, 'local');
    assert.ok(saved.binaryPath);
    const cached = readCachedHubVersion(dataDir);
    assert.equal(cached?.version, '2.36.0');
    assert.equal(cached?.cl, '1050000123');
    assert.equal(cached?.source, 'local');
  });

  it('never fabricates a Frankenstein pair from product.json alone or binary without cl=', async () => {
    const installDir = makeTempDir('magpie-agy-nocl-');
    const dataDir = makeTempDir('magpie-agy-nocl-data-');
    makeSyntheticInstallDir(installDir, {
      version: '2.99.0',
      includeBinary: true,
      includeCl: false
    });

    const res = await detectLocalAntigravityFingerprint({
      dataDir,
      installDir,
      persist: true
    });
    assert.equal(res, null);
    assert.equal(readCachedHubVersion(dataDir), null);
  });

  it('prefers package.json hub version over product.json IDE version with Blaze CL, and rejects IDE-only pairing', async () => {
    const blazePayload = Buffer.from(
      'noise\0changelist 1029194470 with baseline 1027784732 in a mint client based on //depot/branches/antigravity_web_release_branch/main.go\0',
      'utf8'
    );

    // 1. product.json (4.4.0 IDE) + package.json (2.35.1 hub) + Blaze CL => hub 2.35.1 + oauth 4.4.0
    const installWithPkg = makeTempDir('magpie-agy-pkg-blaze-');
    const dataWithPkg = makeTempDir('magpie-agy-pkg-blaze-data-');
    const appDir1 = path.join(installWithPkg, 'resources', 'app');
    const binDir1 = path.join(installWithPkg, 'resources', 'bin');
    fs.mkdirSync(appDir1, { recursive: true });
    fs.mkdirSync(binDir1, { recursive: true });
    fs.writeFileSync(path.join(appDir1, 'product.json'), JSON.stringify({
      nameShort: 'Antigravity',
      version: '4.4.0',
      ideVersion: '4.4.0',
      vscodeVersion: '1.100.0'
    }) + '\n', 'utf8');
    fs.writeFileSync(path.join(appDir1, 'package.json'), JSON.stringify({
      name: 'antigravity',
      version: '2.35.1'
    }) + '\n', 'utf8');
    fs.writeFileSync(path.join(binDir1, 'language_server.exe'), blazePayload);

    const detected = await detectLocalAntigravityFingerprint({
      dataDir: dataWithPkg,
      installDir: installWithPkg,
      persist: true
    });
    assert.ok(detected);
    assert.equal(detected.version, '2.35.1');
    assert.equal(detected.cl, '1029194470');
    assert.equal(detected.oauthUserAgent, 'vscode/1.100.0 (Antigravity/4.4.0)');

    // 2. product.json (4.4.0 IDE) WITHOUT package.json + Blaze CL => null (never conflate IDE version as Hub version)
    const installIdeOnly = makeTempDir('magpie-agy-ide-only-');
    const dataIdeOnly = makeTempDir('magpie-agy-ide-only-data-');
    const appDir2 = path.join(installIdeOnly, 'resources', 'app');
    const binDir2 = path.join(installIdeOnly, 'resources', 'bin');
    fs.mkdirSync(appDir2, { recursive: true });
    fs.mkdirSync(binDir2, { recursive: true });
    fs.writeFileSync(path.join(appDir2, 'product.json'), JSON.stringify({
      nameShort: 'Antigravity',
      version: '4.4.0',
      ideVersion: '4.4.0',
      vscodeVersion: '1.100.0'
    }) + '\n', 'utf8');
    fs.writeFileSync(path.join(binDir2, 'language_server.exe'), blazePayload);

    const rejected = await detectLocalAntigravityFingerprint({
      dataDir: dataIdeOnly,
      installDir: installIdeOnly,
      persist: true
    });
    assert.equal(rejected, null);
    assert.equal(readCachedHubVersion(dataIdeOnly), null);
  });
});

describe('Antigravity UA priority resolution', () => {
  it('enforces paired env > hub-version.json > baseline and ignores half env overrides', async () => {
    const dataDir = makeTempDir('magpie-agy-prio-');

    const baseline = await resolveAntigravityUserAgents({
      dataDir,
      env: {},
      detectLocal: false
    });
    assert.equal(baseline.hubVersion, OFFICIAL_HUB_VERSION);
    assert.equal(baseline.hubCl, OFFICIAL_HUB_CL);
    assert.equal(baseline.oauthUserAgent, NATIVE_OAUTH_USER_AGENT);
    assert.ok(baseline.egressUserAgent.includes(`antigravity/hub/${OFFICIAL_HUB_VERSION}`));
    assert.ok(baseline.egressUserAgent.includes(`cl=${OFFICIAL_HUB_CL}`));

    writeCachedHubVersion(dataDir, {
      version: '8.1.0',
      cl: '1042000123',
      oauthUserAgent: 'vscode/1.99.2 (Antigravity/4.4.0)',
      source: 'official-sync',
      detectedAt: Date.now()
    });

    const fromCache = await resolveAntigravityUserAgents({
      dataDir,
      env: {},
      detectLocal: false
    });
    assert.equal(fromCache.hubVersion, '8.1.0');
    assert.equal(fromCache.hubCl, '1042000123');
    assert.equal(fromCache.oauthUserAgent, 'vscode/1.99.2 (Antigravity/4.4.0)');
    assert.ok(fromCache.egressUserAgent.includes('antigravity/hub/8.1.0'));
    assert.ok(fromCache.egressUserAgent.includes('cl=1042000123'));

    // Partial env override must NOT mix new version with cached/baseline CL.
    const halfEnv = await resolveAntigravityUserAgents({
      dataDir,
      env: { ANTIGRAVITY_HUB_VERSION: '9.9.9' },
      detectLocal: false
    });
    assert.equal(halfEnv.hubVersion, '8.1.0');
    assert.equal(halfEnv.hubCl, '1042000123');

    const fullEnv = await resolveAntigravityUserAgents({
      dataDir,
      env: {
        ANTIGRAVITY_HUB_VERSION: '9.0.0',
        ANTIGRAVITY_HUB_CL: '1099000111',
        ANTIGRAVITY_OAUTH_USER_AGENT: 'custom-oauth-ua/1.0'
      },
      detectLocal: false
    });
    assert.equal(fullEnv.hubVersion, '9.0.0');
    assert.equal(fullEnv.hubCl, '1099000111');
    assert.equal(fullEnv.oauthUserAgent, 'custom-oauth-ua/1.0');
    assert.equal(fullEnv.source, 'env');
    assert.ok(fullEnv.egressUserAgent.includes('antigravity/hub/9.0.0'));
    assert.ok(fullEnv.egressUserAgent.includes('cl=1099000111'));
  });
});

describe('Official download page parser & streaming tar.gz sync', () => {
  it('parses download page and prefers linux-x64/Antigravity.tar.gz', () => {
    const html = `
      <html><body>
        <a href="https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/darwin-arm64/Antigravity.dmg">mac</a>
        <a href="https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/win32-x64/AntigravitySetup.exe">win</a>
        <a href="https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/linux-x64/Antigravity.tar.gz">linux</a>
      </body></html>
    `;
    const parsed = parseOfficialDownloadPage(html);
    assert.ok(parsed);
    assert.equal(
      parsed.archiveUrl,
      'https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/linux-x64/Antigravity.tar.gz'
    );
    assert.equal(parsed.preferredUrl, parsed.archiveUrl);
    assert.equal(parsed.version, '2.37.0');
    assert.equal(parsed.build, '99999');
    assert.equal(parseOfficialDownloadPage('<html><body>no links here</body></html>'), null);
  });

  it('streams in-memory tar.gz via mocked fetchFn, aborts early on match, and writes hub-version.json', async () => {
    const dataDir = makeTempDir('magpie-agy-sync-');
    const archiveUrl = 'https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/linux-x64/Antigravity.tar.gz';
    const html = `<a href="${archiveUrl}">Download</a>`;

    const binaryPayload = makeBoundaryBinary(
      'antigravity/hub/2.37.0 (aidev_client; os_type=linux; arch=amd64; cl=1066000777)',
      'vscode/1.101.0 (Antigravity/4.5.0)'
    );
    const trailing = Buffer.alloc(64 * 1024);
    for (let i = 0; i < trailing.length; i++) trailing[i] = (i * 73 + 41) & 0xff;

    const tarGz = buildTarGzArchive([
      {
        name: 'Antigravity/resources/app/product.json',
        content: JSON.stringify({ version: '4.5.0', vscodeVersion: '1.101.0' })
      },
      {
        name: 'Antigravity/resources/app/extensions/antigravity/bin/language_server_linux_x64',
        content: binaryPayload
      },
      {
        name: 'Antigravity/resources/app/trailing-large.bin',
        content: trailing
      }
    ]);

    let archiveSignal = null;
    const fetchFn = async (url, init = {}) => {
      if (url === 'https://antigravity.google/download') {
        return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html' } });
      }
      if (url === archiveUrl) {
        archiveSignal = init.signal || null;
        let offset = 0;
        const step = 4096;
        const stream = new ReadableStream({
          pull(controller) {
            if (archiveSignal?.aborted) {
              controller.close();
              return;
            }
            if (offset >= tarGz.length) {
              controller.close();
              return;
            }
            controller.enqueue(tarGz.subarray(offset, Math.min(tarGz.length, offset + step)));
            offset += step;
          }
        });
        return new Response(stream, { status: 200, headers: { 'Content-Type': 'application/gzip' } });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const synced = await syncHubVersionFromOfficial({
      dataDir,
      fetchFn,
      timeoutMs: 10000
    });
    assert.equal(synced.version, '2.37.0');
    assert.equal(synced.cl, '1066000777');
    assert.equal(synced.source, 'official-sync');
    assert.equal(synced.archiveUrl, archiveUrl);
    assert.equal(archiveSignal?.aborted, true);

    const cached = readCachedHubVersion(dataDir);
    assert.equal(cached?.version, '2.37.0');
    assert.equal(cached?.cl, '1066000777');
    assert.equal(cached?.source, 'official-sync');
  });

  it('uses GCS expectedVersion (not product.json IDE version) when tar archive only has Blaze CL', async () => {
    const dataDir = makeTempDir('magpie-agy-sync-blaze-');
    const archiveUrl = 'https://storage.googleapis.com/antigravity-public/antigravity-hub/2.37.0-99999/linux-x64/Antigravity.tar.gz';
    const html = `<a href="${archiveUrl}">Download</a>`;

    const tarGz = buildTarGzArchive([
      {
        name: 'Antigravity/resources/app/product.json',
        content: JSON.stringify({ version: '4.4.0', ideVersion: '4.4.0', vscodeVersion: '1.100.0' })
      },
      {
        name: 'Antigravity/resources/bin/language_server',
        content: Buffer.from(
          'bin\0googlefile:/google_src/files/1066000777/depot/branches/antigravity_web_release_branch/server\0',
          'utf8'
        )
      }
    ]);

    const fetchFn = async url => {
      if (url === 'https://antigravity.google/download') {
        return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html' } });
      }
      if (url === archiveUrl) {
        return new Response(tarGz, { status: 200, headers: { 'Content-Type': 'application/gzip' } });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const synced = await syncHubVersionFromOfficial({
      dataDir,
      fetchFn,
      timeoutMs: 10000
    });
    assert.equal(synced.version, '2.37.0');
    assert.equal(synced.cl, '1066000777');
    assert.equal(synced.source, 'official-sync');
  });
});

describe('scripts/antigravity.mjs CLI integration', () => {
  it('runs sync-ua --local-only and status against temp ANTIGRAVITY_DATA_DIR / ANTIGRAVITY_INSTALL_DIR', () => {
    const installDir = makeTempDir('magpie-cli-install-');
    const dataDir = makeTempDir('magpie-cli-data-');
    const emptyInstallDir = makeTempDir('magpie-cli-empty-');
    makeSyntheticInstallDir(installDir, {
      version: '2.38.0',
      cl: '1077000888',
      oauthUa: 'vscode/1.102.0 (Antigravity/4.6.0)'
    });

    const baseEnv = {
      ...process.env,
      ANTIGRAVITY_DATA_DIR: dataDir,
      ANTIGRAVITY_INSTALL_DIR: installDir
    };
    delete baseEnv.ANTIGRAVITY_HUB_VERSION;
    delete baseEnv.ANTIGRAVITY_HUB_CL;
    delete baseEnv.ANTIGRAVITY_OAUTH_USER_AGENT;

    const syncOut = execFileSync(process.execPath, [CLI_PATH, 'sync-ua', '--local-only'], {
      cwd: REPO_ROOT,
      env: baseEnv,
      encoding: 'utf8',
      windowsHide: true
    });
    assert.match(syncOut, /2\.38\.0/);
    assert.match(syncOut, /1077000888/);
    assert.match(syncOut, /Egress User-Agent:\s*antigravity\/hub\/2\.38\.0.*cl=1077000888/);

    const statusOut = execFileSync(process.execPath, [CLI_PATH, 'status'], {
      cwd: REPO_ROOT,
      env: baseEnv,
      encoding: 'utf8',
      windowsHide: true
    });
    assert.match(statusOut, /Egress User-Agent:\s*antigravity\/hub\/2\.38\.0.*cl=1077000888.*source=local/);
    assert.match(statusOut, /OAuth User-Agent:\s*vscode\/1\.102\.0 \(Antigravity\/4\.6\.0\)/);
    assert.match(statusOut, /Hub version cache:.*hub-version\.json.*version=2\.38\.0.*cl=1077000888/);

    const missingRes = spawnSync(
      process.execPath,
      [CLI_PATH, 'sync-ua', '--local-only', '--install-dir', emptyInstallDir],
      {
        cwd: REPO_ROOT,
        env: baseEnv,
        encoding: 'utf8',
        windowsHide: true
      }
    );
    assert.equal(missingRes.status, 1);
    assert.match(missingRes.stderr, /No valid paired Antigravity Hub version\/CL fingerprint found locally/);
  });
});

describe('Remote manifest sync (Option B) & version convergence', () => {
  it('points default manifest URL to P4rfa1t/magpie-gemini-web and loads valid paired manifest baseline', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'lib', 'antigravity-ua.json'), 'utf8'));
    assert.equal(
      DEFAULT_UA_MANIFEST_URL,
      'https://raw.githubusercontent.com/P4rfa1t/magpie-gemini-web/main/lib/antigravity-ua.json'
    );
    assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/);
    assert.match(manifest.cl, /^\d{6,}$/);
    assert.match(manifest.oauthUserAgent, /^vscode\/\d+\.\d+\.\d+ \(Antigravity\/\d+\.\d+\.\d+\)$/);
    assert.equal(compareHubVersions(manifest.version, '2.35.1') >= 0, true);
    assert.equal(OFFICIAL_HUB_VERSION, manifest.version);
    assert.equal(OFFICIAL_HUB_CL, manifest.cl);
    assert.equal(NATIVE_OAUTH_USER_AGENT, manifest.oauthUserAgent);
    assert.equal(compareHubVersions('2.36.0', '2.35.1'), 1);
    assert.equal(compareHubVersions('2.35.1', '2.35.1'), 0);
    assert.equal(compareHubVersions('2.35.0', '2.35.1'), -1);

    assert.equal(resolveUaManifestUrl({ env: {} }), DEFAULT_UA_MANIFEST_URL);
    assert.equal(resolveUaManifestUrl({ env: { ANTIGRAVITY_UA_MANIFEST_URL: 'off' } }), null);
    assert.equal(resolveUaManifestUrl({ manifestUrl: 'https://example.com/ua.json' }), 'https://example.com/ua.json');
    assert.throws(() => antigravitySettings({ antigravity: { uaManifestUrl: 'ftp://bad.example/ua.json' } }));
    assert.equal(antigravitySettings({ antigravity: { uaManifestUrl: 'off' } }).uaManifestUrl, null);
  });

  it('refreshes paired UA from remote manifest without downgrading or writing Frankenstein payloads', async () => {
    const dataDir = makeTempDir('magpie-agy-remote-');
    let calls = 0;

    const synced = await refreshRemoteHubVersion({
      dataDir,
      manifestUrl: 'https://example.com/ua.json',
      fetchFn: async url => {
        calls += 1;
        assert.equal(url, 'https://example.com/ua.json');
        return Response.json({
          version: '8.39.0',
          cl: '1088000999',
          oauthUserAgent: 'vscode/1.103.0 (Antigravity/4.7.0)'
        });
      }
    });
    assert.ok(synced);
    assert.equal(synced.version, '8.39.0');
    assert.equal(synced.cl, '1088000999');
    assert.equal(synced.source, 'remote-manifest');
    assert.equal(calls, 1);

    // Within 12h TTL, repeated call uses cache without network request.
    const cachedAgain = await refreshRemoteHubVersion({
      dataDir,
      manifestUrl: 'https://example.com/ua.json',
      fetchFn: async () => {
        throw new Error('should not fetch within TTL');
      }
    });
    assert.equal(cachedAgain?.version, '8.39.0');

    // Remote older version must not downgrade cached 8.39.0 even after TTL expiry.
    writeCachedHubVersion(dataDir, {
      ...cachedAgain,
      detectedAt: Date.now() - 13 * 60 * 60 * 1000
    });
    let staleCalled = 0;
    const noDowngrade = await refreshRemoteHubVersion({
      dataDir,
      manifestUrl: 'https://example.com/ua-stale.json',
      fetchFn: async () => {
        staleCalled += 1;
        return Response.json({ version: '2.34.0', cl: '1011000111' });
      }
    });
    assert.equal(staleCalled, 1);
    assert.equal(noDowngrade?.version, '8.39.0');
    assert.equal(readCachedHubVersion(dataDir)?.version, '8.39.0');

    // Frankenstein remote entry (missing CL) is rejected; disabled flag returns null.
    await assert.rejects(() => refreshRemoteHubVersion({
      dataDir,
      manifestUrl: 'https://example.com/ua-bad.json',
      force: true,
      fetchFn: async () => Response.json({ version: '8.40.0' })
    }));
    assert.equal(await refreshRemoteHubVersion({
      dataDir,
      env: { ANTIGRAVITY_UA_MANIFEST_URL: 'false' },
      fetchFn: async () => {
        throw new Error('should not fetch when disabled');
      }
    }), null);
  });

  it('overrides stale disk cache when baseline advances or stale official-sync finds newer local install', async () => {
    const dataDir = makeTempDir('magpie-agy-converge-');
    const installDir = makeTempDir('magpie-agy-converge-install-');
    makeSyntheticInstallDir(installDir, {
      version: '8.41.0',
      cl: '1099111222'
    });

    // Simulate an outdated disk cache older than packaged baseline.
    writeCachedHubVersion(dataDir, {
      version: '2.33.0',
      cl: '1023160026',
      source: 'local',
      detectedAt: Date.now()
    });
    const preferBaseline = resolveAntigravityUserAgents({
      dataDir,
      env: {},
      detectLocal: false
    });
    assert.equal(preferBaseline.hubVersion, OFFICIAL_HUB_VERSION);
    assert.equal(preferBaseline.hubCl, OFFICIAL_HUB_CL);
    assert.equal(preferBaseline.source, 'baseline');

    // By default without ANTIGRAVITY_DETECT_LOCAL=1 or ANTIGRAVITY_INSTALL_DIR,
    // resolveAntigravityUserAgents avoids scanning local install dirs.
    const noLocalScan = resolveAntigravityUserAgents({
      dataDir: makeTempDir('magpie-agy-nolocal-'),
      env: { LOCALAPPDATA: path.dirname(path.dirname(installDir)) }
    });
    assert.equal(noLocalScan.source, 'baseline');

    // Simulate expired (>24h) official-sync cache while local IDE upgraded to 8.41.0.
    writeCachedHubVersion(dataDir, {
      version: '8.36.0',
      cl: '1050000123',
      source: 'official-sync',
      detectedAt: Date.now() - 25 * 60 * 60 * 1000
    });
    const upgraded = resolveAntigravityUserAgents({
      dataDir,
      env: { ANTIGRAVITY_INSTALL_DIR: installDir },
      detectLocal: true
    });
    assert.equal(upgraded.hubVersion, '8.41.0');
    assert.equal(upgraded.hubCl, '1099111222');
    assert.equal(upgraded.source, 'local');
    assert.equal(readCachedHubVersion(dataDir)?.version, '8.41.0');
  });

  it('includes valid LF-only antigravity-ua-sync GitHub workflow', () => {
    const workflowPath = path.join(REPO_ROOT, '.github', 'workflows', 'antigravity-ua-sync.yml');
    const content = fs.readFileSync(workflowPath, 'utf8');
    assert.equal(content.includes('\r\n'), false);
    assert.match(content, /cron:\s*['"][^'"]+['"]/);
    assert.match(content, /syncHubVersionFromOfficial/);
    assert.match(content, /lib\/antigravity-ua\.json/);
  });

  it('enriches Hub fingerprint with OAuth UA from co-installed IDE root and optional IDE tar stream', async () => {
    const hubDir = makeTempDir('magpie-hub-only-');
    const ideDir = makeTempDir('magpie-ide-only-');
    const dataDir = makeTempDir('magpie-cross-root-data-');

    const hubAppDir = path.join(hubDir, 'resources', 'app');
    const hubBinDir = path.join(hubDir, 'resources', 'bin');
    fs.mkdirSync(hubAppDir, { recursive: true });
    fs.mkdirSync(hubBinDir, { recursive: true });
    fs.writeFileSync(path.join(hubAppDir, 'package.json'), JSON.stringify({
      name: 'antigravity',
      version: '2.35.1'
    }) + '\n', 'utf8');
    fs.writeFileSync(
      path.join(hubBinDir, 'language_server.exe'),
      Buffer.from('noise\0changelist 1029194470 with baseline 1027784732 in a mint client based on //depot/branches/antigravity_web_release_branch/main.go\0', 'utf8')
    );

    const ideAppDir = path.join(ideDir, 'resources', 'app');
    fs.mkdirSync(ideAppDir, { recursive: true });
    fs.writeFileSync(path.join(ideAppDir, 'product.json'), JSON.stringify({
      nameShort: 'Antigravity',
      version: '4.5.2',
      ideVersion: '4.5.2',
      vscodeVersion: '1.101.0'
    }) + '\n', 'utf8');

    const localDetected = detectLocalAntigravityFingerprint({
      dataDir,
      installDir: hubDir,
      env: { ANTIGRAVITY_IDE_INSTALL_DIR: ideDir },
      persist: true
    });
    assert.ok(localDetected);
    assert.equal(localDetected.version, '2.35.1');
    assert.equal(localDetected.cl, '1029194470');
    assert.equal(localDetected.oauthUserAgent, 'vscode/1.101.0 (Antigravity/4.5.2)');

    const hubUrl = 'https://storage.googleapis.com/antigravity-public/antigravity-hub/2.39.0-99999/linux-x64/Antigravity.tar.gz';
    const ideUrl = 'https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.9.0-123456/linux-x64/Antigravity%20IDE.tar.gz';
    const html = `<a href="${hubUrl}">Hub</a><a href="${ideUrl}">IDE</a>`;
    const parsedPage = parseOfficialDownloadPage(html);
    assert.equal(parsedPage?.idePreferredUrl, ideUrl);

    const hubTarGz = buildTarGzArchive([
      {
        name: 'Antigravity/resources/app/package.json',
        content: JSON.stringify({ name: 'antigravity', version: '2.39.0' })
      },
      {
        name: 'Antigravity/language_server_linux_x64',
        content: Buffer.from('noise\0antigravity/hub/2.39.0 (aidev_client; os_type=linux; arch=amd64; cl=1088000777)\0', 'utf8')
      }
    ]);
    const ideTarGz = buildTarGzArchive([
      {
        name: 'Antigravity IDE/resources/app/product.json',
        content: JSON.stringify({ nameShort: 'Antigravity', version: '4.6.1', vscodeVersion: '1.102.0' })
      }
    ]);

    const synced = await syncHubVersionFromOfficial({
      dataDir: makeTempDir('magpie-ide-sync-data-'),
      syncIdeOAuthUa: true,
      fetchFn: async url => {
        if (url === 'https://antigravity.google/download') return new Response(html, { status: 200 });
        if (url === hubUrl) return new Response(hubTarGz, { status: 200 });
        if (url === ideUrl) return new Response(ideTarGz, { status: 200 });
        throw new Error(`Unexpected URL: ${url}`);
      }
    });
    assert.equal(synced.version, '2.39.0');
    assert.equal(synced.cl, '1088000777');
    assert.equal(synced.oauthUserAgent, 'vscode/1.102.0 (Antigravity/4.6.1)');
  });

  it('extracts clean binary protocol signals, builds deterministic wire snapshots, and wires protocol sync into CI workflow', () => {
    const rawBlob = Buffer.from(
      'https://www.googleapis.com/auth/cclogcreating ' +
      'https://www.googleapis.com/auth/userinfo.emailtelemetry ' +
      'https://www.googleapis.com/auth/cloud-platformhttps://www.googleapis.com/auth/drive.file ' +
      '/v1internal:notifyUsercrypto /v1internal:notifyUser /v1internal:deleteInstancechunk /v1internal:streamGenerateContent?alt=sse ' +
      'aidev_client os_type=%s arch=%s datacollection_opt_in=false Accept-Encoding',
      'latin1'
    );
    const signals = extractStaticProtocolSignals(rawBlob);
    assert.ok(signals.oauthScopes.includes('https://www.googleapis.com/auth/cclog'));
    assert.ok(signals.oauthScopes.includes('https://www.googleapis.com/auth/userinfo.email'));
    assert.ok(signals.oauthScopes.includes('https://www.googleapis.com/auth/cloud-platform'));
    assert.ok(signals.oauthScopes.includes('https://www.googleapis.com/auth/drive.file'));
    assert.ok(signals.endpoints.includes('/v1internal:notifyUser'));
    assert.ok(signals.endpoints.includes('/v1internal:deleteInstance'));
    assert.ok(signals.endpoints.includes('/v1internal:streamGenerateContent'));
    assert.equal(signals.endpoints.some(e => e.endsWith('crypto') || e.endsWith('chunk')), false);

    const snapshot = summarizeCapturedExchanges([
      {
        method: 'POST',
        url: '/v1internal:loadCodeAssist',
        body: JSON.stringify({ metadata: { ideType: 'ANTIGRAVITY' } })
      },
      {
        method: 'POST',
        url: '/v1internal:streamGenerateContent?alt=sse',
        rawHeaderNames: ['Host', 'User-Agent', 'Content-Length', 'Authorization', 'Content-Type', 'Accept-Encoding'],
        headers: {
          'user-agent': 'antigravity/cli/2.35.2 (aidev_client; os_type=windows; arch=amd64; cl=1029311855)',
          'content-type': 'application/json',
          'accept-encoding': 'gzip'
        },
        body: JSON.stringify({
          project: 'p1',
          requestId: 'agent/11111111-1111-4111-8111-111111111111/1700000000000/22222222-2222-4222-8222-222222222222/1',
          request: {
            contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
            tools: [{ functionDeclarations: [{ name: 'a' }, { name: 'b' }] }],
            labels: { cascade_id: 'c', last_step_index: '0', root_cascade_id: 'c', trajectory_id: 't' },
            generationConfig: { maxOutputTokens: 65536, thinkingConfig: { includeThoughts: true, thinkingLevel: 'HIGH' } },
            sessionId: '-123456'
          },
          model: 'gemini-4-hydrogen-high',
          userAgent: 'antigravity',
          requestType: 'agent'
        })
      }
    ], signals, { version: '2.35.2', cl: '1029311855' });

    assert.equal(snapshot.headers.acceptEncoding, 'gzip');
    assert.equal(snapshot.headers.userAgentTemplate, 'antigravity/cli/2.35.2 (aidev_client; os_type=<os>; arch=<arch>; cl=1029311855)');
    assert.equal(snapshot.streamGenerateContent.toolsPacking, 'single_function_declarations_wrapper');
    assert.deepEqual(snapshot.clientMetadata.loadCodeAssist, { ideType: 'ANTIGRAVITY' });

    const withTs1 = { ...snapshot, updatedAt: 100 };
    const withTs2 = { ...snapshot, updatedAt: 999 };
    assert.equal(isSameProtocolSnapshot(withTs1, withTs2), true);
    assert.equal(isSameProtocolSnapshot(withTs1, { ...snapshot, headers: { ...snapshot.headers, acceptEncoding: 'br' } }), false);

    const protocolManifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'lib', 'antigravity-protocol.json'), 'utf8'));
    assert.equal(protocolManifest.apiVersion, 'v1internal');
    assert.equal(protocolManifest.headers.acceptEncoding, 'gzip');
    assert.equal(protocolManifest.streamGenerateContent.toolsPacking, 'single_function_declarations_wrapper');

    const workflowText = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'antigravity-ua-sync.yml'), 'utf8');
    assert.equal(workflowText.includes('\r\n'), false);
    assert.match(workflowText, /syncHubVersionFromOfficial/);
    assert.match(workflowText, /scripts\/sync-antigravity-protocol\.mjs/);
  });
});
