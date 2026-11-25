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
  HUB_VERSION_FILENAME,
  detectLocalAntigravityFingerprint,
  extractHubFingerprintFromTextOrBuffer,
  parseOfficialDownloadPage,
  readCachedHubVersion,
  resolveAntigravityUserAgents,
  syncHubVersionFromOfficial,
  writeCachedHubVersion
} from '../lib/antigravity-ua.mjs';

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
      version: '2.35.1',
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
    assert.equal(fromCache.hubVersion, '2.35.1');
    assert.equal(fromCache.hubCl, '1042000123');
    assert.equal(fromCache.oauthUserAgent, 'vscode/1.99.2 (Antigravity/4.4.0)');
    assert.ok(fromCache.egressUserAgent.includes('antigravity/hub/2.35.1'));
    assert.ok(fromCache.egressUserAgent.includes('cl=1042000123'));

    // Partial env override must NOT mix new version with cached/baseline CL.
    const halfEnv = await resolveAntigravityUserAgents({
      dataDir,
      env: { ANTIGRAVITY_HUB_VERSION: '9.9.9' },
      detectLocal: false
    });
    assert.equal(halfEnv.hubVersion, '2.35.1');
    assert.equal(halfEnv.hubCl, '1042000123');

    const fullEnv = await resolveAntigravityUserAgents({
      dataDir,
      env: {
        ANTIGRAVITY_HUB_VERSION: '3.0.0',
        ANTIGRAVITY_HUB_CL: '1099000111',
        ANTIGRAVITY_OAUTH_USER_AGENT: 'custom-oauth-ua/1.0'
      },
      detectLocal: false
    });
    assert.equal(fullEnv.hubVersion, '3.0.0');
    assert.equal(fullEnv.hubCl, '1099000111');
    assert.equal(fullEnv.oauthUserAgent, 'custom-oauth-ua/1.0');
    assert.equal(fullEnv.source, 'env');
    assert.ok(fullEnv.egressUserAgent.includes('antigravity/hub/3.0.0'));
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
