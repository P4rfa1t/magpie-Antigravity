import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  cleanBackend,
  stopBackend,
  hasBackendAssets,
  localBackend,
  localSetup
} from '../lib/native.mjs';
import {
  isPluginInMagpie,
  cleanDownloadedAssets,
  registerMagpieCleanup,
  ensureDetachedWatcher
} from '../lib/cleanup.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function freePort() {
  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  return port;
}

function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

describe('Automatic & Manual Cleanup of Downloaded Assets', () => {
  let tmpRoot;
  const watchers = new Set();
  const spawnWatcher = (...args) => {
    const child = spawn(...args);
    watchers.add(child);
    return child;
  };

  afterEach(async () => {
    for (const child of watchers) {
      if (child.exitCode === null && child.signalCode === null) {
        const exited = once(child, 'exit', { signal: AbortSignal.timeout(10000) });
        child.ref();
        child.kill('SIGKILL');
        await exited;
      }
      watchers.delete(child);
    }
  });

  before(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'magpie-cleanup-test-'));
  });

  after(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('1. cleanBackend stops running gemini-web2api-go, removes bin/, and preserves config, secrets & gemini.db', async () => {
    const dataDir = path.join(tmpRoot, 'web-clean');
    const binDir = path.join(dataDir, 'bin');
    fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
    const binName = process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go';
    const binPath = path.join(binDir, binName);
    fs.copyFileSync(process.execPath, binPath, fs.constants.COPYFILE_FICLONE);

    fs.writeFileSync(path.join(dataDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port: 18083 }), { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_keep', adminToken: 'adm_keep' }), { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, 'gemini.db'), 'sqlite-data', { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, 'backend-channel.json'), '{"channel":"optimized"}\n', { mode: 0o600 });
    fs.writeFileSync(path.join(dataDir, 'argon-build.json'), `{"sha256":"${'a'.repeat(64)}"}\n`, { mode: 0o600 });

    const nodeLib = path.join(path.dirname(fs.realpathSync(process.execPath)), '..', 'lib');
    const child = spawn(binPath, ['-e', 'process.send("ready"); setInterval(() => {}, 1000)'], {
      env: { ...process.env, DYLD_LIBRARY_PATH: nodeLib, LD_LIBRARY_PATH: nodeLib },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    const childExited = new Promise(resolve => child.on('exit', resolve));
    await new Promise((resolve, reject) => {
      child.once('message', resolve);
      child.once('error', reject);
    });
    fs.writeFileSync(path.join(dataDir, 'backend.pid'), `${child.pid}\n`, { mode: 0o600 });

    assert.equal(hasBackendAssets(dataDir), true);
    assert.ok(localBackend({ dataDir }));

    try {
      const res = await cleanBackend({ dataDir });
      assert.equal(res.cleaned, true);
      await childExited;
      assert.equal(processAlive(child.pid), false, 'running gemini-web2api-go process must be stopped');
    } finally {
      try { process.kill(child.pid, 'SIGKILL'); } catch {}
    }

    assert.equal(hasBackendAssets(dataDir), false);
    assert.equal(localBackend({ dataDir }), null, 'localBackend is null once binary is removed');
    assert.deepEqual(localSetup({ dataDir }), {
      origin: 'http://127.0.0.1:18083',
      baseURL: 'http://127.0.0.1:18083/v1',
      apiKey: 'gw_keep',
      adminToken: 'adm_keep'
    });
    assert.equal(fs.existsSync(path.join(dataDir, 'gemini.db')), true, 'gemini.db must be preserved');
  });

  it('2. isPluginInMagpie distinguishes installed, disabled ("off": true), stale paths, and removed states', () => {
    const magpieDir = path.join(tmpRoot, 'magpie-config');
    fs.mkdirSync(magpieDir, { recursive: true });

    // Missing plugins.json -> null
    assert.equal(isPluginInMagpie(magpieDir), null);

    // Invalid JSON -> null
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), '{not-valid');
    assert.equal(isPluginInMagpie(magpieDir), null);

    // Installed via npm spec
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: 'magpie-gemini-web@0.9.0' }]
    }));
    assert.equal(isPluginInMagpie(magpieDir), true);

    // Disabled via UI toggle ("off": true) -> still true!
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: 'magpie-gemini-web', off: true }]
    }));
    assert.equal(isPluginInMagpie(magpieDir), true);

    // Stale path entry pointing to a non-existent folder -> false!
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: path.join(tmpRoot, 'deleted-checkout-magpie-gemini-web'), off: true }]
    }));
    assert.equal(isPluginInMagpie(magpieDir, { pluginRoot: path.join(tmpRoot, 'other-root') }), false);

    // Valid local path entry with package.json name === "magpie-gemini-web" -> true!
    const validLocalDir = path.join(tmpRoot, 'local-checkout');
    fs.mkdirSync(validLocalDir, { recursive: true });
    fs.writeFileSync(path.join(validLocalDir, 'package.json'), JSON.stringify({ name: 'magpie-gemini-web' }));
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: validLocalDir }]
    }));
    assert.equal(isPluginInMagpie(magpieDir, { pluginRoot: path.join(tmpRoot, 'other-root') }), true);

    // Removed (empty plugins list) -> false!
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: []
    }));
    assert.equal(isPluginInMagpie(magpieDir), false);
  });

  it('3. detached watcher automatically cleans Web assets when plugin is disabled then removed in Magpie', async () => {
    const magpieDir = path.join(tmpRoot, 'magpie-e2e');
    const webDir = path.join(tmpRoot, 'web-e2e');
    const pidFile = path.join(tmpRoot, 'watcher.pid');

    fs.mkdirSync(magpieDir, { recursive: true });
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: 'magpie-gemini-web' }]
    }));

    // Populate Web downloaded assets + db
    fs.mkdirSync(path.join(webDir, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(webDir, 'bin', process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go'), 'web-bin');
    fs.writeFileSync(path.join(webDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port: await freePort() }));
    fs.writeFileSync(path.join(webDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_1', adminToken: 'adm_1' }));
    fs.writeFileSync(path.join(webDir, 'gemini.db'), 'db-keep');

    const watcher = ensureDetachedWatcher({
      magpieDir,
      webDir,
      pidFile,
      pollMs: 100,
      spawnFn: spawnWatcher
    });
    assert.ok(watcher?.pid, 'detached watcher should be spawned');

    try {
      // Step 1: User toggles plugin OFF in Magpie ("off": true) -> assets must NOT be deleted
      fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
        plugins: [{ spec: 'magpie-gemini-web', off: true }]
      }));
      await sleep(300);
      assert.equal(hasBackendAssets(webDir), true, 'disabling plugin must not delete Web assets');

      // Step 2: User deletes plugin in Magpie -> entry removed from plugins.json
      fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
        plugins: []
      }));

      const deadline = Date.now() + 30000;
      while (Date.now() < deadline && hasBackendAssets(webDir)) {
        await sleep(100);
      }

      assert.equal(hasBackendAssets(webDir), false, 'Web downloaded assets must be removed upon uninstall');
      assert.equal(fs.existsSync(path.join(webDir, 'gemini.db')), true, 'Web gemini.db must be preserved');
      assert.equal(fs.existsSync(path.join(webDir, 'secrets.json')), true, 'Web secrets.json must be preserved');
    } finally {
      fs.rmSync(pidFile, { force: true });
    }
  });

  it('4. CLI clean subcommand in scripts/backend.mjs cleans downloaded assets while keeping accounts', async () => {
    const webDir = path.join(tmpRoot, 'cli-web');

    fs.mkdirSync(path.join(webDir, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(webDir, 'bin', process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go'), 'web');
    fs.writeFileSync(path.join(webDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port: await freePort() }));
    fs.writeFileSync(path.join(webDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_cli', adminToken: 'adm_cli' }));

    const runCli = (script, args) => new Promise((resolve, reject) => {
      const proc = spawn(process.execPath, [path.resolve(script), ...args], { stdio: 'pipe' });
      let out = '';
      proc.stdout.on('data', d => { out += d; });
      proc.stderr.on('data', d => { out += d; });
      proc.on('error', reject);
      proc.on('close', code => resolve({ code, out }));
    });

    const webRes = await runCli('scripts/backend.mjs', ['clean', `--data-dir=${webDir}`]);
    assert.equal(webRes.code, 0, webRes.out);
    assert.equal(hasBackendAssets(webDir), false);
    assert.equal(fs.existsSync(path.join(webDir, 'config.json')), true);

    const directRes = await cleanDownloadedAssets({ webDir });
    assert.equal(directRes.web.cleaned, true);
  });

  it('5. registerMagpieCleanup exposes handle.pid, resets after reinstall, and cleans again on 2nd removal', async () => {
    const magpieDir = path.join(tmpRoot, 'magpie-reinstall');
    const webDir = path.join(tmpRoot, 'web-reinstall');
    const pidFile = path.join(tmpRoot, 'watcher-reinstall.pid');

    fs.mkdirSync(magpieDir, { recursive: true });
    fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
      plugins: [{ spec: 'magpie-gemini-web' }]
    }));

    const seedAssets = async () => {
      fs.mkdirSync(path.join(webDir, 'bin'), { recursive: true });
      fs.writeFileSync(path.join(webDir, 'bin', process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go'), 'web-bin');
      fs.writeFileSync(path.join(webDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port: await freePort() }));
      fs.writeFileSync(path.join(webDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_re', adminToken: 'adm_re' }));
    };

    await seedAssets();
    const handle = registerMagpieCleanup({ directory: magpieDir }, {
      webDir,
      pidFile,
      pollMs: 80,
      spawnFn: spawnWatcher
    });
    assert.ok(handle, 'registerMagpieCleanup must return a handle');
    assert.ok(Number.isInteger(handle.pid) && handle.pid > 0, 'handle.pid must expose active watcher PID');

    try {
      // 1st removal
      fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({ plugins: [] }));
      handle.triggerIfRemoved();

      const deadline1 = Date.now() + 30000;
      while (Date.now() < deadline1 && hasBackendAssets(webDir)) {
        await sleep(80);
      }
      assert.equal(hasBackendAssets(webDir), false, '1st removal must clean Web assets');

      // Wait for 1st watcher to exit and clear pidFile
      const exitDeadline1 = Date.now() + 10000;
      while (Date.now() < exitDeadline1 && handle.pid !== undefined) {
        await sleep(50);
      }

      // Reinstall plugin in plugins.json and re-create assets
      fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({
        plugins: [{ spec: 'magpie-gemini-web' }]
      }));
      await seedAssets();
      const rewatched = handle.ensureWatcher();
      assert.ok(rewatched?.pid, 'ensureWatcher must re-arm after reinstall');
      assert.ok(Number.isInteger(handle.pid) && handle.pid > 0, 'handle.pid must be populated after reinstall');

      // 2nd removal
      fs.writeFileSync(path.join(magpieDir, 'plugins.json'), JSON.stringify({ plugins: [] }));
      handle.triggerIfRemoved();

      const deadline2 = Date.now() + 30000;
      while (Date.now() < deadline2 && hasBackendAssets(webDir)) {
        await sleep(80);
      }
      assert.equal(hasBackendAssets(webDir), false, '2nd removal must also clean Web assets');
    } finally {
      handle.close();
      fs.rmSync(pidFile, { force: true });
    }
  });

  it('6. stale or reused PIDs are never signaled and do not keep the watcher alive as an orphan', async () => {
    const webDir = path.join(tmpRoot, 'stale-pid-web');
    fs.mkdirSync(webDir, { recursive: true });

    const unrelated = spawn(process.execPath, ['-e', 'process.send("ready"); setInterval(() => {}, 1000)'], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    const exited = new Promise(resolve => unrelated.on('exit', resolve));
    await new Promise((resolve, reject) => {
      unrelated.once('message', resolve);
      unrelated.once('error', reject);
    });

    try {
      fs.writeFileSync(path.join(webDir, 'backend.pid'), `${unrelated.pid}\n`);

      // hasBackendAssets must ignore and clean up stale/unverified backend.pid
      assert.equal(hasBackendAssets(webDir), false, 'unverified Web backend.pid must not count as active asset');
      assert.equal(fs.existsSync(path.join(webDir, 'backend.pid')), false);

      // Even when binaries exist on disk, cleanBackend must not kill unrelated PID
      fs.mkdirSync(path.join(webDir, 'bin'), { recursive: true });
      fs.writeFileSync(path.join(webDir, 'bin', process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      fs.writeFileSync(path.join(webDir, 'backend.pid'), `${unrelated.pid}\n`);

      await cleanBackend({ dataDir: webDir });

      assert.equal(processAlive(unrelated.pid), true, 'unrelated process must survive cleanBackend');
    } finally {
      try { unrelated.kill('SIGKILL'); } catch {}
      await exited;
    }
  });

  it('7. cleanBackend serializes with .setup.lock and stopBackend rejects foreign listeners', async () => {
    const webDir = path.join(tmpRoot, 'lock-web');

    fs.mkdirSync(path.join(webDir, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(webDir, 'bin', process.platform === 'win32' ? 'gemini-web2api-go.exe' : 'gemini-web2api-go'), 'bin');
    fs.writeFileSync(path.join(webDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port: await freePort() }));
    fs.writeFileSync(path.join(webDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_lock', adminToken: 'adm_lock' }));

    const webLock = path.join(webDir, '.setup.lock');
    fs.writeFileSync(webLock, `${process.pid}\n${Date.now()}\n`, { mode: 0o600 });

    let webCleaned = false;
    const pWeb = cleanBackend({ dataDir: webDir }).then(() => { webCleaned = true; });

    await sleep(150);
    assert.equal(webCleaned, false, 'cleanBackend must wait while .setup.lock is held');

    fs.rmSync(webLock, { force: true });
    await pWeb;
    assert.equal(webCleaned, true);

    // stopBackend rejects foreign listener (HTTP 401 on /v1/models)
    await assert.rejects(
      stopBackend({
        dataDir: webDir,
        fetchFn: async () => new Response('unauthorized', { status: 401 })
      }),
      /Cannot stop unknown or foreign process/
    );
  });
});
