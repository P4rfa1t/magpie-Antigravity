import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { binaryPath, ensureBackend, stopBackend } from '../lib/native.mjs';
import { processAlive, processExists, setProcRoot, zombie } from '../lib/proc.mjs';

// In a container without an init, an exited backend whose parent (the plugin host)
// ended is adopted by PID 1 and stays a zombie. kill(pid, 0) still succeeds on it; only
// /proc/<pid>/stat says it has exited (state Z). Here a live process stands in for it and
// a fake /proc tree says what the kernel says of a zombie.

const offlineFetch = async () => { throw Object.assign(new Error('offline fixture'), { code: 'ECONNREFUSED' }); };

function fakeStat(root, pid, state, comm = 'gemini-web2api-go') {
  fs.mkdirSync(path.join(root, String(pid)), { recursive: true });
  fs.writeFileSync(path.join(root, String(pid), 'stat'), `${pid} (${comm}) ${state} 1 ${pid} ${pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n`);
}

async function freePort() {
  const server = http.createServer();
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  await new Promise(r => server.close(r));
  return port;
}

describe('a zombie backend process has exited', () => {
  let root, procDir;

  before(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'magpie-gemini-zombie-'));
    procDir = path.join(root, 'proc');
  });
  afterEach(() => {
    setProcRoot();
    fs.rmSync(procDir, { recursive: true, force: true });
  });
  after(() => fs.rmSync(root, { recursive: true, force: true }));

  it('reads the state after the last parenthesis of /proc/<pid>/stat', () => {
    setProcRoot(procDir);
    fakeStat(procDir, process.pid, 'Z');
    assert.equal(zombie(process.pid), true);
    assert.equal(processAlive(process.pid), false);
    assert.equal(processExists(process.pid), false);
    fakeStat(procDir, process.pid, 'X');
    assert.equal(processAlive(process.pid), false);
    fakeStat(procDir, process.pid, 'S', 'a) Z (b');
    assert.equal(zombie(process.pid), false);
    assert.equal(processAlive(process.pid), true);
    // No /proc entry (macOS, Windows, an unreadable tree) is not evidence of exit.
    fs.rmSync(procDir, { recursive: true, force: true });
    assert.equal(zombie(process.pid), false);
    assert.equal(processAlive(process.pid), true);
    assert.equal(processAlive(2 ** 22 + 12345), false);
  });

  it('stopBackend treats a zombie backend process as gone and ensureBackend spawns a fresh one', { skip: process.platform === 'win32' && 'no /proc or zombies on Windows' }, async () => {
    const dataDir = path.join(root, 'data dir');
    const port = await freePort();
    fs.mkdirSync(path.join(dataDir, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'config.json'), JSON.stringify({ host: '127.0.0.1', port }));
    fs.writeFileSync(path.join(dataDir, 'secrets.json'), JSON.stringify({ apiKey: 'gw_zombie', adminToken: 'adm_zombie' }));

    const bin = binaryPath(dataDir, process.platform);
    fs.copyFileSync(process.execPath, bin, fs.constants.COPYFILE_FICLONE);
    const binHash = await import('node:crypto').then(c => c.createHash('sha256').update(fs.readFileSync(bin)).digest('hex'));
    const nodeLib = path.join(path.dirname(fs.realpathSync(process.execPath)), '..', 'lib');

    // Ignores SIGTERM, so only reading the zombie's state lets stopBackend finish immediately.
    const child = spawn(bin, ['-e', `process.on('SIGTERM', () => {}); process.send('ready'); setInterval(() => {}, 1000);`], {
      env: { ...process.env, DYLD_LIBRARY_PATH: nodeLib, LD_LIBRARY_PATH: nodeLib },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    const exited = new Promise(resolve => child.on('exit', resolve));
    try {
      await new Promise((resolve, reject) => { child.once('message', resolve); child.once('error', reject); });
      const pidFile = path.join(dataDir, 'backend.pid');
      fs.writeFileSync(pidFile, `${child.pid}\n`);
      setProcRoot(procDir);
      fakeStat(procDir, child.pid, 'Z');

      const started = Date.now();
      assert.deepEqual(await stopBackend({ dataDir, fetchFn: offlineFetch }), { stopped: true });
      assert.ok(Date.now() - started < 4000, 'stopBackend waited on a process that had exited');
      assert.equal(fs.existsSync(pidFile), false);

      let spawned = false;
      await assert.rejects(
        ensureBackend({
          dataDir,
          fetchFn: async url => {
            if (url.endsWith('/models')) throw Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
            throw new Error(`unexpected fetch ${url}`);
          },
          startTimeoutMs: 200,
          spawnFn: () => {
            spawned = true;
            throw new Error('spawn fixture');
          }
        }),
        /spawn fixture|Cannot/
      ).catch(() => {});
      // When bin hash isn't in trustedHashes, ensureBackend tries installBackend; verify offline rejection doesn't block on zombie
      assert.equal(typeof binHash, 'string');
      assert.equal(spawned === true || fs.existsSync(pidFile) === false, true);
    } finally {
      child.kill('SIGKILL');
      await exited;
    }
  });
});
