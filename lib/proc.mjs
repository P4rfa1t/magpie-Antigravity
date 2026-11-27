import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// Where /proc is read. Tests point it at a fake tree.
let procRoot = '/proc';

export function setProcRoot(root) {
  procRoot = root || '/proc';
}

// zombie: /proc says the PID has exited and waits only to be reaped (Z), or is
// being torn down (X). A process whose parent ended is adopted by PID 1, and in
// a container without an init (magpie itself as PID 1) nothing may ever reap
// it, while kill(pid, 0) still succeeds on it. Off Linux there is no /proc and
// an unreadable entry is not evidence of exit: both answer false.
export function zombie(pid) {
  let stat;
  try { stat = fs.readFileSync(`${procRoot}/${pid}/stat`, 'utf8'); } catch { return false; }
  // The command name, in parentheses, can hold spaces and ')'; the state follows the last ')'.
  const state = stat.slice(stat.lastIndexOf(')') + 1).trim()[0];
  return state === 'Z' || state === 'X';
}

// processAlive: a PID that can still run. EPERM means it exists under another
// user; a zombie has exited.
export function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); } catch (err) { if (err.code !== 'EPERM') return false; }
  return !zombie(pid);
}

// processExists: as processAlive, but a failed probe other than ESRCH counts as
// alive, for callers that must not reclaim what they cannot inspect.
export function processExists(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); } catch (err) { if (err.code === 'ESRCH') return false; }
  return !zombie(pid);
}

/**
 * Returns whether the current process appears to be running inside a container.
 */
export function isContainerEnv({
  env = process.env,
  platform = process.platform,
  existsSync = fs.existsSync,
  readFileSync = fs.readFileSync,
} = {}) {
  const override = String(env?.DOCKER_CONTAINER || '').trim().toLowerCase();
  if (override === '1' || override === 'true') return true;
  if (override === '0' || override === 'false') return false;
  if (String(env?.container || '').trim()) return true;
  if (String(env?.KUBERNETES_SERVICE_HOST || '').trim()) return true;
  if (platform !== 'linux') return false;
  try {
    if (existsSync('/.dockerenv') || existsSync('/run/.containerenv')) return true;
  } catch {}
  try {
    const cgroup = readFileSync('/proc/1/cgroup', 'utf8');
    if (/(?:docker|containerd|kubepods|podman|lxc)/i.test(cgroup)) return true;
  } catch {}
  return false;
}

/**
 * Returns whether a proxy URL points to loopback (127.0.0.1, localhost, or ::1).
 */
export function isLoopbackProxy(proxy) {
  const raw = String(proxy || '').trim();
  if (!raw) return false;
  try {
    const { hostname } = new URL(raw);
    const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
    return host === '127.0.0.1' || host === 'localhost' || host === '::1';
  } catch {
    return false;
  }
}

/**
 * Returns a Docker-specific hint when a loopback proxy URL is used inside a container.
 */
export function dockerProxyHint(proxy, opts = {}) {
  const inContainer = opts.container ?? isContainerEnv(opts);
  if (!inContainer || !isLoopbackProxy(proxy)) return '';
  return '检测到当前运行在容器环境中，容器内的 127.0.0.1/localhost 指向容器自身而非宿主机代理；若代理在宿主机上，请改用 http://host.docker.internal:<端口>（Linux Docker 需添加 --add-host=host.docker.internal:host-gateway）、宿主机局域网 IP，或使用 --network host。';
}

function sameExecutable(actual, expected) {
  if (!actual) return false;
  actual = actual.trim().replace(/ \(deleted\)$/, '');
  const normalize = p => process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p);
  if (!path.isAbsolute(actual)) return false;
  if (normalize(actual) === normalize(expected)) return true;
  try { return normalize(fs.realpathSync(actual)) === normalize(fs.realpathSync(expected)); } catch { return false; }
}

function replacedExecutable(actual, expected) {
  return sameExecutable(actual, path.join(path.dirname(expected), '.' + path.basename(expected) + '.old'));
}

function launchedFrom(command, bin) {
  return [bin, '"' + bin + '"'].some(prefix => command === prefix || command.startsWith(prefix + ' '));
}

// true = verified executable, false = another/dead process, null = inspection unavailable.
// File replacement is a pathname change, not evidence that a running PID has exited.
export function verifyProcessIdentity(pid, expectedBinaryPath, platform = process.platform, run = execFileSync) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  const opts = { encoding: 'utf8', timeout: 5000, windowsHide: true, env: { ...process.env,
    LC_ALL: process.env.LC_ALL || process.env.LANG || 'en_US.UTF-8', LANG: process.env.LANG || 'en_US.UTF-8' } };
  try {
    if (platform === 'win32') {
      const out = run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
        '$ErrorActionPreference = "Stop"; [Console]::OutputEncoding = [Text.UTF8Encoding]::new(); Get-CimInstance Win32_Process -Filter "ProcessId = $env:TARGET_PID" | Select-Object -ExpandProperty ExecutablePath'],
      { ...opts, timeout: 20000, env: { ...process.env, TARGET_PID: String(pid) } }).trim();
      if (!out) return processAlive(pid) ? null : false;
      if (sameExecutable(out, expectedBinaryPath)) return true;
      if (!replacedExecutable(out, expectedBinaryPath)) return false;
      const command = run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
        '(Get-CimInstance Win32_Process -Filter "ProcessId = $env:TARGET_PID").CommandLine'],
      { ...opts, timeout: 20000, env: { ...process.env, TARGET_PID: String(pid) } }).trim();
      return command ? launchedFrom(command, expectedBinaryPath) : null;
    }
    if (platform === 'linux' && run === execFileSync) {
      const exe = fs.readlinkSync('/proc/' + pid + '/exe');
      if (sameExecutable(exe, expectedBinaryPath)) return true;
      if (!replacedExecutable(exe, expectedBinaryPath)) return false;
      return sameExecutable(fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0')[0], expectedBinaryPath);
    }
    const comm = run('ps', ['-p', String(pid), '-o', 'comm='], opts).trim();
    if (!comm) return processAlive(pid) ? null : false;
    if (sameExecutable(comm, expectedBinaryPath)) return true;
    if (!replacedExecutable(comm, expectedBinaryPath) &&
        (path.isAbsolute(comm) || path.basename(comm.replace(/ \(deleted\)$/, '')) !== path.basename(expectedBinaryPath))) return false;
    const command = run('ps', ['-ww', '-p', String(pid), '-o', 'command='], opts).trim();
    return command ? launchedFrom(command, expectedBinaryPath) : processAlive(pid) ? null : false;
  } catch { return processAlive(pid) ? null : false; }
}

export function processPids(bin, platform = process.platform, run = execFileSync) {
  const opts = { encoding: 'utf8', timeout: platform === 'win32' ? 20000 : 5000, windowsHide: true };
  let output;
  if (platform === 'win32') {
    try {
      output = run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
        '$ErrorActionPreference = "Stop"; Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:TARGET_BINARY -or $_.ExecutablePath -eq $env:TARGET_OLD_BINARY } | Select-Object -ExpandProperty ProcessId'],
      { ...opts, env: { ...process.env, TARGET_BINARY: path.resolve(bin), TARGET_OLD_BINARY: path.join(path.dirname(path.resolve(bin)), '.' + path.basename(bin) + '.old') } });
    } catch (err) {
      throw new Error(`Cannot check for remaining backend processes (${path.basename(bin)}). Check that PowerShell/CIM is available and permitted.`, { cause: err });
    }
    return [...new Set(String(output).trim().split(/\s+/).map(Number).filter(n => Number.isInteger(n) && n > 0))];
  }
  if (platform === 'linux' && run === execFileSync) {
    return fs.readdirSync('/proc').filter(n => /^\d+$/.test(n)).flatMap(n => {
      try {
        const command = fs.readFileSync(`/proc/${n}/cmdline`, 'utf8').split('\0')[0];
        return path.isAbsolute(command) && path.resolve(command) === path.resolve(bin) && !zombie(n) ? [Number(n)] : [];
      } catch { return []; }
    });
  }
  const psOpts = run === execFileSync
    ? {
        ...opts,
        env: {
          ...process.env,
          LC_ALL: process.env.LC_ALL || process.env.LANG || 'en_US.UTF-8',
          LANG: process.env.LANG || 'en_US.UTF-8'
        }
      }
    : opts;
  const pids = new Set();
  output = run('ps', ['-axo', 'pid=,comm='], psOpts);
  for (const line of String(output).split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(.+)$/);
    if (match && (sameExecutable(match[2], bin) || replacedExecutable(match[2], bin))) pids.add(Number(match[1]));
  }
  const commands = run('ps', ['-ww', '-axo', 'pid=,command='], psOpts);
  for (const line of String(commands).split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(.+)$/);
    if (match && launchedFrom(match[2], bin)) pids.add(Number(match[1]));
  }
  return [...pids].filter(pid => !zombie(pid));
}

export function listenerPids(port, platform = process.platform, run = execFileSync) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid listener port');
  const opts = { encoding: 'utf8', timeout: platform === 'win32' ? 20000 : 5000, windowsHide: true };
  let output;
  if (platform === 'win32') {
    output = run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      '$ErrorActionPreference = "Stop"; Get-NetTCPConnection -State Listen -LocalPort $env:TARGET_PORT | Select-Object -ExpandProperty OwningProcess -Unique'],
    { ...opts, env: { ...process.env, TARGET_PORT: String(port) } });
  } else {
    try {
      output = run('lsof', ['-nP', '-t', `-iTCP:${port}`, '-sTCP:LISTEN'], opts);
    } catch (err) {
      if (platform !== 'linux') throw err;
      const rows = run('ss', ['-H', '-ltnp', `sport = :${port}`], opts);
      output = [...String(rows).matchAll(/pid=(\d+)/g)].map(m => m[1]).join('\n');
    }
  }
  return [...new Set(String(output).trim().split(/\s+/).map(Number).filter(n => Number.isInteger(n) && n > 0))];
}
