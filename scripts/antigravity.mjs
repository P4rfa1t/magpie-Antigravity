#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {
  antigravityDataDir,
  loadAntigravityAccounts,
  loadOAuthClients,
  parseRefreshTokenPackage,
  removeAntigravityAccount,
  saveAntigravityAccount,
  saveOAuthClientCredentials,
  verifyRefreshToken
} from '../lib/antigravity-oauth.mjs';
import {
  ANTIGRAVITY_BASE,
  antigravitySettings,
  antigravityUsage,
  forwardAntigravity,
  listAntigravityModels
} from '../lib/antigravity.mjs';
import {
  HUB_VERSION_FILENAME,
  detectLocalAntigravityFingerprint,
  readCachedHubVersion,
  resolveAntigravityUserAgents,
  syncHubVersionFromOfficial
} from '../lib/antigravity-ua.mjs';

const USAGE_TEXT = `Usage: node scripts/antigravity.mjs <command> [options]

Commands:
  status                                    Show data dir, effective User-Agents, cache status, and accounts
  sync-ua [--proxy http://...] [--install-dir <path>] [--local-only]
                                            Sync paired Hub version/CL from official download or local install
  oauth --client-id <id> --client-secret <secret> [--type personal|enterprise]
                                            Save OAuth client credentials
  login <refresh_token_or_json> [--type personal|enterprise] [--proxy http://...] [--file <path>] [--client-id <id> --client-secret <secret>]
                                            Verify and import Refresh Token(s)
  remove <email>                            Remove a saved account
  quota [--proxy http://...]                Print quota summary JSON
  models [--proxy http://...]               List aggregated models and variants
  smoke [--model <id>] [--proxy http://...] Run minimal chat completion smoke test`;

function parseArgs(argv) {
  const args = [...argv];
  const command = args.shift() || 'status';
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--type' || a === '-t') flags.type = args[++i];
    else if (a === '--proxy' || a === '-p') flags.proxy = args[++i];
    else if (a.startsWith('--proxy=')) flags.proxy = a.slice('--proxy='.length);
    else if (a === '--model' || a === '-m') flags.model = args[++i];
    else if (a === '--file' || a === '-f') flags.file = args[++i];
    else if (a === '--client-id') flags.clientId = args[++i];
    else if (a === '--client-secret') flags.clientSecret = args[++i];
    else if (a === '--install-dir') flags.installDir = args[++i];
    else if (a.startsWith('--install-dir=')) flags.installDir = a.slice('--install-dir='.length);
    else if (a === '--local-only') flags.localOnly = true;
    else if (a === '--help' || a === '-h') flags.help = true;
    else positional.push(a);
  }
  return { command, flags, positional };
}

function readStdinText() {
  if (process.stdin.isTTY) return '';
  return fs.readFileSync(0, 'utf8');
}

async function main() {
  const { command, flags, positional } = parseArgs(process.argv.slice(2));
  if (command === 'help' || command === '--help' || command === '-h' || flags.help) {
    console.log(USAGE_TEXT);
    return;
  }

  const opts = antigravitySettings({
    ...(flags.proxy ? { antigravity: { proxy: flags.proxy } } : {})
  });
  const dataDir = antigravityDataDir(opts.dataDir);

  if (command === 'status') {
    const accounts = loadAntigravityAccounts(dataDir);
    const clients = loadOAuthClients({ dataDir });
    const cachePath = path.join(dataDir, HUB_VERSION_FILENAME);
    const cachedBefore = readCachedHubVersion(dataDir);
    const ua = await resolveAntigravityUserAgents({ dataDir });
    const cached = cachedBefore || readCachedHubVersion(dataDir);
    console.log(`Data directory: ${dataDir}`);
    console.log(`Egress User-Agent: ${ua.egressUserAgent} (source=${ua.source})`);
    console.log(`OAuth User-Agent: ${ua.oauthUserAgent}`);
    if (cached) {
      console.log(`Hub version cache: ${cachePath} (version=${cached.version}, cl=${cached.cl}, source=${cached.source})`);
    } else if (fs.existsSync(cachePath)) {
      console.log(`Hub version cache: ${cachePath} (invalid/ignored)`);
    } else {
      console.log('Hub version cache: none');
    }
    console.log(`Configured OAuth clients: ${clients.size}`);
    console.log(`Saved accounts: ${accounts.length}`);
    for (const acc of accounts) {
      console.log(`- ${acc.email} (${acc.tier || 'FREE'}, ${acc.clientType}, project=${acc.projectId})`);
    }
    return;
  }

  if (command === 'sync-ua') {
    if (flags.localOnly || flags.installDir) {
      const detected = await detectLocalAntigravityFingerprint({
        dataDir,
        ...(flags.installDir ? { installDir: flags.installDir } : {}),
        persist: true
      });
      if (!detected) {
        console.error(
          `No valid paired Antigravity Hub version/CL fingerprint found locally${flags.installDir ? ` in ${flags.installDir}` : ''}. ` +
          'Run without --local-only to sync from the official download page.'
        );
        process.exitCode = 1;
        return;
      }
      const ua = await resolveAntigravityUserAgents({ dataDir, detectLocal: false });
      console.log(`Version: ${detected.version}`);
      console.log(`CL: ${detected.cl}`);
      console.log(`OAuth User-Agent: ${detected.oauthUserAgent || ua.oauthUserAgent}`);
      console.log(`Source: ${detected.source || 'local'}`);
      if (detected.binaryPath) console.log(`Binary path: ${detected.binaryPath}`);
      console.log(`Egress User-Agent: ${ua.egressUserAgent} (source=${ua.source})`);
      console.log(`Saved cache: ${path.join(dataDir, HUB_VERSION_FILENAME)}`);
      return;
    }

    let synced;
    try {
      synced = await syncHubVersionFromOfficial({
        dataDir,
        proxy: opts.proxy || undefined
      });
    } catch (err) {
      console.error(`Failed to sync Antigravity User-Agent from official download page: ${err?.message || err}`);
      console.error('Tip: pass --proxy http://... if needed, or run with --local-only to scan a local Antigravity installation.');
      process.exitCode = 1;
      return;
    }
    if (!synced || !synced.version || !synced.cl) {
      console.error('Official download sync did not return a valid paired version and CL.');
      process.exitCode = 1;
      return;
    }
    const ua = await resolveAntigravityUserAgents({ dataDir, detectLocal: false });
    console.log(`Version: ${synced.version}`);
    console.log(`CL: ${synced.cl}`);
    console.log(`OAuth User-Agent: ${synced.oauthUserAgent || ua.oauthUserAgent}`);
    console.log(`Source: ${synced.source || 'official-sync'}`);
    if (synced.archiveUrl) console.log(`Archive URL: ${synced.archiveUrl}`);
    console.log(`Egress User-Agent: ${ua.egressUserAgent} (source=${ua.source})`);
    console.log(`Saved cache: ${path.join(dataDir, HUB_VERSION_FILENAME)}`);
    return;
  }

  if (command === 'oauth') {
    if (!flags.clientId || !flags.clientSecret) {
      console.error('Usage: node scripts/antigravity.mjs oauth --client-id <id> --client-secret <secret> [--type personal|enterprise]');
      process.exitCode = 1;
      return;
    }
    const saved = saveOAuthClientCredentials({
      clientType: flags.type || 'personal',
      clientId: flags.clientId,
      clientSecret: flags.clientSecret,
      dataDir
    });
    console.log(`Saved OAuth client [${saved.key}] to ${dataDir}`);
    return;
  }

  if (command === 'login' || command === 'import') {
    let raw = positional.join(' ').trim();
    if (!raw && flags.file) raw = fs.readFileSync(flags.file, 'utf8');
    if (!raw) raw = readStdinText();
    if (!raw) {
      console.error('Usage: node scripts/antigravity.mjs login <refresh_token_or_json> [--type personal|enterprise] [--proxy http://...] [--client-id <id> --client-secret <secret>]');
      process.exitCode = 1;
      return;
    }
    const pkg = parseRefreshTokenPackage(raw);
    const customClientId = flags.clientId || pkg.clientId;
    const customClientSecret = flags.clientSecret || pkg.clientSecret;
    for (const rt of pkg.tokens) {
      const acc = await verifyRefreshToken(rt, {
        clientType: flags.type || 'personal',
        proxy: opts.proxy || undefined,
        ...(customClientId && customClientSecret ? { customClientId, customClientSecret } : {}),
        dataDir
      });
      saveAntigravityAccount(acc, dataDir);
      console.log(`Imported ${acc.email} (${acc.tier}, project=${acc.projectId}, models=${acc.modelsCount})`);
    }
    if (customClientId && customClientSecret) {
      saveOAuthClientCredentials({
        clientType: flags.type || 'personal',
        clientId: customClientId,
        clientSecret: customClientSecret,
        dataDir
      });
    }
    return;
  }

  if (command === 'remove' || command === 'rm') {
    const target = positional[0];
    if (!target) {
      console.error('Usage: node scripts/antigravity.mjs remove <email>');
      process.exitCode = 1;
      return;
    }
    const removed = removeAntigravityAccount(target, dataDir);
    console.log(removed ? `Removed ${target}` : `Account not found: ${target}`);
    return;
  }

  if (command === 'quota' || command === 'models' || command === 'smoke') {
    const accounts = loadAntigravityAccounts(dataDir);
    if (accounts.length === 0) {
      console.error('No saved Antigravity accounts. Run antigravity:login first.');
      process.exitCode = 1;
      return;
    }
    const getAuth = async () => ({
      type: 'api',
      key: accounts[0].refreshToken,
      metadata: { mode: 'antigravity', accounts: accounts.map(a => a.id) }
    });
    if (command === 'quota') {
      const card = await antigravityUsage(await getAuth(), opts);
      console.log(JSON.stringify(card, null, 2));
      return;
    }
    if (command === 'models') {
      const models = await listAntigravityModels(await getAuth(), opts);
      for (const m of Object.values(models)) {
        const variants = Object.keys(m.variants || {});
        console.log(`${m.id} (${m.name})${variants.length ? ` [${variants.join(', ')}]` : ''}`);
      }
      return;
    }
    const model = flags.model || 'gemini-3.8-flash-low';
    const res = await forwardAntigravity(`${ANTIGRAVITY_BASE}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'Reply with OK' }],
        stream: false
      })
    }, getAuth, opts);
    console.log('HTTP', res.status);
    console.log(await res.text());
    return;
  }

  console.error(`Unknown command: ${command}`);
  console.error('');
  console.error(USAGE_TEXT);
  process.exitCode = 1;
}

main().catch(err => {
  console.error(err?.message || err);
  process.exitCode = 1;
});
