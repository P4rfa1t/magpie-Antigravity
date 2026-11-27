'use strict';

process.title = 'magpie-antigravity-cleanup';

const fs = require('node:fs');

const cfg = JSON.parse(process.env.MAGPIE_CLEANUP_CFG || '{}');
const {
  magpieDir,
  pluginRoot,
  webDir,
  pidFile,
  mode = 'watch',
  pollMs = 2000
} = cfg;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function removePidFile() {
  if (!pidFile) return;
  try {
    const recorded = Number(fs.readFileSync(pidFile, 'utf8').trim());
    if (recorded === process.pid) {
      fs.rmSync(pidFile, { force: true });
    }
  } catch {}
}

(async () => {
  try {
    // Load the cleanup module into memory immediately on startup so the watcher still has all
    // code in memory even after `bun remove` deletes node_modules/magpie-antigravity from disk.
    const {
      isPluginInMagpie,
      hasDownloadedAssets,
      cleanDownloadedAssets
    } = await import('./cleanup.mjs');

    if (mode === 'immediate') {
      await cleanDownloadedAssets({ webDir });
      return;
    }

    for (;;) {
      const state = isPluginInMagpie(magpieDir, { pluginRoot });
      if (state === false) {
        await cleanDownloadedAssets({ webDir });
        return;
      }
      if (!hasDownloadedAssets({ webDir })) {
        return;
      }
      await sleep(pollMs);
    }
  } catch {
    // Best-effort background cleanup
  } finally {
    removePidFile();
  }
})();
