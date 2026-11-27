# <img src="docs/logo.svg" width="28" height="28" align="top" alt="" /> magpie-gemini-web

[![Test Suite](https://github.com/P4rfa1t/magpie-gemini-web/actions/workflows/test.yml/badge.svg)](https://github.com/P4rfa1t/magpie-gemini-web/actions/workflows/test.yml) [![UA & Protocol Sync](https://github.com/P4rfa1t/magpie-gemini-web/actions/workflows/antigravity-ua-sync.yml/badge.svg)](https://github.com/P4rfa1t/magpie-gemini-web/actions/workflows/antigravity-ua-sync.yml) [![Magpie Plugin](https://img.shields.io/badge/Magpie-Plugin-3b82f6?style=flat-square)](https://usemagpie.ai/) [![Node.js >= 22](https://img.shields.io/badge/node-%3E%3D22-8b5cf6?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/) [![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-6366f1?style=flat-square)](https://github.com/P4rfa1t/magpie-gemini-web) [![License: MIT](https://img.shields.io/badge/license-MIT-10b981?style=flat-square)](LICENSE)

[中文](README.md) | English | [Contributing & Issue Guide](CONTRIBUTING.md) | [Technical Handoff](HANDOFF.md)

A standalone, zero-dependency Google model provider plugin for [Magpie](https://usemagpie.ai/) and **OpenCode**. Centered on **Antigravity (RT)** (`antigravity-rt`) — direct Node/Bun access to Google Cloud Code `v1internal` using OAuth Refresh Tokens with **no local binary** and no extra CLI system-prompt overhead, delivering **Gemini 4**, **Claude 5.5**, **GPT-OSS**, native function calling, image generation, high-hit implicit prefix caching, and automated daily zero-credential UA/protocol synchronization — alongside **Gemini Web** (`gemini-web`) as an optional web-cookie channel.

> **Standalone Repository Notice:** `P4rfa1t/magpie-gemini-web` is now maintained as an independent repository (no longer a fork). The legacy AI Studio (`ai-studio`) module has been removed to focus cleanly on **Antigravity (RT)** reliability, protocol alignment, and **Gemini Web** support.

---

## Which Provider Should I Choose?

The plugin provides two independent providers that can be used individually or side by side:

| Feature | Antigravity (RT) (`antigravity-rt`) — **Primary** | Gemini Web (`gemini-web`) — Web Fallback |
| :--- | :--- | :--- |
| **Best for** | **Primary chat, coding agents, multi-model routing (no local binary)** | Casual chat & reusing web subscription quota |
| **Key models** | `gemini-4-neon`, `gemini-4-hydrogen`, `gemini-4-argon`, `gemini-3.8-flash`, `claude-opus-5-5`, `claude-sonnet-5-5`, `gpt-oss-120b-medium` (live upstream catalog) | `gemini-4-hydrogen` (signed-in, incl. free accounts), `gemini-4-carbon` / `gemini-4-neon` (paid / Ultra), `gemini-3.6-flash`, `gemini-3.5-flash-lite` |
| **Tool calling** | **Native Function Calling** (`$ref` expansion, deterministic budget trimming, persistent `thoughtSignature` LRU) | Prompt-emulated (experimental; Flash often skips tools) |
| **Thinking levels** | `minimal` / `low` / `medium` / `high` / `xhigh` / `max` (auto-folded & mapped per model) | `low` (base) / `medium` (`-thinking-medium`, `gemini-4-argon` only) / `high` (`-thinking` extended thinking) |
| **Image input** | Enabled by default; multimodal chat & PDF `inlineData` | Enabled by default; chat models read images (needs a signed-in cookie) |
| **Image generation** | `gemini-3.1-flash-image` (OpenAI & Gemini Native endpoints) | Not supported |
| **Sign-in method** | **Google OAuth browser authorization** (auto loopback callback / manual callback URL or code paste) & **Refresh Token import** (single / JSON batch) | Copy `cookie` from a private/incognito `gemini.google.com` window |
| **Usage cards** | Syncs **5-hour** & **weekly** quotas (Gemini / Claude & GPT / Argon, informational `aside: true`) | Syncs **5-hour** & **weekly** usage and reset times from the web |
| **Local dependency** | **None required** (direct Node/Bun fetch to `v1internal` with ALPN `h2` proxy pooling) | `gemini-web2api-go` (local Go daemon; supports official upstream or self-built optimized binary) |

---

## Quick Start

### Install the Plugin

Clone this repository locally and register it in Magpie (or add via Git URL):

```bash
git clone https://github.com/P4rfa1t/magpie-gemini-web.git
magpie plugin add ./magpie-gemini-web
```

> Exported symbols: `GeminiWebPlugin` (default export) and `AntigravityPlugin` (named export). Zero runtime or dev npm dependencies; supports Node.js >= 22 and Magpie's built-in Bun runtime.

---

### Option 1: Antigravity (RT) (`antigravity-rt` — Recommended)

1. Under **From plugins** in Magpie, select **Antigravity (RT)** (uses a dedicated ID so it does not collide with Magpie's built-in `Antigravity` subscription) and choose one of the sign-in flows:
   - **「通过 Google OAuth 浏览器授权登录（推荐）」** (Browser OAuth with auto loopback callback): starts a local listener on `http://localhost:<port>/oauth-callback`, opens Google sign-in in your browser, and automatically captures the callback to exchange for a Refresh Token;
   - **「通过 Google OAuth 授权（手动粘贴回调链接 / Code）」** (auto-promoted first inside containers): open the OAuth URL in any local browser, then paste the redirected callback URL (or raw authorization code) into Magpie;
   - **「通过 Refresh Token 登录（支持批量）」**: paste a single `1//03...` token, JSON array `[{"refresh_token":"1//03..."}, ...]`, or any text containing tokens (compatible with Antigravity Tools / Antigravity-Manager exports).
2. Choose your account type (**Personal** for standard Gmail accounts, or **Enterprise / GCP (Vertex AI)**) and optionally enter a proxy URL (the browser sign-in page reaches Google directly; token exchange and API traffic use your configured proxy, also configurable via `ANTIGRAVITY_PROXY` or `antigravity.proxy`).
3. **Provide matching Google OAuth client credentials** (no `client_id` / `client_secret` are hardcoded in this repo) via any of:
   - Enter them in the interactive sign-in prompts (saved per account type to `~/.local/share/magpie-antigravity/oauth-clients.json` after verification);
   - Set `ANTIGRAVITY_OAUTH_CLIENT_ID` / `ANTIGRAVITY_OAUTH_CLIENT_SECRET` (optional `ANTIGRAVITY_GCP_CLIENT_ID` / `ANTIGRAVITY_GCP_CLIENT_SECRET`, or `ANTIGRAVITY_OAUTH_CLIENTS`);
   - Pre-configure via CLI: `npm run antigravity:oauth -- --client-id <id> --client-secret <secret>`;
   - Or include `client_id` and `client_secret` inside your pasted Refresh Token JSON payload.
4. The plugin exchanges the token for a short-lived `access_token`, provisions or resolves `cloudaicompanionProject` via `:loadCodeAssist` / `:onboardUser`, validates models, and saves accounts locally to `~/.local/share/magpie-antigravity/accounts.json` with `0o700`/`0o600` permissions (`ANTIGRAVITY_DATA_DIR` overrides this path).

#### Key Capabilities

- **Wire-Protocol Parity & Daily Zero-Credential Sync:** Continuously aligned against official `language_server` captures (`tools` single-wrapper packing, `requestId` / `trajectory_id` / `last_step_index`, `labels`, header ordering, and `accept-encoding: gzip`). GitHub Actions (`.github/workflows/antigravity-ua-sync.yml`) runs daily single-pass archive extraction and zero-credential protocol probing, opening an alert issue if upstream drift breaks parity tests.
- **High-Hit Implicit Prefix Caching:** Derives a deterministic 64-bit `sessionId` per conversation anchor (isolating main chats, subagents, and background checks), strips dynamic `x-anthropic-billing-header` noise, removes schema `title` clutter, applies deterministic tool-description budget trimming (`fitToolDeclarations`), and persists `thoughtSignature` entries in a 10k LRU + `signature-cache.json`.
- **Multi-Account Failover & Quota Pool Isolation:** Supports per-request multi-account rotation (`failoverOnError`) and converts single-pool long-cooldown `429` exhaustion into HTTP `400` guidance so Magpie does not lock out other healthy model pools on the same account.

#### Antigravity CLI Commands

```bash
npm run antigravity:status                                     # Inspect dataDir, active Egress/OAuth UAs, cache & saved accounts
npm run antigravity:oauth -- --client-id <ID> --client-secret <SECRET>
npm run antigravity:oauth-login -- --proxy http://127.0.0.1:7890 # Open browser for Google OAuth sign-in (--no-browser / --code supported)
npm run antigravity:login -- "1//03..." --proxy http://127.0.0.1:7890
npm run antigravity:models                                     # Print aggregated models and thinking variants
npm run antigravity:quota                                      # Inspect live 5h / weekly quota buckets
npm run antigravity:smoke -- --model gemini-3.8-flash-low      # Run minimal end-to-end smoke request
npm run antigravity:sync-ua                                    # Stream-extract paired UA from official archive (--remote / --local-only / --proxy)
npm run antigravity:sync-protocol                              # Run zero-credential wire-protocol probe
```

---

### Option 2: Gemini Web (`gemini-web`)

1. Sign in to **Gemini Web** in Magpie and choose **「一键配置本地 Gemini Web（推荐）」** (One-click local setup). Enter an optional proxy URL (e.g. `http://127.0.0.1:7890`) and your **Google account index** (`/u/N/app` -> `N`; leave blank for `0`).
2. Open <https://gemini.google.com/app> in a **private / incognito window** (Firefox recommended):
   1. Press `F12` (`⌥⌘I` on macOS), switch to **Network**, and reload;
   2. Click any `gemini.google.com` request → **Headers** → **Request Headers**, copy the full `cookie` value, and paste it into Magpie;
   3. **Close the private window directly—do not sign out** (signing out invalidates the session).
3. To install the official upstream `gemini-web2api-go` binary (`v4.31.0`) or build the optimized Argon binary from source:
   ```bash
   npm run backend:install:upstream  # Download & verify official v4.31.0 binary
   npm run backend:build:argon       # Or build optimized binary from source (see docs/backend-release.md)
   npm run backend:status            # Inspect local backend status
   ```
   You can also select **「连接已有后端（自定义地址 + API key）」** to point directly at a self-hosted `gemini-web2api-go` instance.

> **Why is a private window required?** `gemini-web2api-go` rotates cookies periodically to keep the session alive. Sharing a session with your daily browser causes Google to invalidate the session and sign your browser out of all Google services.

---

## Configuration & Advanced Usage

<details>
<summary><b>⚙️ Antigravity (RT) Plugin Options & Environment Variables</b> (all 28 `antigravity.*` keys)</summary>

<br>

Configure via `magpie plugin options magpie-gemini-web '{"antigravity":{...}}'` or environment variables:

| Option (`antigravity.*`) | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `proxy` | `ANTIGRAVITY_PROXY` | `""` | HTTP/HTTPS proxy for reaching Google (`http://host.docker.internal:<port>` in Docker) |
| `dataDir` | `ANTIGRAVITY_DATA_DIR` | `~/.local/share/magpie-antigravity` | Local directory for `accounts.json`, `oauth-clients.json`, `signature-cache.json`, `hub-version.json` |
| `uaManifestUrl` | `ANTIGRAVITY_UA_MANIFEST_URL` | `https://raw.githubusercontent.com/P4rfa1t/magpie-gemini-web/main/lib/antigravity-ua.json` | Remote paired UA manifest URL; set `off`/`false`/`0` to disable runtime sync |
| `detectLocal` | `ANTIGRAVITY_DETECT_LOCAL` | `false` | Set `true`/`1` to scan locally installed Antigravity binaries for paired UA |
| `clientId` / `clientSecret` | `ANTIGRAVITY_OAUTH_CLIENT_ID` / `ANTIGRAVITY_OAUTH_CLIENT_SECRET` | — | Personal Google OAuth client credentials |
| `gcpClientId` / `gcpClientSecret` | `ANTIGRAVITY_GCP_CLIENT_ID` / `ANTIGRAVITY_GCP_CLIENT_SECRET` | — | Enterprise / GCP OAuth client credentials |
| `allowTools` / `allowImages` / `imageModels` | — | `true` | Enable function calling, multimodal image input, and image generation models |
| `contextLimit` / `outputLimit` | — | Upstream catalog limits | Optional cap on context / output token limits reported to clients |
| `requestTimeoutMs` / `modelTimeoutMs` | — | `570000` / `15000` | Generation timeout (ms) and model catalog fetch timeout |
| `compactPrompt` | `ANTIGRAVITY_COMPACT_PROMPT` | `false` | Strip `<example>` blocks outside code fences and tighten default tool budget to `12000` |
| `toolTokenBudget` | `ANTIGRAVITY_TOOL_TOKEN_BUDGET` | `18000` (`12000` when compact) | Token budget for tool descriptions; `0` / `off` disables trimming |
| `failoverOnError` | `ANTIGRAVITY_FAILOVER` | `true` | Rotate to next healthy account within the same request on `429`/`503`/`403`/`401` |
| `emptyReplyMaxWaitMs` / `emptyReplyRetryDelayMs` | `ANTIGRAVITY_EMPTY_REPLY_MAX_WAIT_MS` / `ANTIGRAVITY_EMPTY_REPLY_RETRY_DELAY_MS` | `0` / `1500` | Bounded retry window (ms) for HTTP 200 empty-candidate responses (`0` disables) |
| `streamIdleTimeoutMs` | `ANTIGRAVITY_STREAM_IDLE_TIMEOUT_MS` | `0` | Max idle gap (ms) between SSE chunks (`0` disables; returns `504` on stall) |
| `signatureRectifier` | `ANTIGRAVITY_SIGNATURE_RECTIFIER` | `true` | Automatically strip and retry once when upstream rejects stale/corrupt `thoughtSignature` |
| `silenceBoundary` | `ANTIGRAVITY_SILENCE_BOUNDARY` | `false` | Inject silent identity boundary statement into `systemInstruction` |
| `userProjectHeader` | `ANTIGRAVITY_USER_PROJECT_HEADER` | `auto` | `x-goog-user-project` header policy (`auto` / `always` / `never`) |
| `claudeBetaHeader` | `ANTIGRAVITY_CLAUDE_BETA_HEADER` | `""` | Custom `anthropic-beta` header passthrough for Claude models |
| `allowOverages` | `ANTIGRAVITY_OVERAGES` | `false` | Enable Google AI Credits overage header (`x-antigravity-allow-overages`) |
| `sandboxFallback` | `ANTIGRAVITY_SANDBOX_FALLBACK` | `false` | Allow fallback probing to `sandbox.googleapis.com` when primary fails |
| `autoPrivacy` | `ANTIGRAVITY_AUTO_PRIVACY` | `false` | Automatically call `:setUserSettings({})` and `:fetchUserInfo` during sign-in verification |

</details>

<details>
<summary><b>🌐 Gemini Web Options & Backend Management</b></summary>

<br>

| Option | Default | Description |
| :--- | :--- | :--- |
| `allowTools` | `true` | Allow tool calls (`false` returns HTTP `400` on tool requests) |
| `allowImages` | `true` | Allow image input in chat (requires a signed-in cookie) |
| `requestTimeoutMs` / `modelTimeoutMs` | `570000` / `10000` | Backend request and model-list fetch timeouts (ms) |
| `stripCitations` | `true` | Strip `[cite: 1]` and `[cite_start]` markers from replies and tool arguments |
| `proxy` | none | Proxy for managed Gemini Web backend (`GEMINI_WEB_PROXY` or sign-in prompt) |
| `baseURL` | `http://127.0.0.1:8083/v1` | Default Gemini Web backend URL |
| `contextLimit` / `outputLimit` | `1000000` / `8192` | Context and output limits reported to clients |

> **Windows PowerShell note:** `magpie.cmd` strips double quotes inside JSON arguments. Call the underlying binary directly (found via `where.exe magpie`): use `'{"allowImages":true}'` on PowerShell 7.3+ and `'{\"allowImages\":true}'` on Windows PowerShell 5.1.

</details>

<details>
<summary><b>🐳 Docker & Remote Server Deployment</b></summary>

<br>

1. **Prefer Antigravity (RT):** Pure headless OAuth Refresh Token flow requires no local browser, no `127.0.0.1` web UI, and no external binaries.
2. **Container proxy addresses:** Inside bridge-network containers, `127.0.0.1` points to the container itself. Use `http://host.docker.internal:<port>` on Docker Desktop (macOS/Windows) or add `--add-host=host.docker.internal:host-gateway` / `--network host` on Linux.
3. **Persistence & zombie reaping:** Persist `ANTIGRAVITY_DATA_DIR` and `GEMINI_WEB_DATA_DIR` via volumes. When running `gemini-web` with Magpie as PID 1, pass `--init` (`init: true` in Compose); `lib/proc.mjs` also detects Linux `Z`/`X` zombie processes safely.

</details>

<details>
<summary><b>🔒 Security, Data Directories & Uninstall Cleanup</b></summary>

<br>

- **Antigravity data directory:** `~/.local/share/magpie-antigravity` (`ANTIGRAVITY_DATA_DIR`), storing `accounts.json`, `oauth-clients.json`, `signature-cache.json`, and `hub-version.json` with `0o700`/`0o600` permissions.
- **Gemini Web data directory:** `~/.local/share/magpie-gemini-web` (`GEMINI_WEB_DATA_DIR`), bound strictly to `127.0.0.1` with logs at `backend.log`.
- **Automatic uninstall cleanup:** Removing the plugin in Magpie (or running `npm run backend:clean`) stops the managed `gemini-web2api-go` process and deletes downloaded binaries in `bin/`, while preserving `gemini.db`, `config.json`, and `secrets.json`.

</details>

---

## License

MIT (see [LICENSE](LICENSE)). Upstream `gemini-web2api-go` is also MIT (see [LICENSE-UPSTREAM](LICENSE-UPSTREAM)).

---

## Star History

<p align="center">
  <a href="https://www.star-history.com/#P4rfa1t/magpie-gemini-web&amp;Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=P4rfa1t/magpie-gemini-web&amp;type=Date&amp;theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=P4rfa1t/magpie-gemini-web&amp;type=Date" />
      <img alt="GitHub star history for magpie-gemini-web" src="https://api.star-history.com/svg?repos=P4rfa1t/magpie-gemini-web&amp;type=Date" width="800" />
    </picture>
  </a>
</p>
