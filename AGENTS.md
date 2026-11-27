# Repository Agent Guide (`magpie-gemini-web`)

Keep this file compact and link-checked: every path reference is validated by `scripts/check-guardrails.mjs` (`npm run check`).

## 1. Core Architecture & Invariants

- **Zero runtime or dev npm dependencies**: `package.json` keeps empty dependencies so `npm test`, `npm run check`, and published plugin installs run directly on bare `Node >= 22` and `Bun`. Use `node:*` built-ins only (`bun:sqlite` is gated on `globalThis.Bun` in `lib/usage.mjs`).
- **Strict module layering**: `lib/` never imports `index.mjs`, `scripts/`, or `test/`; `index.mjs` never imports `scripts/` or `test/`. Keep `package.json` `files` closure self-contained (`closed-package-files-graph`).
- **Process liveness & identity**: Never probe raw `process.kill(pid, 0)` directly outside `lib/proc.mjs`; use `processAlive`, `processExists`, `zombie`, `verifyProcessIdentity`, `processPids`, and `listenerPids` in `lib/proc.mjs` so Linux `Z`/`X` zombie processes, OS PID reuse, and container proxy warnings (`isContainerEnv`, `dockerProxyHint`) are handled safely.
- **Antigravity (RT) protocol & secret safety**: Never hardcode Google OAuth `client_id` / `client_secret` in source. Keep paired Hub UA (`version` + `cl`) atomic via `lib/antigravity-ua.mjs` and `lib/antigravity-ua.json` (never splice mismatched versions/CLs), and verify wire-protocol parity against `lib/antigravity-protocol.json`.
- **Unix LF everywhere**: Keep `.mjs`, `.cjs`, `.js`, `.yml`, and `.md` files with `\n` endings (`jsconfig.json` enables IDE navigation without TypeScript compile steps).

## 2. Subsystem -> Verification Map

| Subsystem | Primary Code | Verification Target |
| :--- | :--- | :--- |
| Static guardrails & IDE links | `scripts/check-guardrails.mjs`, `jsconfig.json` | `test/guardrails.test.mjs` (`npm run check`) |
| Antigravity (RT) OAuth, mapper & protocol sync | `lib/antigravity.mjs`, `lib/antigravity-mapper.mjs`, `lib/antigravity-oauth.mjs`, `lib/antigravity-ua.mjs`, `lib/antigravity-ua.json`, `lib/antigravity-protocol.json`, `scripts/antigravity.mjs`, `scripts/sync-antigravity-protocol.mjs` | `test/antigravity.test.mjs`, `test/antigravity-ua.test.mjs`, `.github/workflows/antigravity-ua-sync.yml` |
| Process liveness, identity & Docker hints | `lib/proc.mjs` | `test/zombie.test.mjs`, `test/cleanup.test.mjs`, `test/backend.test.mjs` |
| Gemini Web plugin, backend & usage | `index.mjs`, `lib/backend.mjs`, `lib/native.mjs`, `lib/setup.mjs`, `lib/cite.mjs`, `lib/usage.mjs`, `lib/backend-release.json`, `scripts/backend.mjs`, `scripts/backend-argon.mjs`, `scripts/backend-release.mjs`, `scripts/backend-smoke.mjs`, `patches/argon.patch` | `test/backend.test.mjs`, `test/native.test.mjs`, `test/setup.test.mjs`, `test/cite.test.mjs`, `test/usage.test.mjs`, `test/backend-release.test.mjs`, `test/task.test.mjs` |
| Detached uninstall cleanup | `lib/cleanup.mjs`, `lib/cleanup-detached.cjs` | `test/cleanup.test.mjs` |
| Release & npm verification | `scripts/release-plugin.mjs`, `scripts/verify-published-package.mjs` | `test/release-plugin.test.mjs`, `.github/workflows/publish-package.yml`, `.github/workflows/verify-package.yml`, `.github/workflows/backend.yml`, `.github/workflows/publish-backend.yml` |
| Diff interrogation & CI | `scripts/interrogate-diff.mjs` | `test/interrogate-diff.test.mjs`, `.github/workflows/test.yml`, `.github/workflows/antigravity-ua-sync.yml` |

## 3. Rule <-> Enforcer Matrix

| Invariant / Hazard | Local & CI Enforcer |
| :--- | :--- |
| No raw kill-zero probes, layer crossings, bare npm imports, CRLF shebangs, or dangling `AGENTS.md` paths | `scripts/check-guardrails.mjs` (via `npm run check` and `.github/workflows/test.yml`) |
| Antigravity paired UA, zero-credential protocol parity, deterministic cache anchors, and WAF cloak rewrites | `test/antigravity.test.mjs`, `test/antigravity-ua.test.mjs`, `.github/workflows/antigravity-ua-sync.yml` |
| Detached cleanup safety, `.setup.lock` serialization, and stale/zombie PID protection | `test/cleanup.test.mjs`, `test/zombie.test.mjs` |
| Pre-publish cleanliness, backend asset reachability, and converged tag/workflow release | `scripts/release-plugin.mjs` (`npm run release:plugin -- --dry-run`) |

## 4. `Author != Verifier` Interrogation Playbook

1. Inspect touched subsystems and hazard sites before claiming completion:
   ```bash
   npm run interrogate -- --brief
   ```
2. Hand the generated brief plus raw diff to an independent verifier to challenge child-process quoting, liveness edge cases, lock races, Windows/Linux differences, and workflow permissions.
3. Run all mapped checks automatically plus pack dry-run:
   ```bash
   npm run interrogate -- --run
   ```

## 5. `/correct` Workflow (Prevent Repeat Mistakes)

- **Encode fixes mechanically**: Every agent error or bug fix should add a rule in `scripts/check-guardrails.mjs` (if syntactically checkable) or a deterministic regression test in `test/*.test.mjs`.
- **Keep docs lean**: Add only short high-signal pointers here; put full architecture, Antigravity (RT) protocol details, WAF cloaking, and cache/CSV analysis in `HANDOFF.md`, and keep Gemini Web backend build/release instructions in `docs/backend-release.md`.
