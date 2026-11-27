# Project Handoff & Technical Analysis (`magpie-Antigravity`)

> 本文档面向后续接手本项目的 AI 模型与开发者，完整汇总独立化后仓库架构、工程红线、`Antigravity` 直连供应商协议与防封伪装机制、隐式缓存诊断、全量配置参考、`Gemini Web` 共享基础设施，以及已验证结论与待办边界。

---

## 1. 独立项目概览与双 Provider 架构

`magpie-Antigravity`（npm 包名 `magpie-antigravity`，当前版本 `1.0.0`）现为 `P4rfa1t/magpie-Antigravity` 独立维护仓库，面向 **Magpie** 与 **OpenCode** 提供零外部 npm 依赖的 Google 模型接入能力（仅使用 `node:*` 内置模块，兼容 `Node >= 22` 与 Magpie 内置 `Bun` 运行时；`bun:sqlite` 仅在 `lib/usage.mjs` 按 `globalThis.Bun` 条件加载）。

> **独立化变更说明**：仓库已移除原 AI Studio (`ai-studio` / `AIStudio2API`) 相关代码、补丁、脚本与测试，并将共享进程身份校验函数（`verifyProcessIdentity`、`processPids`、`listenerPids`）迁移至 `lib/proc.mjs`。当前以 **Antigravity** 为核心主力，同时保留 **Gemini Web** 作为网页版 Cookie 补充通道。

入口 `index.mjs` 导出两个相互独立、可共存的 Provider 插件：

| 导出名 | Provider ID | 底层通道与运行方式 | 核心代码入口 |
| :--- | :--- | :--- | :--- |
| `AntigravityPlugin`（主力核心） | `antigravity-rt` | **纯 JS 直连 Google Cloud Code `v1internal`**，OAuth Refresh Token (`1//...`) 鉴权，免本地二进制 | `lib/antigravity.mjs`, `lib/antigravity-mapper.mjs`, `lib/antigravity-oauth.mjs`, `lib/antigravity-ua.mjs`, `lib/antigravity-ua.json`, `lib/antigravity-protocol.json`, `scripts/antigravity.mjs`, `scripts/sync-antigravity-protocol.mjs` |
| `GeminiWebPlugin`（默认导出） | `gemini-web` | 管理本机 `gemini-web2api-go` 守护进程，通过浏览器无痕窗口 Cookie 访问网页版 Gemini | `index.mjs`, `lib/backend.mjs`, `lib/native.mjs`, `lib/proc.mjs`, `lib/setup.mjs`, `lib/cite.mjs`, `lib/usage.mjs`, `lib/cleanup.mjs` |

---

## 2. 接手必读：工程红线与静态护栏

任何修改提交前**必须**满足 `AGENTS.md` 与 `scripts/check-guardrails.mjs`（`npm run check`）强制执行的 6 条静态规则：

1. **零外部依赖 (`no-external-or-bare-imports`)**：只能 `import` 带 `node:` 前缀的内置模块（`bun:sqlite` 仅限 `lib/usage.mjs` 动态导入）。
2. **严格模块分层 (`layer-boundary`)**：`lib/` 绝不能反向导入 `index.mjs`、`scripts/` 或 `test/`；`index.mjs` 绝不能导入 `scripts/` 或 `test/`；`scripts/` 绝不能导入 `test/`。
3. **打包闭包自洽 (`closed-package-files-graph`)**：`package.json` 的 `"files"` 白名单中所有发布文件引用的相对模块必须同样位于 `"files"` 中，且严禁打包 `.env`、`*secret*`、`*.db` 或 `backend-build`。
4. **禁止裸 `process.kill(pid, 0)` (`no-raw-kill-zero`)**：除 `lib/proc.mjs` 外严禁直接探测 PID，必须使用 `lib/proc.mjs` 的 `processAlive` / `processExists` / `zombie` / `verifyProcessIdentity`。
5. **全仓 Unix LF 换行 (`unix-shebang-lf`)**：所有源码、工作流、文档必须保持 `\n` 换行（Windows 下编辑尤需注意）。
6. **文档路径真实有效 (`agents-doc-links-valid`)**：`AGENTS.md` 中出现的每一个仓库相对路径都会被校验存在性。

常用验证命令：
```bash
npm run check                                                # 静态护栏校验
npm test                                                     # 运行全量单元测试
node --test test/antigravity.test.mjs test/antigravity-ua.test.mjs test/guardrails.test.mjs
npm run interrogate -- --brief                               # 推导受影响子系统、风险清单与测试命令
npm run interrogate -- --run                                 # 执行护栏 + 映射测试 + npm pack --dry-run
```

---

## 3. `Antigravity` 子系统深度拆解

### 3.1 认证、凭据存储与网络代理 (`lib/antigravity-oauth.mjs`)

- **零硬编码 OAuth Secret**：源码中绝不提交 Google OAuth `client_id` / `client_secret`。读取优先级：插件选项 `options.antigravity` > 环境变量 > 本机 `${dataDir}/oauth-clients.json`（默认 `~/.local/share/magpie-antigravity`，`ANTIGRAVITY_DATA_DIR` 覆盖）> 导入 JSON 包内嵌凭据（验证成功后自动以 `0o700`/`0o600` 落盘）。
- **浏览器 OAuth 2.0 + PKCE 授权流程 (`buildOAuthAuthorizeUrl`, `startOAuthCallbackServer`, `parseOAuthCallbackInput`, `exchangeAuthorizationCode`, `verifyAuthorizationCode`)**：对齐 Antigravity Tools 的双模授权体验：
  - 使用 `https://accounts.google.com/o/oauth2/v2/auth`、`S256` PKCE、`state`（`crypto.timingSafeEqual` 校验）、`access_type=offline`、`prompt=consent` 与全部 5 个官方 Scope（`cloud-platform`、`userinfo.email`、`userinfo.profile`、`cclog`、`experimentsandconfigs`）。
  - 自动模式启动双栈本地回环回调服务（`127.0.0.1` 随机端口 + best-effort `::1` 同端口，`http://localhost:<port>/oauth-callback`），响应安全 HTML 并关闭连接（`closeAllConnections`）；手动兜底模式使用固定端口 `51121`（`DEFAULT_MANUAL_OAUTH_PORT`）并支持粘贴完整回调 URL、查询串或裸 Authorization Code。
  - 按账号类型严格匹配客户端凭据（`resolveOAuthClientForType` / `hasConfiguredOAuthClientForType`），并在拿到 `refresh_token` 后通过共享 `completeAccountVerification` 完成 `:loadCodeAssist` / `:onboardUser` / 模型目录校验与落盘。
- **多格式 Refresh Token 导入 (`parseRefreshTokenPackage`)**：兼容单条 `1//...` Token、Antigravity-Manager 导出的 JSON 数组、旧版插件记录、`agy` 原生 `antigravity-oauth-token` 文件及 `go-keyring-base64:` 编码内容，自动提取并去重。
- **Token 刷新与双客户端绑定 (`ensureFreshAccountToken`)**：在过期前 `10 ~ 18` 分钟随机抖动窗口内刷新短期 `access_token`；仅当未绑定 `oauthClientKey` 或遇到 `unauthorized_client`/`invalid_client` 时切换 Personal / Enterprise（GCP）客户端；已绑定账号遇到 `invalid_grant` 时仅对原绑定客户端做一次瞬态重试，确认失效后标记 `invalidGrant: true` 返回 `401`。
- **上游端点与项目发现**：
  - 主端点：`https://daily-cloudcode-pa.googleapis.com/v1internal`（默认不探测 `sandbox.googleapis.com`，仅在显式开启 `sandboxFallback` / `ANTIGRAVITY_SANDBOX_FALLBACK=1` 时启用回退）。
  - 登录校验时调用 `:loadCodeAssist` 获取 `cloudaicompanionProject` 与订阅等级（`FREE` / `PRO` / `ULTRA`）；未返回专属项目时自动调用 `:onboardUser`（含长操作轮询）开通个人 `projectId`，无法开通时回退默认 `bamboo-precept-lgxtn`。登录默认不调用 `:setUserSettings({})` / `:fetchUserInfo`（由 `autoPrivacy` / `ANTIGRAVITY_AUTO_PRIVACY=1` 控制）。
  - 支持直连 HTTPS 与 HTTP/HTTPS `CONNECT` 隧道代理（`fetchWithProxy`），Node 运行时自动协商 **ALPN `h2`（`node:http2`）连接池（60s 空闲超时 + `gzip`/`deflate` 解压，请求默认 `accept-encoding: gzip` 对齐官方）**，必要时平滑回退 HTTP/1.1；容器环境下对回环代理给出 `host.docker.internal` 提示。

### 3.2 Magpie 供应商契约、模型目录、配额与容错 (`lib/antigravity.mjs`)

- **账号导入与管理**：支持 Magpie 原生 `auth.import` / `importFroms` 多语言导入、交互式批量粘贴 Refresh Token 登录、以及从本机 `accounts.json` 选择已保存账号。
- **模型目录清洗与聚合 (`buildAntigravityModels`)**：
  - 调用 `:fetchAvailableModels`（按账号缓存 5 分钟）。
  - 过滤 `disabled`、`isInternal`、`tab_*`、`chat_*`、`gemini-2.5-*`、`*-sonar`、`orchestrator`、无标签裸 `*-tiered` 及冗余 `*-tiered-(low|medium|high|...)` 模型。
  - 将 `-minimal/-low/-medium/-high/-xhigh/-max` 变体折叠入同一基础模型 ID 的 `variants`，请求时按 `reasoning_effort` 动态解析。
  - 优先采用上游真实返回的 `info.maxTokens`（例如 `claude-opus-5-5` 与 `claude-sonnet-5-5` 实测为 `1000000`，兜底表 `KNOWN_MODEL_LIMITS` 仅在上游省略时生效）。
- **配额面板 (`parseUsageSummary` / `antigravityUsage`)**：
  - 调用 `:retrieveUserQuotaSummary` 展示 5 小时 / 7 天配额桶（Gemini、Claude & GPT、Argon）。所有窗口均标记 `aside: true`，仅作展示绝不干预 Magpie 路由。
  - 默认 `maxConcurrency: 2`，模拟正常 IDE 双并发（主对话 + 标题生成）。
- **错误与限流精细分流**：
  - **单模型池配额耗尽不锁整号**：`isLongQuotaExhausted` 识别长周期或秒级配额文案（含 `Resets in \d+[hms]`），将单池耗尽 `429` 转为 HTTP `400` 提示切换模型池，避免 Magpie 冻结整号。
  - **短期并发 429/503 退避**：解析 `Retry-After` / `retryDelay` 退避重试；请求体 `> 64KB` 或重试轮次跳过向 sandbox 重传大包。
  - **403 账号风控验证提取 (`verifyLinkIn`)**：提取上游 Google 验证 URL 提示用户浏览器完成验证。
  - **空回复门控、流式空闲止损与签名自愈**：支持可配置 `emptyReplyMaxWaitMs`（HTTP 200 空候选在首个实质分片输出前限时重试，超时返回 `502`）、`streamIdleTimeoutMs`（SSE 卡死超时止损 `504`）、`signatureRectifier`（签名报错时剥离历史签名重试一次）及 `allowOverages`（Google AI Credits 超额头）。

### 3.3 防封伪装、成对 UA 与零凭据协议自动同步

1. **成对 UA 解析与防 Franken-UA 不变量 (`lib/antigravity-ua.mjs`, `lib/antigravity-ua.json`)**：
   - 解析优先级：成对环境变量（必须同时设置 `ANTIGRAVITY_HUB_VERSION` 与 `ANTIGRAVITY_HUB_CL`）> `${dataDir}/hub-version.json` 原子缓存（`0o700`/`0o600`）> 远端清单热同步（默认拉取 `P4rfa1t/magpie-Antigravity` 的 `lib/antigravity-ua.json`）> 内置基线（当前清单：`2.36.0` / `cl=1031268331` / `oauthUserAgent="vscode/1.107.0 (Antigravity/2.8.0)"`，源码常数兜底 `2.35.1` / `1029194470`）。
   - `syncHubVersionFromOfficial` 采用**单遍流式 tar 解析**同时提取 Hub `(version, cl)`、`oauthUserAgent` 并缓存 `language_server` 二进制供后续协议探测复用（无需二次下载归档）。
2. **零凭据线协议自动同步与软告警兜底 (`scripts/sync-antigravity-protocol.mjs`, `lib/antigravity-protocol.json`, `.github/workflows/antigravity-ua-sync.yml`)**：
   - 使用本地 mock HTTPS/HTTP 服务器驱动官方 `language_server` 启动探针（零 Google 凭据），提取真实请求头顺序、Envelope 拓扑、身份行、静态枚举标签（`staticLabels`）及二进制静态信号（有序 `observedEndpoints` / `binarySignals.endpoints` / `oauthScopes`）。
   - `.github/workflows/antigravity-ua-sync.yml` 配置每日 3 个错峰 UTC 定时槽（`23 4 * * *`、`17 12 * * *`、`41 20 * * *`）与并发组 `sync-antigravity`（`cancel-in-progress: false`），并启用 `continue-on-error: true` 软告警模式：更新前执行 `npm run check`、身份字符串一致性测试及协议对齐测试，通过则自动提交推送；若遇破坏性结构漂移或拉取异常，则**跳过推送以防 UA/请求体不匹配**、自动建/评 Issue 并输出 `::warning::`，工作流自身保持绿色。
3. **Envelope 拓扑、自适应协议读取与系统提示词侧载 (`lib/antigravity-mapper.mjs`)**：
   - `OFFICIAL_ANTIGRAVITY_IDENTITY`、`BUNDLED_USER_AGENT_FIELD` 与 `BUNDLED_STATIC_LABELS`（通过 `buildOfficialLabels` 合并静态标签且不覆盖动态键）均直接从 `lib/antigravity-protocol.json` 自动适配读取（缺失时回退内置常数），官方新增静态标签或微调身份行时无需手动改代码即可自动过测推送。
   - 外层 Envelope 严格保持 `['project', 'requestId', 'request', 'model', 'userAgent', 'requestType']`；`innerRequest` 键序固定为 `contents -> systemInstruction -> tools -> toolConfig -> labels -> generationConfig -> sessionId`。
   - `tools` 打包进单个 `[{ functionDeclarations }]`；`requestId` 为 `agent/<convUuid>/<ts>/<trajectoryUuid>/<step>`，其中 `step = contents.length`、`labels.last_step_index = contents.length - 1`、`labels.request_id = <trajectory_id>-<已完成 model 回合数>`，同会话同一账号复用 `trajectory_id`（多号 failover 严格按账号隔离）。
   - 第三方长指令或 Agent 提示词通过侧载进入 `contents[0].parts[0]` 的 `<instructions>...</instructions>`，而 `innerRequest.systemInstruction` 仅保留官方 `OFFICIAL_ANTIGRAVITY_IDENTITY`；`buildCloakLineRe` 在代码块外（`transformOutsideCodeBlocks`）穿透零宽字符改写 Claude Code / Codex / OpenCode / Hermes / pi / RFC 2119 等敏感特征句。
   - `loadSignatureStore(dataDir)` 维护 10,000 条内存 LRU + `${dataDir}/signature-cache.json`（7 天 TTL），并在缺失 `tool_call.id` 时生成确定性 ID。

---

## 4. 隐式前缀缓存诊断与 Prompt 精简策略

- **缓存边界**：Google Cloud Code 隐式前缀缓存按**前缀字节精确匹配 + `2048` tokens 块量化**命中。插件通过 100% 确定性前缀序列化与按会话锚点隔离的负 64 位整数 `sessionId`（`deriveConversationAnchor` + `deriveUpstreamSessionId`）决定命中上限。
- **生产日志（2026-11-23 CSV，`antigravity-rt` 506 行）结论**：
  - 正常对话（`kind == ""`，377 次）命中率 **`83.4%`**，稳定 tool loop 单轮达 **`97.5% ~ 99.7%`**（新对齐实测 66k+ 3 轮可达 **`99.77% ~ 99.85%`**）。
  - `auto_mode_check_inferred`（72 次）因客户端每次重拼滑动摘要导致命中率仅 **`0.6%`**，消耗了全天 `35.7%` 的未缓存输入（\$10.758 / \$43.6313）。
  - 偶发回落 `61k` 前缀主要由旧版未隔离 `sessionId` 跨对话冲刷 KV 或客户端主动修改历史消息（`dtot < 0`）引起。
- **已落地保护与裁剪**：
  1. 在 `stripFingerprintNoise` 中提前剥离 `x-anthropic-billing-header`（防止动态 `cch=` 扰动会话锚点）；
  2. 无损剔除 JSON Schema 冗余 `'title'` 元数据键、空白 `description` 及代码块外行尾空格，并对连续开场 `system`/`developer` 去重；
  3. `fitToolDeclarations`（默认预算 `18000` tokens）在超限时确定性剥离末尾 `Examples:` 并等比收敛工具描述，保留全部工具名、`enum` 与 `required`；`compactPrompt` 可选进一步剔除 `<example>` 块并收紧预算至 `12000`。

---

## 5. `Antigravity` 配置项与 CLI 运维速查

### 5.1 全量 `options.antigravity`（28 项）与环境变量

| 插件选项 (`antigravity.*`) | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `proxy` | `ANTIGRAVITY_PROXY` | `""` | HTTP/HTTPS 代理 URL |
| `dataDir` | `ANTIGRAVITY_DATA_DIR` | `~/.local/share/magpie-antigravity` | 本机状态与缓存目录 |
| `uaManifestUrl` | `ANTIGRAVITY_UA_MANIFEST_URL` | `https://raw.githubusercontent.com/P4rfa1t/magpie-Antigravity/main/lib/antigravity-ua.json` | 远端 UA 清单地址（`off`/`false`/`0` 关闭） |
| `detectLocal` | `ANTIGRAVITY_DETECT_LOCAL` | `false` | 设 `1`/`true` 扫描本机 Antigravity 客户端 |
| `clientId` / `clientSecret` | `ANTIGRAVITY_OAUTH_CLIENT_ID` / `ANTIGRAVITY_OAUTH_CLIENT_SECRET` | — | Personal OAuth 客户端凭据 |
| `gcpClientId` / `gcpClientSecret` | `ANTIGRAVITY_GCP_CLIENT_ID` / `ANTIGRAVITY_GCP_CLIENT_SECRET` | — | Enterprise / GCP 客户端凭据 |
| `allowTools` / `allowImages` / `imageModels` | — | `true` | 工具调用、读图与生图模型开关 |
| `contextLimit` / `outputLimit` | — | 上游上限 | 上报客户端的最大上下文 / 输出 token |
| `requestTimeoutMs` / `modelTimeoutMs` | — | `570000` / `15000` | 生成超时与模型目录超时（毫秒） |
| `compactPrompt` | `ANTIGRAVITY_COMPACT_PROMPT` | `false` | 激进精简系统 `<example>` 并设工具预算 `12000` |
| `toolTokenBudget` | `ANTIGRAVITY_TOOL_TOKEN_BUDGET` | `18000` | 工具描述 token 预算（`0` / `off` 关闭） |
| `failoverOnError` | `ANTIGRAVITY_FAILOVER` | `true` | `429`/`503`/`403`/`401` 自动同请求轮换账号 |
| `emptyReplyMaxWaitMs` / `emptyReplyRetryDelayMs` | `ANTIGRAVITY_EMPTY_REPLY_MAX_WAIT_MS` / `ANTIGRAVITY_EMPTY_REPLY_RETRY_DELAY_MS` | `0` / `1500` | HTTP 200 空候选限时重试门控与延迟 |
| `streamIdleTimeoutMs` | `ANTIGRAVITY_STREAM_IDLE_TIMEOUT_MS` | `0` | SSE 分片间最大空闲超时（`0` 关闭） |
| `signatureRectifier` | `ANTIGRAVITY_SIGNATURE_RECTIFIER` | `true` | 签名报错自动剥离重试一次 |
| `silenceBoundary` | `ANTIGRAVITY_SILENCE_BOUNDARY` | `false` | 注入静默身份边界声明 |
| `userProjectHeader` | `ANTIGRAVITY_USER_PROJECT_HEADER` | `auto` | `x-goog-user-project` 头策略 |
| `claudeBetaHeader` | `ANTIGRAVITY_CLAUDE_BETA_HEADER` | `""` | Claude `anthropic-beta` 透传值 |
| `allowOverages` | `ANTIGRAVITY_OVERAGES` | `false` | 允许 Google AI Credits 超额请求头 |
| `sandboxFallback` | `ANTIGRAVITY_SANDBOX_FALLBACK` | `false` | 主端点异常时允许回退 `sandbox.googleapis.com` |
| `autoPrivacy` | `ANTIGRAVITY_AUTO_PRIVACY` | `false` | 登录时自动调用 `:setUserSettings({})` 与 `:fetchUserInfo` |

另支持纯环境变量：`ANTIGRAVITY_OAUTH_CLIENTS`、`ANTIGRAVITY_INSTALL_DIR`、`ANTIGRAVITY_IDE_INSTALL_DIR`、`ANTIGRAVITY_HUB_VERSION` + `ANTIGRAVITY_HUB_CL`（必须成对）、`ANTIGRAVITY_OAUTH_USER_AGENT`、`ANTIGRAVITY_NORMALIZE_IDENTITY`（默认开启）。

### 5.2 本地 CLI (`scripts/antigravity.mjs`, `scripts/sync-antigravity-protocol.mjs`)

```bash
npm run antigravity:status
npm run antigravity:sync-ua -- [--remote | --local-only | --proxy http://127.0.0.1:7890]
npm run antigravity:sync-protocol -- [--binary <path>] [--write] [--force]
npm run antigravity:oauth -- --client-id <ID> --client-secret <SECRET>
npm run antigravity:oauth-login -- [--type personal|enterprise] [--proxy http://127.0.0.1:7890] [--no-browser] [--code <url_or_code>]
npm run antigravity:login -- --file exported-accounts.json
npm run antigravity:models
npm run antigravity:quota
npm run antigravity:smoke -- --model gemini-3.8-flash-low
```

---

## 6. `Gemini Web` 子系统与共享基础设施

- **进程与容器守护 (`lib/proc.mjs`)**：集中实现 `zombie`（读取 `/proc/<pid>/stat` 处理容器 PID 1 下 `Z`/`X` 状态）、`processAlive`/`processExists`、`verifyProcessIdentity`、`processPids`、`listenerPids` 与 `dockerProxyHint`。
- **本地后端生命周期 (`lib/native.mjs`, `lib/backend-release.json`, `patches/argon.patch`)**：管理 `gemini-web2api-go` 下载、SHA-256 校验、`.setup.lock` 互斥、健康检查、官方 `v4.31.0` 回退及自建优化版发布流程（见 `docs/backend-release.md`）。
- **请求转发、引用剥离与清理 (`lib/backend.mjs`, `lib/setup.mjs`, `lib/cite.mjs`, `lib/usage.mjs`, `lib/cleanup.mjs`, `lib/cleanup-detached.cjs`)**：负责 OpenAI 兼容转发、`[cite: ...]` 流式/整包剥离、用量读取，以及插件卸载后的脱离式后台清理（仅清理 `bin/` 保留 `gemini.db`/`config.json`/`secrets.json`）。

---

## 7. 实测结论、硬边界与后续开放事项

### 7.1 已验证结论（v2.35.2 上游抓包与真机端到端验证）

- **全链路实测通过**：OAuth `/token`（`expires_in: 3599`）、`:loadCodeAssist`、`:fetchAvailableModels`（41 模型，5h 耗尽时 Gemini 模型省略 `remainingFraction` 仅返 `resetTime`）、`:retrieveUserQuotaSummary`（5h/weekly 桶）、隐式缓存（66k+ 3 轮工具循环命中率 `99.77%~99.85%`）、`gpt-oss-120b-medium`、Claude 5.5 工具循环、Gemini 3.8 Flash 签名持久化（`signature-cache.json`）与 `gemini-3.1-flash-image` 均已验证 HTTP 200。
- **429 池耗尽报文实测**：返回 `text/event-stream` 且**无 `Retry-After` 头**，正文含 `QUOTA_EXHAUSTED`、`quotaResetDelay`（如 `13m9s`）与 `retryDelay`；`isLongQuotaExhausted` 已兼容 `<1m` 秒级冷却并验证迅速返回 HTTP `400` 解耦账号锁死。
- **官方 `language_server` 孤立探针验证**：确认同 cascade 多轮 `trajectory_id` 恒定、`requestId` 末段取 `contents.length`、`last_step_index = contents.length - 1`、`labels.request_id` 为 `<trajectory>-<turn>`；取消操作直接断开 SSE，不发额外取消 RPC。

### 7.2 已知硬边界与待办项

- **纯 JS 层硬边界**：Node/Bun 的 TLS JA3/JA4 与官方 Go `language_server`（`JA3 03117a8ed39ef02427ebbc39f121275c` / `JA4 t13d1312h1_f57a46bbacb6_f50d94e863eb`）存在固有差异；伴生 RPC（`:writeTrajectoryAcls`、`:listExperiments`）默认未模拟。
- **待跟进工程项**：
  1. **CI Runner 与 Action 升级**：持续观察 `macos-15-intel` 队列排队情况，适时将 `.github/workflows/*.yml` 中的 `actions/checkout@v4` / `actions/setup-node@v4` 升级至 Node 24 运行时版本。
  2. **可选 `checkpoint` 标题生成请求**：官方部分 cascade 会附带 `requestType: "checkpoint"` 轻量请求，当前未模拟，可视后续风控观测决定是否引入。
  3. **Gemini Web 优化版二进制发布**：独立仓库下如需默认下载 `4.31.0-magpie.2`（`lib/backend-release.json` 已指向 `P4rfa1t/magpie-Antigravity`），需触发 `.github/workflows/backend.yml` 与 `publish-backend.yml` 上传对应 tag 二进制，否则用户需使用 `npm run backend:install:upstream` 或 `npm run backend:build:argon`。
  4. **上游 WAF 规则与 `503 MODEL_CAPACITY_EXHAUSTED` 抓包**：持续对照社区 Cloak 规则同步新增特征词，并补充真实 `503` 现场样本单测。
