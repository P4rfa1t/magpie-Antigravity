# Project Handoff & Technical Analysis (`magpie-gemini-web`)

> 本文档面向后续接手本项目的 AI 模型与开发者，完整汇总仓库架构、核心不变量、`Antigravity (RT)` 直连供应商的协议细节、防封伪装机制、真实请求日志（CSV）缓存分析、Prompt 精简策略以及下一步演进方向。

---

## 1. 项目概览与三大 Provider 架构

`magpie-gemini-web`（当前版本 `0.17.0`）是面向 **Magpie** 与 **OpenCode** 的多合一 Google 模型插件包。全仓遵循 **零外部 npm 依赖** 原则（`package.json` 无 `dependencies` / `devDependencies`，仅使用 `node:*` 内置模块，兼容 `Node >= 22` 与 Magpie 内置 `Bun` 运行时）。

入口文件 `index.mjs` 导出三个相互独立、可共存的 Provider 插件：

| 插件导出名 | Provider ID | 底层通道与运行方式 | 核心代码入口 |
| :--- | :--- | :--- | :--- |
| `GeminiWebPlugin`（默认导出） | `gemini-web` | 管理本机 `gemini-web2api-go` 守护进程，通过浏览器无痕窗口 Cookie 访问网页版 Gemini | `index.mjs`, `lib/backend.mjs`, `lib/native.mjs`, `lib/usage.mjs`, `lib/cleanup.mjs` |
| `AIStudioPlugin` | `google-aistudio` | 管理本机 `AIStudio2API` 后端，含跨宿主文件锁与自动热更新状态机（TLA+ 建模） | `lib/studio.mjs`, `lib/studio-native.mjs`, `lib/studio-updates.mjs`, `docs/models/studio-lock-protocol.tla` |
| `AntigravityPlugin`（近期核心开发项） | `antigravity-rt` | **纯 JS 直连 Google Cloud Code `v1internal` 接口**（无需本机安装或拉起 `agy` CLI 子进程），使用 OAuth Refresh Token（`1//...`）鉴权 | `lib/antigravity.mjs`, `lib/antigravity-mapper.mjs`, `lib/antigravity-oauth.mjs`, `lib/antigravity-ua.mjs`, `scripts/antigravity.mjs` |

---

## 2. 接手必读：工程红线与静态护栏

任何修改在提交前**必须**满足 `AGENTS.md` 与 `scripts/check-guardrails.mjs`（`npm run check`）强制执行的 6 条静态规则：

1. **零外部依赖 (`no-external-or-bare-imports`)**：只能 `import` 带 `node:` 前缀的内置模块（`bun:sqlite` 仅在 `lib/usage.mjs` 中按 `globalThis.Bun` 条件动态加载）。
2. **严格模块分层 (`layer-boundary`)**：`lib/` 绝不能反向导入 `index.mjs`、`scripts/` 或 `test/`；`index.mjs` 绝不能导入 `scripts/` 或 `test/`。
3. **打包闭包自洽 (`closed-package-files-graph`)**：`package.json` 的 `"files"` 白名单中所有发布文件引用的相对模块必须同样位于 `"files"` 中；注意不要把包含密钥或测试大文件的开发文档塞进 `"files"`。
4. **禁止裸 `process.kill(pid, 0)` (`no-raw-kill-zero`)**：除 `lib/proc.mjs` 外严禁直接探测 PID，必须使用 `lib/proc.mjs` 的 `processAlive` / `processExists` / `zombie`（处理 Linux `Z`/`X` 僵尸进程与 PID 复用）。
5. **全仓 Unix LF 换行 (`unix-shebang-lf`)**：所有 `.mjs`、`.cjs`、`.js`、`.yml`、`.tla`、`.md` 必须保持 `\n` 换行（Windows 环境下编辑后尤需注意，CRLF 会导致护栏直接报错）。
6. **文档路径真实有效 (`agents-doc-links-valid`)**：`AGENTS.md` 中出现的每一个仓库相对路径都会被校验存在性。

常用验证命令：
```bash
# 1. 运行静态护栏校验
npm run check

# 2. 运行 Antigravity 与护栏单元测试
node --test test/antigravity.test.mjs test/guardrails.test.mjs

# 3. 按当前 git diff 自动推导受影响子系统、输出审查清单并执行映射测试 + npm pack --dry-run
npm run interrogate -- --brief
npm run interrogate -- --run
```

---

## 3. `Antigravity (RT)` 子系统深度拆解

### 3.1 认证、凭据存储与网络代理 (`lib/antigravity-oauth.mjs`)

- **零硬编码 OAuth Secret**：源码中绝不提交 Google OAuth `client_id` / `client_secret`。读取优先级：插件选项 `options.antigravity` > 环境变量 > 本机数据目录 `~/.local/share/magpie-antigravity/oauth-clients.json`（可通过 `ANTIGRAVITY_DATA_DIR` 覆盖）> 导入 JSON 包内嵌的 `client_id`/`client_secret`（验证成功后自动落盘，后续免填）。
- **多格式 Refresh Token 导入 (`parseRefreshTokenPackage`)**：兼容单条 `1//...` Token、Antigravity-Manager 导出的 JSON 数组、旧版插件记录、`agy` 原生 `antigravity-oauth-token` 文件以及 `go-keyring-base64:` 编码内容，自动提取并去重。
- **Token 刷新与双客户端回退 (`ensureFreshAccountToken`)**：提前 15 分钟刷新短期 `access_token`；仅当未绑定已知 `oauthClientKey` 或遇到明确 `unauthorized_client`/`invalid_client` 时才尝试 Personal / Enterprise（GCP）客户端切换（已绑定账号在遇到 `invalid_grant` 时仅对原绑定客户端做一次瞬态重试，不再盲试另一客户端），确认彻底失效后才标记 `invalidGrant: true` 返回 `401`。
- **上游端点与项目发现**：
  - 主端点：`https://daily-cloudcode-pa.googleapis.com/v1internal`（备用：`https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal`）。
  - 登录校验时调用 `:loadCodeAssist` 获取真实 `cloudaicompanionProject` 与订阅等级（`FREE` / `PRO` / `ULTRA`）；未返回专属项目或命中占位项目名时回退至官方默认 `bamboo-precept-lgxtn`。
  - 支持 HTTP/HTTPS `CONNECT` 隧道代理（`fetchWithProxy`），Node 运行时下对 HTTPS 目标自动协商 **ALPN `h2`（`node:http2`）** 并在需要时平滑回退 HTTP/1.1；容器环境下（`isContainerEnv`）对 `127.0.0.1` 给出 `host.docker.internal` 提示。

### 3.2 Magpie 供应商契约、模型目录与额度展示 (`lib/antigravity.mjs`)

参考并对齐了社区 `magpie-community/plugins`（`packages/agy-cli`）的供应商交互体验：

- **账号导入与管理**：同时支持 Magpie 原生「导入已有登录」（`auth.import` / `importFroms` 多语言提示）、交互式批量粘贴 Refresh Token 登录、以及从本机 `accounts.json` 选择已保存账号。
- **模型目录清洗与聚合 (`buildAntigravityModels`)**：
  - 调用 `:fetchAvailableModels`（按账号缓存 5 分钟）。
  - 过滤 `disabled`、`isInternal`、`tab_*`、`chat_*`、`gemini-2.5-*`、`*-sonar`、`orchestrator`、无标签裸 `*-tiered` 以及已有标准变体的冗余 `*-tiered-(low|medium|high|...)` 模型。
  - 将同族 `-minimal/-low/-medium/-high/-xhigh/-max` 折叠进同一个基础模型 ID（如 `gemini-4-hydrogen`、`claude-opus-5-5`）的 `variants` 中，由请求时的 `reasoning_effort` 动态解析回具体后端模型 ID。
  - **上下文窗口 (`contextLimitForModel`)**：优先读取上游目录真实返回的 `info.maxTokens`（例如 `claude-opus-5-5` 与 `claude-sonnet-5-5` 在 Antigravity 上游实测为 **1M 上下文**；此前曾误用硬编码 `Math.min(..., 200000)` 导致 Magpie 面板显示怪异裸数字或截断，已在 `4ffbc4e` 修复）。
- **配额面板 (`parseUsageSummary` / `antigravityUsage`)**：
  - 调用 `:retrieveUserQuotaSummary` 解析 5 小时 / 7 天配额池窗口（Gemini、Claude & GPT、Argon 等）及每个模型家族的最紧配额条。
  - 所有窗口均标记 `aside: true`：**仅在 Magpie UI 展示剩余百分比与重置时间，绝不锁定或干预 Magpie 路由选择**。
- **并发度说明**：插件声明默认 `maxConcurrency: 2`（模拟正常 IDE 双并发：主对话 + 标题生成/轻量后台请求）；用户在 Magpie 供应商界面手动设置「不限制」或自定义并发数时会覆盖该默认值，但单账号并发过高更容易触发 Google 短期速率限制 `429`。
- **错误与限流精细分流**：
  - **单模型池配额耗尽不锁整号 (`c5f0cc1`)**：当上游返回 `429` 且正文包含长周期池耗尽（如 Claude 池耗尽 `Individual quota reached ... Resets in 2h...`），插件将其转换为 HTTP `400` 并附带中文提示「切换其它模型池（如 Gemini / Claude）继续使用」。原因是若原样返回 `429`，Magpie 网关会冻结整个账号，导致明明还有额度的 Gemini 池也无法使用。
  - **短期并发 429/503 退避 (`ec31289`)**：解析 `Retry-After` / `retryDelay` 退避重试；当请求体 `> 64KB` 或处于重试轮次时跳过向 sandbox 端点重复上传超大请求体。
  - **403 账号风控验证提取 (`verifyLinkIn`)**：提取上游返回的 Google 验证链接，提示用户在浏览器打开完成账号验证。

---

## 4. 防封号与请求体伪装设计（Anti-Ban / WAF Cloaking）

Google `v1internal` 网关会对请求头、JSON 拓扑及 Prompt 文本执行特征检测；命中第三方客户端指纹（哪怕配额充足）也会直接返回裸 `429 Resource has been exhausted (e.g. check quota)`。本项目在 `lib/antigravity-mapper.mjs` 与 `lib/antigravity-oauth.mjs` 中构建了四层防护：

1. **Egress Header 与官方 Envelope 拓扑对齐（含动态 UA 对齐与防 Franken-UA 不变量）**
   - 出站 Hub `User-Agent` 与 OAuth `User-Agent` 由 `lib/antigravity-ua.mjs` 统一解析（`resolveAntigravityUserAgents`），优先级为：
     1. **显式成对环境变量覆盖**：必须同时提供 `ANTIGRAVITY_HUB_VERSION` 与 `ANTIGRAVITY_HUB_CL` 才覆盖 Hub UA（单边设置会被忽略，严禁与内置或缓存字段混拼出「缝合怪 UA / Frankenstein UA」，例如把新版 `2.35.1` 错配旧版 `cl=1023160026`）；`ANTIGRAVITY_OAUTH_USER_AGENT` 可独立覆盖 OAuth 刷新头。
     2. **持久化指纹缓存 `${dataDir}/hub-version.json`（及 Option A 本机自动探测）**：文件格式为 `{ version, cl, oauthUserAgent?, source, detectedAt, binaryPath? | archiveUrl? }`，写入前严格校验 `version`（SemVer）与 `cl`（`^\d{6,}$`）成对存在并以 `0o700` 目录 / `0o600` 临时文件原子重命名落盘；读取时若字段缺失或格式异常则直接丢弃。若缓存缺失且未禁用 `detectLocal`，`detectLocalAntigravityFingerprint` 会以带 TTL 节流的非联网方式扫描 `ANTIGRAVITY_INSTALL_DIR` 及 Windows/macOS/Linux 标准 Antigravity 安装目录中的 `language_server*` / `antigravity` 二进制（分块流式 + 重叠尾缓冲）与 `product.json`/`package.json`，提取到有效成对指纹即落盘 `source: 'local'`。
     3. **内置成对基线**：`OFFICIAL_HUB_VERSION = '2.33.0'` + `OFFICIAL_HUB_CL = '1023160026'` + `NATIVE_OAUTH_USER_AGENT = 'vscode/1.99.0 (Antigravity/4.3.0)'`。
   - **Option C 官方归档流式同步 (`syncHubVersionFromOfficial`)**：当本机未安装官方客户端时，可通过 `npm run antigravity:sync-ua` 从 `https://antigravity.google/download` 解析官方下载链接（`parseOfficialDownloadPage` 优先选择 `linux-x64/Antigravity.tar.gz`），通过 `node:zlib` `createGunzip()` + 零依赖流式 tar 解析器扫描候选中文件；一旦提取到成对 `(version, cl)` 即刻通过 `AbortController` 中止下载流并原子写入 `${dataDir}/hub-version.json`（`source: 'official-sync'`）。
   - 外层 Envelope 严格保持 `['project', 'requestId', 'request', 'model', 'userAgent', 'requestType']`（个人 Gmail 为 `userAgent: 'antigravity'`，企业号为 `'jetski'`；存在工具上下文时带 `requestType: 'agent'`）。
   - `innerRequest` 字段顺序固定为：`contents -> systemInstruction -> tools -> toolConfig -> labels -> generationConfig -> sessionId`。
   - `requestId` 采用 `agent/<deterministicConvUuid>/<timestamp>/<trajectoryUuid>/<step>`：同一用户主回合及其后续工具调用轨迹复用确定性 `trajectoryUuid`（直到开启下一个用户提问才推进），且 `requestId` 末段 `step`、`labels.last_step_index` 与 `labels.request_id` 统一采用已完成的 `model` 回合数；不注入虚假的 `safetySettings`。
2. **第三方 Agent 系统提示词侧载（System Prompt Sideloading）**
   - 当检测到长系统提示词或包含 `rule|instruction|agent|tool|guideline|context` 的第三方 Agent 指令时，`innerRequest.systemInstruction` 仅发送纯净的官方身份 `OFFICIAL_ANTIGRAVITY_IDENTITY`，而将洗白后的真实系统指令封装为 `<system-instruction priority="critical" role="developer">...</system-instruction>` 注入 `contents[0].parts[0]`。既保留完整指令遵循能力，又避免 `systemInstruction` 字段触发上游拦截。
3. **WAF 敏感词洗白与抗零宽字符 Cloak 改写（同步 `agy-cli` & `opencode-antigravity-bridge`）**
   - 自动剥离 `x-anthropic-billing-header:` 及包含 `cc_version`、`cc_entrypoint`、`cch=` 等 Claude Code 计费追踪行。
   - 使用 `buildCloakLineRe` 穿透零宽/隐形字符（`U+00AD`, `U+180E`, `U+200B..U+200F`, `U+2060..U+2064`, `U+FEFF`）匹配并改写所有已验证会被上游拒之门外的特征句：
     - `built on Anthropic's Claude Agent SDK` / `You are Claude Code, Anthropic's official CLI for Claude`
     - `CLAUDE_CODE_SECURITY`（安全测试授权段落）与 `CLAUDE_CODE_PASTED`（`<pasted_content>` 说明段落）整段等价重述
     - `You are Codex, a coding agent based on GPT-5` / `running in the Codex CLI`
     - `RFC 2119 keywords: MUST, REQUIRED...`（`keywords -> key words`）
     - `Hermes Agent`、`Nous Research`、`OpenCode`、`inside pi`、`inside pi-bolt`、`DeepSeek Harness`、前 20k 字符内的 `codemode -> codem0de`
   - 所有清洗均通过 `transformOutsideCodeBlocks` 保护 Markdown 代码块，避免破坏用户真实代码与 patch 内容。
4. **工具 Schema 与思考签名兼容**
   - `cleanJsonSchema` 递归展开本地 `$defs`/`definitions` `$ref`，合并 `anyOf`/`oneOf`/`allOf` 分支，转换 `const -> enum`，对齐 `required` 并转大写类型（`OBJECT`/`STRING` 等）。
   - `loadSignatureStore(dataDir)`（按目录隔离的内存 10,000 条 LRU + 磁盘 `${dataDir}/signature-cache.json` 持久化，7 天 TTL，在流式/非流式响应结束时落盘）按 `tool_call.id` 跨重启保存 `thoughtSignature`，减少不必要回退；历史消息缺失签名时回退至 `SENTINEL_SIGNATURE`，缺失 `tool_call.id` 时用 `SHA-256(turnIdx:callIdx:fnName:args)` 生成确定性 ID。

---

## 5. Prompt 缓存机制、真实日志（CSV）诊断与精简优化

### 5.1 底层缓存原理与插件可控边界

- **Google 隐式前缀缓存（Implicit Prefix Caching）**：与 Anthropic 显式 `cache_control` 不同，Google Cloud Code 后端自动按 **前缀字节精确匹配 + `2048` tokens 块边界量化** 决定缓存命中（因此正常连续命中时常看到 `tot - cache_read ≈ 2049` tokens 的正常块尾差）。
- **插件做不到与做得到的事**：
  - 做不到：强制指定某一段不缓存或跳过 Google 后端的缓存淘汰策略。
  - **做得到（决定命中率上限的关键）**：
    1. **100% 确定性的前缀序列化**：同一会话相邻轮次的 `systemInstruction`、`tools`、历史 `contents`（含 `functionCall.id`、`thoughtSignature`、清洗结果）不能有任何随机或抖动字节。
    2. **会话粘性路由 (`innerRequest.sessionId`)**：同一会话必须稳定携带同一个负 64 位整数格式 `sessionId`，而不同会话 / 子 Agent / 后台分类请求必须分流到各自的 `sessionId`，避免多并发请求在同一账号通道内互相冲刷后端副本 KV 状态。

### 5.2 2026-11-23 生产请求日志（CSV）量化诊断结论

对用户导出的 `magpie-requests-today-2026-11-23-3.csv`（共 `971` 行，其中 Antigravity 相关 `516` 行，`antigravity-rt` `506` 行）全量统计结果如下：

- **总体指标**：未缓存输入 `18,672,001` tokens，缓存读取 `60,573,194` tokens，整体缓存命中率 **`76.44%`**，总计费 **\$43.6313**。
- **按请求类型拆解暴露核心症结**：
  1. **正常对话（`kind == ""`，377 次）**：未缓存 `12.00M`、缓存读取 `60.48M`，命中率 **`83.4%`**（花费 \$32.854）。在稳定阶段连续 tool loop 单轮命中率达 **`97.5% ~ 99.7%`**。
  2. **`auto_mode_check_inferred`（Claude Desktop/Code 自动权限分类推断，72 次）**：未缓存高达 **`6,667,480` tokens（占全天总未缓存输入的 `35.7%`）**，缓存读取仅 `40,960` tokens，**命中率仅 `0.6%`**，单这一项辅助检查就烧掉 **\$10.758（占全天总账单 `24.7%`）**。全天仅 1 次命中 `40,960` 静态前缀，其余 71 次（每次携带 `45k ~ 171k` 滑动窗口对话摘要）全部 `cache_read = 0`。
  3. **680k 超长主会话偶发回落到固定前缀 `61,041` / `60,611` tokens**：
     - 在 `169cfab` 上线前，所有请求未按会话锚点隔离 `sessionId`，主会话、子 Agent 与 `auto_mode` 混用通道导致多副本负载落到未持有 680k 尾部 KV 的节点时回退至约 `61k` 基础前缀。
     - 另一部分回落伴随客户端自身裁剪旧消息或清理历史块（表现为相邻轮次总上下文 `dtot` 负增长 `-1,538` / `-4,325` / `-7,920` / `-11,699`），一旦客户端改写中部历史，改写点之后的 `500k+` tokens 必然重算。
  4. **长上下文空回复重试（HTTP `502`）**：3 次上游返回 0 输出 token 触发 Magpie `an empty reply` 重试，损耗约 **\$2.12**。

### 5.3 对比 `DylanLIiii/opencode-antigravity-bridge` 与已落地的 Prompt 精简

1. **为什么不需要搬运 `AGY_BRIDGE_MINIMAL_AGENT`？**
   - `opencode-antigravity-bridge` 通过 ACP 驱动本地 `agy` CLI，而 `agy` 默认会额外塞入约 `8,400` tokens 的官方 IDE Agent 系统提示词与内置工具，因此它需要 `excludeDefaultComponents: true` 将其压到 ~500 tokens。
   - 本项目的 `Antigravity (RT)` 直接请求 `v1internal` HTTP API，**天然没有这 8,400 tokens 的 CLI 额外开销**。
2. **已落地的缓存保护与确定性精简优化（Commits `169cfab` & `32f3ca4`）**：
   - **按会话锚点派生稳定 `sessionId` (`deriveConversationAnchor` + `deriveUpstreamSessionId`)**：基于首条用户消息（剥离动态 `<system-reminder>` / `<environment>` 后）、系统指令及工具名集合计算哈希，再经 64-bit FNV-1a 映射为官方负整数字符串 `sessionId`。主对话、子 Agent、`auto_mode` 自动分流且各自内部保持恒定。
   - **修复动态计费头导致的 `sessionId` 跳变 (`32f3ca4`)**：在 `stripFingerprintNoise` 中提前剥离 `x-anthropic-billing-header`（含随请求变化的 `cch=<hash>`、`cc_prev_req`、`cc_prompt_id`），防止 `sessionId` 每轮被计费头扰动。
   - **无损默认精简（始终开启，100% 确定性不伤缓存）**：
     - 从 `ALLOWED_SCHEMA_KEYS` 移除无语义的 JSON Schema 元数据键 `'title'`（保留 `properties.title` 等客户端真实参数名），剔除空白 `description`。
     - 代码块外清理行尾多余空白，并对 `body.instructions` 与开场连续 `system`/`developer` 消息做精确去重。
   - **工具定义预算裁剪 (`fitToolDeclarations`，移植自 `tool-budget.mjs`)**：
     - 默认预算 `DEFAULT_TOOL_TOKEN_BUDGET = 18000`（按 `Math.ceil(utf8Bytes / 3)` 估算）。工具集未超预算时**原封不动**；当遇到 Claude Desktop 等携带 67 KB+（约 22k+ tokens）超大 MCP/内置工具描述时，确定性地优先剥离末尾 `Examples:` 段落并按契约权重等比收敛描述长度，**绝不丢弃任何工具名、字段名、类型、`enum` 或 `required`**。
   - **可选激进精简模式 (`compactPrompt`)**：默认关闭；开启后额外剔除系统提示词代码块外的 `<example>...</example>` 冗长示例块，并将默认工具预算收紧至 `12000`。

---

## 6. 配置项与 CLI 运维速查

### 6.1 插件配置项 (`options.antigravity`) 与环境变量

| 插件选项 (`antigravity.*`) | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `proxy` | `ANTIGRAVITY_PROXY` | `""` | 访问 Google 的 HTTP/HTTPS 代理（容器内请用 `http://host.docker.internal:<port>`） |
| `dataDir` | `ANTIGRAVITY_DATA_DIR` | `~/.local/share/magpie-antigravity` | 存放 `accounts.json`、`oauth-clients.json`、`signature-cache.json` 与 `hub-version.json` 的本机目录 |
| `uaManifestUrl` | `ANTIGRAVITY_UA_MANIFEST_URL` | `https://raw.githubusercontent.com/P4rfa1t/magpie-gemini-web/main/lib/antigravity-ua.json` | 运行期轻量同步的远端成对 UA 清单地址；设为 `off`/`false`/`0` 可关闭后台拉取 |
| `clientId` / `clientSecret` | — | — | Personal Google OAuth 客户端凭据（首次填入或由导入 JSON 自动保存） |
| `gcpClientId` / `gcpClientSecret` | — | — | Enterprise / GCP OAuth 客户端凭据 |
| `allowTools` / `allowImages` / `imageModels` | — | `true` | 是否启用工具调用、图片输入与生图模型 |
| `contextLimit` / `outputLimit` | — | 上游模型上限 | 手动限制上报给客户端的最大上下文 / 最大输出 token |
| `requestTimeoutMs` / `modelTimeoutMs` | — | `570000` / `15000` | 单次生成超时（9.5 分钟）与模型目录拉取超时 |
| `emptyReplyMaxWaitMs` / `emptyReplyRetryDelayMs` | `ANTIGRAVITY_EMPTY_REPLY_MAX_WAIT_MS` / `ANTIGRAVITY_EMPTY_REPLY_RETRY_DELAY_MS` | `0` / `1500` | HTTP 200 空候选（`candidatesTokenCount = 0`）优雅重连时间上限（`0` 关闭自动重发，设为如 `15000` 开启流式首字门控+时间受限重试，超时返回 `502`）与退避间隔 |
| `streamIdleTimeoutMs` | `ANTIGRAVITY_STREAM_IDLE_TIMEOUT_MS` | `0` | 流式 SSE 分片间最大空闲超时毫秒数（`0` 关闭；设为如 `60000` 可在假死时及时以 `504` 止损） |
| `compactPrompt` | `ANTIGRAVITY_COMPACT_PROMPT` | `false` (`1`/`true` 开启) | 激进精简：剥离系统提示词中的 `<example>` 块并将默认工具预算收紧至 `12000` |
| `toolTokenBudget` | `ANTIGRAVITY_TOOL_TOKEN_BUDGET` | `18000`（`compactPrompt` 下 `12000`） | 工具 Schema 描述 token 预算上限；设为 `0` 或 `off` 可完全关闭裁剪 |
| `failoverOnError` | `ANTIGRAVITY_FAILOVER` | `true` (`0`/`false`/`off` 关闭) | 单账号报错（`429`/`503`/`403`/`401`）时是否同请求自动轮换至下一账号 |
| — | `ANTIGRAVITY_INSTALL_DIR` / `ANTIGRAVITY_IDE_INSTALL_DIR` | 自动探测常见系统安装路径 | 分别指定本机 Antigravity Hub 与 Antigravity IDE 目录供扫描提取 `(version, cl)` 与 `oauthUserAgent` |
| — | `ANTIGRAVITY_HUB_VERSION` / `ANTIGRAVITY_HUB_CL` / `ANTIGRAVITY_OAUTH_USER_AGENT` | `hub-version.json` 缓存或内置基线 | 覆盖出站 Hub UA（必须成对设置 Version 与 CL 才生效）与 OAuth 刷新 UA |
| — | `ANTIGRAVITY_NORMALIZE_IDENTITY` | 默认开启（`0`/`false` 关闭） | 是否将第三方 Agent 身份重写为 Antigravity（即使关闭仍会剥离 WAF 计费头） |

### 6.2 本地诊断 CLI (`scripts/antigravity.mjs`)

```bash
npm run antigravity:status                                     # 查看数据目录、有效 Egress/OAuth UA、hub-version.json 缓存与账号
npm run antigravity:sync-ua                                    # Option C：从官方下载页流式解析归档提取成对 (version, cl) 并落盘
npm run antigravity:sync-ua -- --remote                        # Option B：从 GitHub 成对清单快速拉取同步（<1s）
npm run antigravity:sync-ua -- --local-only                    # Option A：仅扫描本机 Antigravity 客户端（可加 --install-dir <路径>）
npm run antigravity:sync-ua -- --proxy http://127.0.0.1:7890   # 通过 HTTP 代理同步官方归档指纹
npm run antigravity:oauth -- --client-id <ID> --client-secret <SECRET>
npm run antigravity:login -- --file exported-accounts.json     # 导入并在线校验 Refresh Token
npm run antigravity:models                                     # 打印聚合后的可用模型及 effort 变体
npm run antigravity:quota                                      # 查看实时配额池窗口与单模型余量 JSON
npm run antigravity:smoke -- --model gemini-3.8-flash-low      # 发送最小连通性测试请求
```

---

## 7. 近期演进脉络与下一步建议（Next Steps for Incoming Models）

### 近期关键提交脉络
- `35b154f` -> `c5f0cc1` -> `ec31289`：建立基础 WAF 清洗、解决单模型池耗尽锁死整号问题、优化瞬态 429 退避与大包跳过 sandbox 重传。
- `829a949` -> `e163758` -> `5b8795a`：引入 System Prompt 侧载、对齐官方 UUID `requestId` / `labels` / `generationConfig` 拓扑、合入 `agy-cli` 抗隐形字符 Cloak 规则。
- `40db242` -> `4ffbc4e`：重构供应商配额窗口与批量账号导入 UI、修复 Claude 5.5 1M 上下文上限读取并隐藏无标签 `-tiered` 模型。
- `169cfab` -> `32f3ca4`：实现基于会话锚点的 `upstreamSessionId` 粘性隔离、10k LRU `signatureCache`、修复 `cch=` 计费头扰动锚点、移除 Schema `'title'` 噪音并引入 `fitToolDeclarations` 与 `compactPrompt`。
- **最新一致性与链路收敛**：对齐 `trajectory_id` 与 `last_step_index`、`cutDescriptionText` 完整句截断不强加 `…`、移除 `vscode/1.X.X` 占位头并支持版本覆盖、阻止已绑定账号 `invalid_grant` 跨客户端盲试、Node `CONNECT` 代理支持 ALPN `h2` (`node:http2`)、`signature-cache.json` 跨重启持久化以及 `failoverOnError` 开关。

### 已知协议/环境硬边界（纯 JS 插件层无法根治）
- 第三方编码工具轮廓（`Bash`/`Read`/`Edit` 等）与提示词整体语义聚类；
- Node OpenSSL / Bun BoringSSL 与官方 Electron/C++ 客户端之间的 TLS JA3/JA4 握手指纹差异；
- OAuth `client_id` 审核吊销及上游官方 IDE 遥测/伴生 RPC 缺失。如核心诉求是零风控稳定性，建议使用官方 Gemini / Vertex API 或通过本地官方 `agy` CLI 桥接运行。

### 后续接手可重点关注的方向
1. **跟踪新版本日志验证缓存收敛**：用户升级到包含 `169cfab` + `32f3ca4` 的版本后，如提供新的 Magpie 请求 CSV，优先核查主会话是否不再高频跌回 `60,611`，并区分「后端副本未命中」与「客户端主动截断历史（`dtot < 0`）」。
2. **`auto_mode_check_inferred` 成本治理**：若日志中 `auto_mode_check_inferred` 仍占高额未命中开销（因其请求体由客户端拼装滑动窗口摘要），可协助用户在 Magpie 路由层将该类请求路由到免费/低成本 Flash 模型，或在客户端侧调整 Auto Mode 检查策略。
3. **长上下文空回复优雅自愈（已支持可配置时间门控）**：已新增 `emptyReplyMaxWaitMs`（`ANTIGRAVITY_EMPTY_REPLY_MAX_WAIT_MS`）、`emptyReplyRetryDelayMs` 与 `streamIdleTimeoutMs`（`ANTIGRAVITY_STREAM_IDLE_TIMEOUT_MS`）。默认保持 `0` 以避免未经授权的重复扣费；开启后在发送首个实质内容分片前门控空候选并在限定时间窗内退避/切号恢复。
4. **上游 WAF 规则持续同步**：若后续出现剩余额度充足却报裸 `429 Resource has been exhausted` 的新客户端 Prompt（例如新版 Cursor / Claude Code 新增段落），优先对照 `magpie-community/plugins/packages/agy-cli` 与 `DylanLIiii/opencode-antigravity-bridge/cloak.mjs` 在 `lib/antigravity-mapper.mjs` 的 `CLOAK_REWRITES` 中增补等价改写并补充单测。
