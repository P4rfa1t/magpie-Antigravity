# 贡献与反馈指南

感谢使用和改进 `magpie-Antigravity`（npm 包名 `magpie-antigravity`，独立维护仓库：[P4rfa1t/magpie-Antigravity](https://github.com/P4rfa1t/magpie-Antigravity)）。清晰的反馈能显著缩短定位时间，中文或英文均可。

> **请首先明确问题属于哪个 Provider：Antigravity（`antigravity-rt`）还是 Gemini Web（`gemini-web`）。**两者底层协议、鉴权方式与工具调用机制完全不同，请不要只写“Gemini 报错”。

## 提交 Issue 前

1. **搜索已有 Issue**：先检索 [P4rfa1t/magpie-Antigravity/issues](https://github.com/P4rfa1t/magpie-Antigravity/issues)；若涉及 `gemini-web2api-go` 自身行为，也可对照上游 [zexadev/gemini-web2api-go](https://github.com/zexadev/gemini-web2api-go/issues)。
2. **更新至最新版本**：先执行 `git pull` / 刷新 Magpie 插件并重新运行 `npm run check && npm test` 确认复现。
3. **缩小复现范围**：尽量使用新会话与最小提示词，测试更换模型或关闭某项可选开关（如 `compactPrompt`、`signatureRectifier`）后的差异。
4. **严格脱敏**：提交日志或截图前务必完成[脱敏要求](#脱敏要求)。

## Issue 基本规则

- **一个 Issue 只讨论一个问题**。
- 标题建议以 **`[Antigravity]` 或 `[Gemini Web]`** 开头，附带客户端、模型 ID 及核心现象，例如：
  - `[Antigravity] Claude 5.5：多轮工具调用返回 signature 校验失败`
  - `[Gemini Web] Windows：Cookie 过期后状态检测未触发重登提示`
- 请提供可观察的报错全文、HTTP 状态码、错误码与复现步骤，避免只写“不能用”“限流了”。

## 可复制的 Issue 模板

```markdown
## 问题概述
<!-- 一句话说明具体问题。 -->

## 环境
- OS / 架构：
- Magpie / OpenCode 版本：
- 插件版本 / Git Commit：
- Provider（必须勾选一项）：
  - [ ] Antigravity (`antigravity-rt`)
  - [ ] Gemini Web (`gemini-web`)
- 完整模型 ID：
- 代理 / 多账号 / 自定义插件选项：

## 实际行为
<!-- 粘贴完整错误文本、HTTP 状态码、错误码。 -->

## 期望行为

## 最小复现步骤
1.
2.
3.

## 对照实验
<!-- 更换模型、单账号直连或调整配置后的结果。 -->

## 脱敏日志与输出
<!-- 如涉及 Antigravity，可附脱敏后的 `npm run antigravity:status` 输出。 -->
```

## 脱敏要求

提交前**必须删除或遮盖**以下敏感信息：

- Google OAuth **Refresh Token**（`1//...`）、`access_token`、`client_id`、`client_secret`、`accounts.json` 与 `oauth-clients.json` 内容；
- Gemini Web **Cookie**（`__Secure-1PSID` 等）、`adminToken` 与本地 API Key；
- 代理 URL 中的用户名和密码；
- 真实邮箱、项目名称、私人文件路径与私有对话正文。

## 提交代码

- 使用 Node.js >= 22；**严禁引入任何运行时或开发 npm 依赖**。
- 修改前阅读 [`AGENTS.md`](AGENTS.md) 与 [`HANDOFF.md`](HANDOFF.md)，遵守模块分层、`lib/proc.mjs` 进程探测、成对 UA 校验与 Unix LF (`\n`) 规范。
- 修复 Bug 需附带确定性回归测试；提交前必须通过全量验证：

  ```bash
  npm run check
  npm test
  npm run interrogate -- --run
  ```

- PR 请聚焦单一改动，说明根因与实际执行的验证命令，禁止把未运行的测试报告为“已通过”。
