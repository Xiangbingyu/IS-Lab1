# 实验截图和证据索引

截图统一存放在 `screenshots/`，原始输出保存在 `raw/`（Part II 的原始输出保存在 `vulhub-fix/CVE-2015-3337/evidence/`）。正文插图已写入 `docs/PART1_REPORT.md` 和 `docs/PART2_REPORT.md`；复制到 Word 时按下面顺序插入即可。

| 图片 | 建议位置 | 证明内容 |
|---|---|---|
| `01-notes-working.png` | API Description | 实际登录后成功创建并显示笔记 |
| `02-xss-safe-rendering.png` | XSS Protection | 恶意标签作为文本显示；浏览器断言另存 JSON |
| `03-api-security-checks.png` | Functional and Security Testing | 实际请求的状态码和返回内容，令牌已省略 |
| `04-pytest.png` | Functional and Security Testing | 实际 pytest 日志，43 项通过 |
| `05-security-scans.png` | Security Scanning | 实际 Bandit 与 pip-audit JSON 结果 |
| `06-github-actions.png` | GitHub Actions Execution | GitHub API 返回的三个成功任务及对应提交 |
| `07-cve-reproduction.png` | Part II · Reproduction | 漏洞版实际响应：版本横幅、插件可达、穿越读 `/etc/passwd` 返回 200 |
| `08-cve-root-cause.png` | Part II · Root Cause | 1.4.4 与 1.4.5 的 `handlePluginSite` 代码逐行对照 |
| `09-cve-fix-verification.png` | Part II · Verification | 漏洞版（:9200）与修复版（:9201）对照：穿越 200→404，插件自身文件仍 200 |
| `10-cve-attack-variants.png` | Part II · Attack Variants | 编码穿越与任意文件读取在两个镜像上的结果 |

01–02 为应用页面截图。03–06、07–10 为真实输出或 API 记录的证据阅读页截图，不是终端窗口或 GitHub 网站截图，不应在报告中将其描述为终端截图。Part I 截图采集由 `scripts/capture_evidence.cjs` 和 `scripts/render_evidence_summary.cjs` 完成，Part II 由 `scripts/capture_part2_evidence.cjs` 完成。

`raw/bandit-initial.json` 保留第一次扫描的 Bearer 协议名称误报。最终 Bandit 存在 1 处局部 B106 抑制，报告已说明，不能描述为“没有使用规则抑制”。

`raw/browser-results.json` 保存真实请求及浏览器 XSS 断言结果。`raw/checks-summary.json` 记录检查时间和退出码。`private/` 包含仅供本地演示使用的临时登录资料，已被 Git 忽略，不提交。

截图中的软件版本、结果和日期来自本次实验。Part I 的证据只用于 Part I 的结论，Part II 的证据（07–10）只用于 CVE-2015-3337 的结论，两者不互相替代。
