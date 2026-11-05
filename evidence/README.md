# 实验截图和证据索引

截图统一存放在 `screenshots/`，原始输出保存在 `raw/`。正文插图已写入 `docs/PART1_REPORT.md`；复制到 Word 时按下面顺序插入即可。

| 图片 | 建议位置 | 证明内容 |
|---|---|---|
| `01-notes-working.png` | API Description | 实际登录后成功创建并显示笔记 |
| `02-xss-safe-rendering.png` | XSS Protection | 恶意标签作为文本显示；浏览器断言另存 JSON |
| `03-api-security-checks.png` | Functional and Security Testing | 实际请求的状态码和返回内容，令牌已省略 |
| `04-pytest.png` | Functional and Security Testing | 实际 pytest 日志，43 项通过 |
| `05-security-scans.png` | Security Scanning | 实际 Bandit 与 pip-audit JSON 结果 |

01–02 为应用页面截图。03–05 为真实输出的证据阅读页截图，不是终端窗口截图，不应在报告中将其描述为终端截图。截图采集由 `scripts/capture_evidence.cjs` 自动完成。

`raw/bandit-initial.json` 保留第一次扫描的 Bearer 协议名称误报。最终 Bandit 存在 1 处局部 B106 抑制，报告已说明，不能描述为“没有使用规则抑制”。

`raw/browser-results.json` 保存真实请求及浏览器 XSS 断言结果。`raw/checks-summary.json` 记录检查时间和退出码。`private/` 包含仅供本地演示使用的临时登录资料，已被 Git 忽略，不提交。

截图中的软件版本、结果和日期来自本次实验。不得把本部分证据用作尚未开展的 CVE 实验结果。
