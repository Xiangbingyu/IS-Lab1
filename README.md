# IS Lab 1 Secure Notes

信息安全实验第一部分：使用 Flask 实现个人学习笔记 API，完成身份认证、密码哈希、SQL 注入与 XSS 防护、用户数据隔离，以及自动测试和安全扫描。

作者：XiangBingYu，学号：23320211。

仓库：<https://github.com/Xiangbingyu/IS-Lab1>

## 文件导航

- [英文实验报告](docs/PART1_REPORT.md)：可按章节填入 Word。
- [截图索引](evidence/README.md)：每张图片的用途与插入位置。
- `app/`：应用、网页和安全逻辑。
- `tests/`：43 项功能与安全测试。
- `.github/workflows/ci.yml`：测试、SAST、SCA 三个独立任务。
- `evidence/raw/`：真实运行日志与机器可读结果。
- `evidence/screenshots/`：实验截图。

本仓库当前只包含第一部分；第二部分 CVE 选题和复现后续单独完成。

## 本地启动

要求 Python 3.13。以下命令在仓库根目录的 PowerShell 执行。密钥只放在环境变量中，用户密码交互输入，不写进代码或命令行参数。

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:LAB1_SECRET_KEY = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
& .\.venv\Scripts\python.exe -m flask --app app:create_app init-db
& .\.venv\Scripts\python.exe -m flask --app app:create_app create-user xiangbingyu
& .\.venv\Scripts\waitress-serve.exe --host=127.0.0.1 --port=5081 --call app:create_app
```

打开 <http://127.0.0.1:5081>，使用刚创建的账号登录。数据库位于 `instance/notes.db`，已从 Git 排除。密码要求 12–72 个 UTF-8 字节；bcrypt 成本为 12。新开终端时需要重新设置环境变量；更换密钥会使旧令牌失效。

Linux/macOS 对应命令：

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
export LAB1_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m flask --app app:create_app init-db
python -m flask --app app:create_app create-user xiangbingyu
waitress-serve --host=127.0.0.1 --port=5081 --call app:create_app
```

## API

| 方法 | 路径 | 作用 | 认证 |
|---|---|---|---|
| POST | `/auth/login` | 提交 `username` 和 `password`，获得 JWT | 否 |
| GET | `/api/data` | 获取当前用户的笔记，兼容实验基础数据接口 | 是 |
| GET | `/api/notes?q=JWT` | 按标题搜索自己的笔记 | 是 |
| POST | `/api/notes` | 提交 `title`、`body` 创建笔记 | 是 |
| GET | `/api/notes/<id>` | 获取自己的单条笔记 | 是 |
| GET | `/health` | 健康检查 | 否 |

认证请求使用 `Authorization: Bearer <token>`。令牌有效期 30 分钟，校验签名、算法、有效期、签发时间、启用时间、签发者、受众和用户是否存在。客户端保存令牌于内存；退出仅清除本地令牌，不撤销已签发令牌。

## 检查

```powershell
& .\.venv\Scripts\python.exe scripts/run_checks.py
```

该命令依次执行 pytest、Bandit 和 pip-audit，保存真实输出到 `evidence/raw/`；任何任务失败都会返回非零退出码。依赖审计需要网络。

运行时依赖在 `requirements.txt` 中固定版本并包含传递依赖。`requirements-dev.txt` 额外包含测试和审计工具。SCA 的明确范围是运行时依赖，并不代表开发工具或整个操作系统也通过审计。当前锁定列表按 Python 3.13 环境生成；更换解释器或平台后应重新验证依赖解析。

Bandit 初次发现 1 条 B106 误报：把 `token_type="Bearer"` 当成密码。Bearer 是公开认证协议名称，该处使用局部 `# nosec B106`，原因紧邻代码说明，未全局禁用规则。保留了 `bandit-initial.json`。最终扫描无未处理发现，包含 1 处已说明的规则抑制。

GitHub Actions 会在 push、pull request 和手动触发时运行相同类别的检查。失败不会被 `continue-on-error` 隐藏；报告会通过 artifacts 上传。此实验实现持续集成与安全检查，未部署到公网服务。

## 重现浏览器截图

另开终端运行实验专用演示服务器；它使用临时内存数据库和随机密码，不改动正常数据库：

```powershell
& .\.venv\Scripts\python.exe scripts/serve_demo.py
```

演示登录信息仅保存在被忽略的 `evidence/private/demo-login.json`。截图脚本需要 Node.js、Playwright 和 Chrome；可在独立工具目录安装 Playwright，再通过环境变量 `PLAYWRIGHT_MODULE` 指向其模块路径，不必将它加入 Python 运行时依赖。

```powershell
# PLAYWRIGHT_MODULE 为你的 Playwright 模块路径；已能正常 require 时可省略。
node scripts/capture_evidence.cjs
```

先执行 `run_checks.py`，再执行截图脚本。截图脚本操作真正的浏览器，完成登录、创建笔记和 XSS 检查，并保存实际 HTTP 响应。03–05 是基于真实日志生成的证据阅读页截图，不是终端截图。重新采集前重启演示服务器，以清空临时笔记。

## 安全边界

这是本地教学项目。对外部署还需要 HTTPS、登录限速、密钥管理与轮换、令牌撤销策略、审计日志和运维配置。本项目不把“测试通过”或“未检出已知漏洞”解释为没有任何安全风险。

JSON 中的笔记是普通文本，前端必须通过 `textContent` 等安全方式显示；其他客户端如果把内容传入 `innerHTML`，仍可能引入 XSS。浏览器测试另开禁用 CSP 的上下文验证了安全文本显示本身的效果。
