# IS Lab 1 Secure Notes

[English](README.md) | 简体中文

信息安全实验分两部分。第一部分使用 Flask 实现个人学习笔记 API，完成身份认证、密码哈希、SQL 注入与 XSS 防护、用户数据隔离，以及自动测试和安全扫描。第二部分在 Docker 中复现、分析、修复并验证一个真实漏洞 **CVE-2015-3337**（Elasticsearch 目录穿越）。

作者：XiangBingYu，学号：23320211。

验证结果：本地 43 项测试通过，SAST 无未处理发现（1 处已说明的误报抑制），13 个运行时依赖未检出已知漏洞；[GitHub Actions 三个任务全部通过](https://github.com/Xiangbingyu/IS-Lab1/actions/runs/41979506780)。第二部分中，穿越请求由漏洞版的 200（带文件内容）变为修复版的 404，同时站点插件自身文件仍返回 200。

仓库：<https://github.com/Xiangbingyu/IS-Lab1>

## 文件导航

- [整体实验报告（第一 + 第二部分）](docs/WORK1_REPORT.md)：合并为一份，供直接整理进 Word 提交。
- [英文实验报告（第一部分）](docs/PART1_REPORT.md)：安全 REST API 的开发与测试。
- [英文实验报告（第二部分）](docs/PART2_REPORT.md)：CVE-2015-3337 复现、根因、修复与验证。
- [截图索引](evidence/README.md)：每张图片的用途与插入位置。
- `app/`：应用、网页和安全逻辑。
- `tests/`：43 项功能与安全测试。
- `.github/workflows/ci.yml`：测试、SAST、SCA 三个独立任务。
- `vulhub-fix/CVE-2015-3337/`：漏洞版与修复版镜像、补丁源码与原始证据。
- `evidence/raw/`：真实运行日志与机器可读结果。
- `evidence/screenshots/`：实验截图（第一部分 01–06，第二部分 07–10）。

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
node scripts/render_evidence_summary.cjs
```

先执行 `run_checks.py`，再执行截图脚本。截图脚本操作真正的浏览器，完成登录、创建笔记和 XSS 检查，并保存实际 HTTP 响应。第二个脚本生成更适合插入 Word 的紧凑证据截图。03–06 是基于真实日志或 API 记录生成的证据阅读页截图，不是终端或 GitHub 网站截图。重新采集前重启演示服务器，以清空临时笔记。06 使用仓库内已保存的 GitHub 运行记录，并不自动抓取新流水线。

第二部分截图（07–10）由同一机制渲染已记录的输出：

```powershell
node scripts/capture_part2_evidence.cjs
```

## 第二部分：CVE-2015-3337

完整分析见[第二部分报告](docs/PART2_REPORT.md)。简述：Elasticsearch 在 1.4.5 之前及 1.5.2 之前的 1.5.x 中，站点插件处理器存在 `../` 目录穿越。`HttpServer.handlePluginSite` 用 `getAbsolutePath()` 做包含校验，而它不会解析 `..`，导致该校验永远无法拦穿越请求；修复方案是先归一化再比较（`toPath().normalize().startsWith(...)`）。该漏洞只有在安装站点插件时才可达。

所有产物位于 `vulhub-fix/CVE-2015-3337/`，需要 Docker。两个镜像均为故意不安全的版本并绑定回环地址，仅供实验使用，切勿暴露到公网。

```powershell
cd vulhub-fix/CVE-2015-3337
docker compose -f docker-compose.yml up -d --build          # 漏洞版，宿主 9200
docker compose -f docker-compose.fixed.yml up -d --build    # 修复版，宿主 9201
```

验证（漏洞版返回 200 带文件内容，修复版返回 404，两者都仍以 200 提供插件自身文件）：

```powershell
curl.exe --path-as-is "http://127.0.0.1:9200/_plugin/head/../../../../../../../../../etc/passwd"
curl.exe --path-as-is "http://127.0.0.1:9201/_plugin/head/../../../../../../../../../etc/passwd"
curl.exe -o NUL -w "%{http_code}`n" http://127.0.0.1:9201/_plugin/head/index.html
```

该目录需包含 `head-master.zip`（`elasticsearch-head` 站点插件包）。修复以代码级 backport 方式实施：`Dockerfile.fixed` 用补丁后的 `HttpServer.java` 针对已发布的 1.4.4 jar 重新编译，只替换受影响的类。细节见 `vulhub-fix/CVE-2015-3337/FIX.md`。

## 安全边界

这是本地教学项目。对外部署还需要 HTTPS、登录限速、密钥管理与轮换、令牌撤销策略、审计日志和运维配置。本项目不把“测试通过”或“未检出已知漏洞”解释为没有任何安全风险。

JSON 中的笔记是普通文本，前端必须通过 `textContent` 等安全方式显示；其他客户端如果把内容传入 `innerHTML`，仍可能引入 XSS。浏览器测试另开禁用 CSP 的上下文验证了安全文本显示本身的效果。
