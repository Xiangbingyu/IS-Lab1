# IS Lab 1 Secure Notes

English | [简体中文](README.zh-CN.md)

Part I of the Information Security laboratory: a personal learning-notes API built with Flask. It demonstrates authentication, password hashing, SQL injection and XSS protection, per-user access control, automated tests, and security scanning.

Author: **XiangBingYu** · Student ID: **23320211**

Recorded results: **43 local tests passed**, no unsuppressed SAST findings (one documented false-positive suppression), and no known vulnerabilities found in 13 runtime dependencies. [All three GitHub Actions jobs passed](https://github.com/Xiangbingyu/IS-Lab1/actions/runs/41963172326).

Repository: <https://github.com/Xiangbingyu/IS-Lab1>

## Project Contents

- [English laboratory report](docs/PART1_REPORT.md): organized into sections for transfer to the Word report.
- [Screenshot index (Chinese)](evidence/README.md): explains the purpose and suggested placement of each image.
- `app/`: application, browser interface, and security logic.
- `tests/`: 43 functional and security tests.
- `.github/workflows/ci.yml`: separate test, SAST, and SCA jobs.
- `evidence/raw/`: actual execution logs and machine-readable results.
- `evidence/screenshots/`: experiment screenshots.

This repository currently covers Part I. CVE selection and reproduction for Part II will be completed separately.

## Local Setup

Python 3.13 is required. Run the following commands in PowerShell from the repository root. The signing secret is supplied through an environment variable, and the user password is entered interactively rather than stored in source code or command-line arguments.

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:LAB1_SECRET_KEY = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
& .\.venv\Scripts\python.exe -m flask --app app:create_app init-db
& .\.venv\Scripts\python.exe -m flask --app app:create_app create-user xiangbingyu
& .\.venv\Scripts\waitress-serve.exe --host=127.0.0.1 --port=5081 --call app:create_app
```

Open <http://127.0.0.1:5081> and sign in with the account you created. The database is stored in `instance/notes.db` and excluded from Git. Passwords must contain 12–72 UTF-8 bytes; bcrypt uses a cost factor of 12. Set the environment variable again when opening a new terminal. Changing the signing secret invalidates previously issued tokens.

Equivalent commands for Linux/macOS:

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

| Method | Endpoint | Purpose | Authentication |
|---|---|---|---|
| POST | `/auth/login` | Submit `username` and `password` to obtain a JWT | Public |
| GET | `/api/data` | Retrieve the current user's notes through the basic data endpoint | Required |
| GET | `/api/notes?q=JWT` | Search the current user's notes by title | Required |
| POST | `/api/notes` | Create a note using `title` and `body` | Required |
| GET | `/api/notes/<id>` | Retrieve a single note owned by the current user | Required |
| GET | `/health` | Check service health | Public |

Authenticated requests use `Authorization: Bearer <token>`. Tokens expire after 30 minutes. Verification checks the signature, accepted algorithm, expiration, issue time, not-before time, issuer, audience, and whether the user still exists. The browser stores the token in memory. Signing out clears the local token but does not revoke an already issued token.

## Tests and Security Checks

```powershell
& .\.venv\Scripts\python.exe scripts/run_checks.py
```

This command runs pytest, Bandit, and pip-audit in sequence and saves their actual output to `evidence/raw/`. It returns a nonzero exit code if any check fails. The dependency audit requires network access.

`requirements.txt` pins runtime dependencies, including transitive packages. `requirements-dev.txt` adds testing and auditing tools. The SCA scope is the runtime dependency list; it does not cover development tools or the entire operating system. The current list was generated for Python 3.13. Revalidate dependency resolution when changing the interpreter or platform.

The initial Bandit scan reported one B106 false positive: it interpreted `token_type="Bearer"` as a hardcoded password. `Bearer` is a public authentication scheme name. A local `# nosec B106` annotation documents the exception, with the explanation immediately above the code. The rule is not disabled globally. The original finding is preserved in `bandit-initial.json`. The final scan contains no unsuppressed findings and one documented suppression.

GitHub Actions runs the same categories of checks on pushes, pull requests, and manual dispatches. Failures are not hidden with `continue-on-error`, and reports are uploaded as artifacts. This project implements continuous integration and security checks; it does not deploy a public service.

## Reproducing Browser Evidence

Start the dedicated demonstration server in another terminal. It uses a temporary in-memory database and random passwords without modifying the regular application database:

```powershell
& .\.venv\Scripts\python.exe scripts/serve_demo.py
```

Demonstration credentials are saved only in the Git-ignored file `evidence/private/demo-login.json`. The screenshot scripts require Node.js, Playwright, and Chrome. You can install Playwright in a separate tools directory and point `PLAYWRIGHT_MODULE` to its module path; it is not a Python runtime dependency.

```powershell
# Set PLAYWRIGHT_MODULE to your Playwright module path if it is not already resolvable.
node scripts/capture_evidence.cjs
node scripts/render_evidence_summary.cjs
```

Run `run_checks.py` before the screenshot scripts. The first screenshot script operates a real browser, signs in, creates notes, checks XSS behavior, and records actual HTTP responses. The second produces compact evidence screenshots suitable for the Word report.

Screenshots 03–06 show evidence pages generated from real logs or API records; they are not terminal-window or GitHub-website screenshots. Restart the demonstration server before collecting evidence again to clear its temporary notes. Screenshot 06 uses the saved GitHub execution record and does not fetch a new workflow run automatically.

## Security Scope and Limitations

This is a local educational project. Public deployment would additionally require HTTPS, login rate limiting, secret management and rotation, token revocation, audit logging, and operational configuration. Passing tests or finding no known dependency vulnerabilities does not establish that the application has no security risks.

Notes returned in JSON are plain text. Clients must display them through a safe text API such as `textContent`. A different client that inserts the content through `innerHTML` could still introduce XSS. The browser experiment also checks a separate context with CSP bypassed to verify the protection provided by safe text rendering itself.
