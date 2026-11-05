"""Run real checks and preserve their exit codes and raw output."""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.stdout.reconfigure(encoding="utf-8")
os.environ["PYTHONIOENCODING"] = "utf-8"
OUT = ROOT / "evidence" / "raw"
OUT.mkdir(parents=True, exist_ok=True)
commands = {
    "pytest": [sys.executable, "-m", "pytest", "-v", "--junitxml=evidence/raw/pytest.xml"],
    "bandit": [sys.executable, "-m", "bandit", "-r", "app", "-f", "json", "-o", "evidence/raw/bandit.json"],
    "pip-audit": [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--disable-pip", "--no-deps", "-f", "json", "-o", "evidence/raw/pip-audit.json"],
}
summary = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version, "checks": {}}
for name, command in commands.items():
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    output = result.stdout + result.stderr
    (OUT / f"{name}.txt").write_text(output, encoding="utf-8")
    summary["checks"][name] = {"exit_code": result.returncode, "command": " ".join(command[1:])}
    print(f"{name}: exit {result.returncode}\n{output[-2000:]}", flush=True)
(OUT / "checks-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
sys.exit(int(any(check["exit_code"] for check in summary["checks"].values())))
