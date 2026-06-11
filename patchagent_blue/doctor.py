from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class DoctorCheck:
    name: str
    status: str
    detail: str


def run_doctor() -> int:
    checks = [
        _tool_check("git", ["git", "--version"], required=True),
        _tool_check("codex", ["codex", "--version"], required=False),
        _tool_check("claude", ["claude", "--version"], required=False),
        _tool_check("semgrep", ["semgrep", "--version"], required=True),
        _tool_check("docker", ["docker", "--version"], required=False),
        _tool_check("node", ["node", "--version"], required=False),
        _tool_check("python", ["python", "--version"], required=True),
    ]
    for check in checks:
        print(f"[{check.status}] {check.name}: {check.detail}")
    if any(check.name == "semgrep" and check.status == "MISSING" for check in checks):
        print()
        print("Install Semgrep:")
        print("  pipx install semgrep")
        print("or:")
        print("  python -m pip install semgrep")
        print("or:")
        print("  docker run --rm semgrep/semgrep semgrep --version")
    return 0


def _tool_check(name: str, command: list[str], required: bool) -> DoctorCheck:
    executable = shutil.which(command[0])
    if executable is None:
        return DoctorCheck(name=name, status="MISSING" if required else "WARN", detail="not found")
    completed = subprocess.run(
        " ".join(command),
        shell=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    detail = completed.stdout.strip() or completed.stderr.strip() or executable
    if completed.returncode != 0:
        return DoctorCheck(name=name, status="WARN", detail=detail)
    return DoctorCheck(name=name, status="OK", detail=detail.splitlines()[0])
