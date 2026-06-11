from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from .gitops import GitError, git_head, git_status


def capture_run_start(target: Path, run_dir: Path, config_name: str = "patchagent-blue.yml") -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    base_commit = _safe_git_value(lambda: git_head(target), "unavailable")
    status_before = _safe_git_value(lambda: git_status(target), "")
    (run_dir / "base_commit.txt").write_text(base_commit + "\n", encoding="utf-8")
    (run_dir / "git_status_before.txt").write_text(status_before, encoding="utf-8")
    environment = {
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "node": _version(["node", "--version"]),
        "npm": _version(["npm", "--version"]),
        "git": _version(["git", "--version"]),
        "codex": _version(["codex", "--version"]),
        "claude": _version(["claude", "--version"]),
        "semgrep": _version(["semgrep", "--version"]),
    }
    (run_dir / "environment.json").write_text(
        json.dumps(environment, indent=2, sort_keys=True), encoding="utf-8"
    )
    manifest = {
        "target": str(target),
        "config": str(target / config_name),
        "base_commit": base_commit,
        "artifact_version": 1,
    }
    (run_dir / "manifest.snapshot.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


def capture_run_end(target: Path, run_dir: Path) -> None:
    (run_dir / "git_status_after.txt").write_text(
        _safe_git_value(lambda: git_status(target), ""), encoding="utf-8"
    )


def _version(command: list[str]) -> str:
    executable = shutil.which(command[0])
    if executable is None:
        return "unavailable"
    completed = subprocess.run(
        " ".join(command),
        shell=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return (completed.stdout.strip() or completed.stderr.strip() or "unknown").splitlines()[0]


def _safe_git_value(fn, default: str) -> str:
    try:
        return fn()
    except (GitError, FileNotFoundError):
        return default
