from __future__ import annotations

import json
import os
import shutil
import subprocess
import hashlib
from pathlib import Path
from typing import Any

from .config import AppConfig
from .models import Finding


class SastError(RuntimeError):
    pass


def normalize_semgrep(raw: dict[str, Any], target: Path | str) -> list[Finding]:
    target_path = Path(target).resolve()
    results = sorted(
        raw.get("results") or [],
        key=lambda item: (
            str(item.get("path", "")),
            int((item.get("start") or {}).get("line", 0)),
            str(item.get("check_id", "")),
        ),
    )
    findings: list[Finding] = []
    for index, result in enumerate(results, start=1):
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}
        findings.append(
            Finding(
                finding_id=f"F{index:04d}",
                tool="semgrep",
                rule_id=str(result.get("check_id", "")),
                path=_normalize_path(result.get("path", ""), target_path),
                start_line=int(start.get("line", 0) or 0),
                start_col=int(start.get("col", 0) or 0),
                end_line=int(end.get("line", start.get("line", 0)) or 0),
                end_col=int(end.get("col", start.get("col", 0)) or 0),
                message=str(extra.get("message") or result.get("check_id") or "Semgrep finding"),
                severity=str(extra.get("severity") or "INFO"),
                cwe=_metadata_list(extra.get("metadata") or {}, "cwe"),
                owasp=_metadata_list(extra.get("metadata") or {}, "owasp"),
                metavars=dict(extra.get("metavars") or {}),
                code_snippet=str(extra.get("lines") or ""),
                metadata=dict(extra.get("metadata") or {}),
            )
        )
    return findings


class SastRunner:
    def scan(self, target: Path | str, config: AppConfig, run_dir: Path) -> list[Finding]:
        target_path = Path(target).resolve()
        raw = self._run_semgrep(target_path, config)
        run_dir.mkdir(parents=True, exist_ok=True)
        _write_version_file(run_dir)
        _write_rule_hash(run_dir, config, target_path)
        (run_dir / "semgrep.raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8"
        )
        findings = normalize_semgrep(raw, target_path)
        (run_dir / "findings.json").write_text(
            json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return findings

    def _run_semgrep(self, target: Path, config: AppConfig) -> dict[str, Any]:
        override = os.environ.get("PATCHAGENT_BLUE_SEMGREP_CMD")
        semgrep_config = config.sast.config or "auto"
        args = [
            "scan",
            "--config",
            semgrep_config,
            "--json",
            f"--metrics={config.sast.metrics}",
            "--timeout",
            str(config.sast.timeout_sec),
            str(target),
        ]
        if override:
            command = f"{override} {subprocess.list2cmdline(args)}"
            completed = subprocess.run(
                command,
                cwd=target,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        else:
            semgrep = shutil.which("semgrep")
            if semgrep is None:
                raise SastError(
                    "Semgrep is not installed. Install it or set PATCHAGENT_BLUE_SEMGREP_CMD "
                    "to a compatible command."
                )
            completed = subprocess.run(
                [semgrep, *args],
                cwd=target,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        if completed.returncode != 0:
            raise SastError(completed.stderr.strip() or completed.stdout.strip() or "Semgrep failed")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SastError(f"Semgrep did not return valid JSON: {exc}") from exc


def _normalize_path(path_value: Any, target: Path) -> str:
    raw_path = Path(str(path_value))
    try:
        if raw_path.is_absolute():
            return raw_path.resolve().relative_to(target).as_posix()
    except ValueError:
        pass
    return raw_path.as_posix()


def _metadata_list(metadata: dict[str, Any], key: str) -> list[str]:
    value = metadata.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _write_version_file(run_dir: Path) -> None:
    semgrep = shutil.which("semgrep")
    if semgrep is None:
        (run_dir / "semgrep.version.txt").write_text("semgrep: unavailable\n", encoding="utf-8")
        return
    completed = subprocess.run(
        [semgrep, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    version = completed.stdout.strip() or completed.stderr.strip() or "unknown"
    (run_dir / "semgrep.version.txt").write_text(version + "\n", encoding="utf-8")


def _write_rule_hash(run_dir: Path, config: AppConfig, target: Path) -> None:
    config_path = Path(config.sast.config)
    if not config_path.is_absolute():
        config_path = target / config_path
    if config.sast.config == "auto" or not config_path.exists():
        value = f"{config.sast.config}\n"
    elif config_path.is_file():
        value = hashlib.sha256(config_path.read_bytes()).hexdigest() + "\n"
    else:
        digest = hashlib.sha256()
        for path in sorted(config_path.rglob("*")):
            if path.is_file():
                digest.update(path.relative_to(config_path).as_posix().encode("utf-8"))
                digest.update(path.read_bytes())
        value = digest.hexdigest() + "\n"
    (run_dir / "semgrep.rule_hash.txt").write_text(value, encoding="utf-8")
