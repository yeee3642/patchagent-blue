from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import AppConfig, ReplayExpectation, normalize_command, normalize_replay


@dataclass
class SuiteResult:
    passed: bool
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    passed: bool
    unit: SuiteResult
    attack: SuiteResult
    phase: str = "after_patch"

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "phase": self.phase,
            "unit": self.unit.to_dict(),
            "attack": self.attack.to_dict(),
        }


def verify_target(
    target: Path | str, config: AppConfig, run_dir: Path, phase: str = "after_patch"
) -> VerificationResult:
    logs_dir = run_dir / "logs" / phase
    unit = run_unit_commands(Path(target), config, logs_dir)
    attack = run_attack_replays(Path(target), config, logs_dir, phase=phase)
    result = VerificationResult(unit.passed and attack.passed, unit, attack, phase)
    run_dir.mkdir(parents=True, exist_ok=True)
    output_name = "baseline.verify.json" if phase == "before_patch" else "verify.json"
    (run_dir / output_name).write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )
    return result


def run_unit_commands(target: Path | str, config: AppConfig, logs_dir: Path) -> SuiteResult:
    commands = config.tests.unit.commands
    if not commands:
        return SuiteResult(True, [])
    logs_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for index, raw_command in enumerate(commands, start=1):
        command = normalize_command(raw_command, f"unit-{index}")
        completed = _run_command(command.cmd, Path(target), command.timeout_sec, command.env)
        log_stem = logs_dir / f"unit-{index}-{_safe_name(command.name)}"
        _write_command_logs(log_stem, completed)
        results.append(
            {
                "name": command.name,
                "command": _command_for_report(command.cmd),
                "returncode": completed.returncode,
                "passed": completed.returncode == 0,
                "stdout_path": str(log_stem.with_suffix(".stdout.txt")),
                "stderr_path": str(log_stem.with_suffix(".stderr.txt")),
            }
        )
    return SuiteResult(all(item["passed"] for item in results), results)


def run_attack_replays(
    target: Path | str, config: AppConfig, logs_dir: Path, phase: str = "after_patch"
) -> SuiteResult:
    replay_specs = config.tests.attack.replays
    if not replay_specs:
        return SuiteResult(True, [])
    logs_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for replay_spec in replay_specs:
        replay_items = _expand_replay_spec(Path(target), replay_spec)
        for raw_item in replay_items:
            replay = normalize_replay(raw_item, f"attack-{len(results) + 1}")
            if isinstance(replay, str):
                continue
            expectation = replay.before_patch if phase == "before_patch" else replay.after_patch
            if expectation is None:
                continue
            completed = _run_command(replay.cmd, Path(target), replay.timeout_sec, replay.env)
            log_stem = logs_dir / f"attack-{len(results) + 1}-{_safe_name(replay.id)}"
            _write_command_logs(log_stem, completed)
            passed, failures = _evaluate_expectations(expectation, completed)
            results.append(
                {
                    "name": replay.id,
                    "id": replay.id,
                    "phase": phase,
                    "command": _command_for_report(replay.cmd),
                    "returncode": completed.returncode,
                    "passed": passed,
                    "failures": failures,
                    "stdout_path": str(log_stem.with_suffix(".stdout.txt")),
                    "stderr_path": str(log_stem.with_suffix(".stderr.txt")),
                }
            )
    return SuiteResult(all(item["passed"] for item in results), results)


def _expand_replay_spec(target: Path, replay_spec: Any) -> list[Any]:
    if isinstance(replay_spec, str):
        path = Path(replay_spec)
        if not path.is_absolute():
            path = target / path
        return _load_replay_file(path)
    return [replay_spec]


def _load_replay_file(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [dict(item) for item in data]
    return [dict(data)]


def _run_command(
    command: str | list[str], cwd: Path, timeout_sec: int | None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(key): str(value) for key, value in env.items()})
    if isinstance(command, list):
        return subprocess.run(
            [str(item) for item in command],
            cwd=cwd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=merged_env,
            encoding="utf-8",
            errors="replace",
        )
    return subprocess.run(
        command,
        cwd=cwd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        env=merged_env,
        encoding="utf-8",
        errors="replace",
    )


def _write_command_logs(log_stem: Path, completed: subprocess.CompletedProcess[str]) -> None:
    log_stem.with_suffix(".stdout.txt").write_text(completed.stdout, encoding="utf-8")
    log_stem.with_suffix(".stderr.txt").write_text(completed.stderr, encoding="utf-8")


def _evaluate_expectations(
    expectation: ReplayExpectation, completed: subprocess.CompletedProcess[str]
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    if expectation.expect_exit_code is not None and completed.returncode != expectation.expect_exit_code:
        failures.append(f"expected exit {expectation.expect_exit_code}, got {completed.returncode}")
    _expect_regex("stdout", completed.stdout, expectation.expect_stdout_regex, failures)
    _expect_regex("stderr", completed.stderr, expectation.expect_stderr_regex, failures)
    _expect_contains("stdout", completed.stdout, expectation.expect_stdout_contains, failures)
    _expect_contains("stderr", completed.stderr, expectation.expect_stderr_contains, failures)
    _expect_not_contains("stdout", completed.stdout, expectation.expect_stdout_not_contains, failures)
    _expect_not_contains("stderr", completed.stderr, expectation.expect_stderr_not_contains, failures)
    return not failures, failures


def _expect_regex(stream_name: str, stream_value: str, pattern: str | None, failures: list[str]) -> None:
    if not pattern:
        return
    if not re.search(pattern, stream_value, flags=re.MULTILINE):
        failures.append(f"expected {stream_name} to match regex {pattern!r}")


def _expect_contains(
    stream_name: str, stream_value: str, expected_value: Any, failures: list[str]
) -> None:
    if expected_value is None:
        return
    for expected in _as_list(expected_value):
        if expected not in stream_value:
            failures.append(f"expected {stream_name} to contain {expected!r}")


def _expect_not_contains(
    stream_name: str, stream_value: str, forbidden_value: Any, failures: list[str]
) -> None:
    if forbidden_value is None:
        return
    for forbidden in _as_list(forbidden_value):
        if forbidden in stream_value:
            failures.append(f"expected {stream_name} not to contain {forbidden!r}")


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _safe_name(name: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in name)[:80]


def _command_for_report(command: str | list[str]) -> str | list[str]:
    if isinstance(command, list):
        return [str(item) for item in command]
    return str(command)
