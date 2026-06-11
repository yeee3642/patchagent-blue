from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .agents import AgentError, BaseAgent, default_agent_registry, resolve_agent_chain
from .artifacts import capture_run_end, capture_run_start
from .config import AppConfig, load_config, write_default_config
from .doctor import run_doctor
from .gitops import (
    GitError,
    apply_diff,
    clean_worktree_required,
    create_worktree,
    ensure_git_repo,
    get_diff,
    reset_worktree,
    rollback_diff,
)
from .models import Finding, PatchAttempt
from .report import write_report
from .sast import SastError, SastRunner
from .verify import verify_target


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            write_default_config(Path(args.target), force=args.force)
            return 0
        if args.command == "doctor":
            return run_doctor()
        if args.command == "scan":
            run_scan(Path(args.target))
            return 0
        if args.command == "verify":
            run_dir = _resolve_run_dir(Path(args.target), args.run)
            return 0 if verify_run(Path(args.target), run_dir) else 1
        if args.command == "patch":
            run_dir = _resolve_run_dir(Path(args.target), args.run)
            passed = patch_finding(
                Path(args.target),
                run_dir,
                args.finding,
                args.agent,
                allow_unsafe_no_git=args.allow_unsafe_no_git,
            )
            return 0 if passed else 1
        if args.command == "run":
            run_dir = run_scan(Path(args.target))
            findings = _load_findings(run_dir)
            passed = True
            for finding in findings:
                if not patch_finding(
                    Path(args.target),
                    run_dir,
                    finding.id,
                    args.agent,
                    allow_unsafe_no_git=args.allow_unsafe_no_git,
                ):
                    passed = False
                    break
            write_report(run_dir)
            return 0 if passed else 1
        parser.print_help()
        return 2
    except (AgentError, GitError, SastError, FileNotFoundError, ValueError) as exc:
        print(f"patchagent-blue: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="patchagent-blue")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="write patchagent-blue.yml")
    init_parser.add_argument("--target", default=".")
    init_parser.add_argument("--force", action="store_true")

    scan_parser = subparsers.add_parser("scan", help="run Semgrep and normalize findings")
    scan_parser.add_argument("--target", required=True)

    subparsers.add_parser("doctor", help="check local PatchAgent-Blue tool setup")

    patch_parser = subparsers.add_parser("patch", help="patch one finding")
    patch_parser.add_argument("--target", required=True)
    patch_parser.add_argument("--finding", required=True)
    patch_parser.add_argument("--agent", default=None)
    patch_parser.add_argument("--run", default=None)
    patch_parser.add_argument("--allow-unsafe-no-git", action="store_true")

    verify_parser = subparsers.add_parser("verify", help="run unit and attack regression tests")
    verify_parser.add_argument("--target", required=True)
    verify_parser.add_argument("--run", required=True)

    run_parser = subparsers.add_parser("run", help="scan, patch, verify")
    run_parser.add_argument("--target", required=True)
    run_parser.add_argument("--agent", default=None)
    run_parser.add_argument("--allow-unsafe-no-git", action="store_true")

    return parser


def run_scan(target: Path, sast_runner: SastRunner | None = None) -> Path:
    target = target.resolve()
    config = load_config(target)
    run_dir = _new_run_dir(target)
    capture_run_start(target, run_dir)
    runner = sast_runner or SastRunner()
    runner.scan(target, config, run_dir)
    capture_run_end(target, run_dir)
    write_report(run_dir)
    return run_dir


def verify_run(target: Path, run_dir: Path) -> bool:
    target = target.resolve()
    config = load_config(target)
    diff_path = _successful_diff_path(run_dir)
    if diff_path is None:
        result = verify_target(target, config, run_dir, phase="after_patch")
        write_report(run_dir)
        return result.passed
    base_commit_path = run_dir / "base_commit.txt"
    base_commit = base_commit_path.read_text(encoding="utf-8").strip() if base_commit_path.exists() else "HEAD"
    verify_worktree = create_worktree(target, run_dir / "verify-worktree", base_commit or "HEAD")
    reset_worktree(verify_worktree)
    apply_diff(verify_worktree, diff_path.read_text(encoding="utf-8"))
    result = verify_target(verify_worktree, config, run_dir, phase="after_patch")
    capture_run_end(target, run_dir)
    write_report(run_dir)
    return result.passed


def patch_finding(
    target: Path,
    run_dir: Path,
    finding_id: str,
    agent_name: str | None,
    allow_unsafe_no_git: bool = False,
    agent_registry: dict[str, BaseAgent] | None = None,
) -> bool:
    target = target.resolve()
    config = load_config(target)
    allow_unsafe_no_git = allow_unsafe_no_git or config.safety.allow_unsafe_no_git
    if config.safety.require_git:
        ensure_git_repo(target, allow_unsafe_no_git=allow_unsafe_no_git)
        if config.safety.require_clean_tree and not allow_unsafe_no_git:
            clean_worktree_required(target)
    capture_run_start(target, run_dir)
    findings = {finding.id: finding for finding in _load_findings(run_dir)}
    if finding_id not in findings:
        raise ValueError(f"Unknown finding id: {finding_id}")
    finding = findings[finding_id]
    registry = agent_registry or default_agent_registry()
    selected = agent_name or config.agent.default
    chain = _resolve_chain(selected, registry, config)
    attempts = _load_attempts(run_dir)
    verify_target(target, config, run_dir, phase="before_patch")
    work_target = target
    worktree_path: Path | None = None
    if (
        config.safety.require_git
        and config.safety.use_worktree
        and not config.safety.direct_modify
        and not allow_unsafe_no_git
    ):
        worktree_path = create_worktree(target, run_dir / "worktree")
        work_target = worktree_path
    for agent in chain[: max(config.limits.max_attempts, 1)]:
        if worktree_path is not None:
            reset_worktree(worktree_path)
        elif config.safety.require_git and config.safety.require_clean_tree and not allow_unsafe_no_git:
            clean_worktree_required(target)
        result = agent.run(work_target, finding, config.tests.unit.commands, run_dir)
        log_path = _write_agent_log(run_dir, finding, result)
        if result.success and result.mode == "diff":
            apply_diff(work_target, result.diff_text or result.stdout)
        diff_text = get_diff(work_target) if config.safety.require_git and not allow_unsafe_no_git else ""
        diff_path = _write_diff(run_dir, finding, agent.name, diff_text)
        if result.success:
            verification = verify_target(work_target, config, run_dir, phase="after_patch")
            status = "passed" if verification.passed else "verification_failed"
        else:
            verification = None
            status = "agent_failed"
        attempts.append(
            PatchAttempt(
                finding_id=finding.id,
                agent=agent.name,
                status=status,
                diff_path=str(diff_path) if diff_path else None,
                log_path=str(log_path),
                message=result.message or result.stderr.strip(),
                provider_mode=result.mode,
                worktree_path=str(worktree_path) if worktree_path else None,
            )
        )
        _write_attempts(run_dir, attempts)
        capture_run_end(target, run_dir)
        write_report(run_dir)
        if result.success and verification and verification.passed:
            return True
        if worktree_path is not None:
            reset_worktree(worktree_path)
        elif diff_text and config.safety.require_git and not allow_unsafe_no_git:
            rollback_diff(target, diff_text)
    return False


def _resolve_chain(agent_name: str, registry: dict[str, BaseAgent], config: AppConfig) -> list[BaseAgent]:
    override = os.environ.get("PATCHAGENT_BLUE_CASCADE_CHAIN") or os.environ.get(
        "PATCHAGENT_BLUE_AUTO_CHAIN"
    )
    if agent_name in {"auto", "cascade"} and override:
        names = [name.strip() for name in override.split(",") if name.strip()]
        missing = [name for name in names if name not in registry]
        if missing:
            raise AgentError(f"Unknown agent in cascade override: {', '.join(missing)}")
        return [registry[name] for name in names]
    return resolve_agent_chain(agent_name, registry, config.agent.cascade_order)


def _new_run_dir(target: Path) -> Path:
    run_id = f"{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:8]}"
    run_dir = target / ".patchagent-blue" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _resolve_run_dir(target: Path, run_id_or_path: str | None) -> Path:
    runs_root = target.resolve() / ".patchagent-blue" / "runs"
    if run_id_or_path:
        candidate = Path(run_id_or_path)
        if candidate.exists():
            return candidate.resolve()
        return runs_root / run_id_or_path
    run_dirs = sorted([path for path in runs_root.iterdir() if path.is_dir()])
    if not run_dirs:
        raise FileNotFoundError("No PatchAgent-Blue run directory found.")
    return run_dirs[-1]


def _load_findings(run_dir: Path) -> list[Finding]:
    data = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    return [Finding.from_dict(item) for item in data]


def _load_attempts(run_dir: Path) -> list[PatchAttempt]:
    path = run_dir / "attempts.json"
    if not path.exists():
        return []
    return [PatchAttempt(**item) for item in json.loads(path.read_text(encoding="utf-8"))]


def _write_attempts(run_dir: Path, attempts: list[PatchAttempt]) -> None:
    (run_dir / "attempts.json").write_text(
        json.dumps([attempt.to_dict() for attempt in attempts], indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _write_agent_log(run_dir: Path, finding: Finding, result) -> Path:
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"agent-{finding.id}-{result.agent}.json"
    log_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return log_path


def _write_diff(run_dir: Path, finding: Finding, agent: str, diff_text: str) -> Path | None:
    if not diff_text.strip():
        return None
    patches_dir = run_dir / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    diff_path = patches_dir / f"{finding.id}-{agent}.diff"
    diff_path.write_text(diff_text, encoding="utf-8")
    return diff_path


def _successful_diff_path(run_dir: Path) -> Path | None:
    attempts_path = run_dir / "attempts.json"
    if not attempts_path.exists():
        return None
    attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
    for attempt in attempts:
        if attempt.get("status") == "passed" and attempt.get("diff_path"):
            path = Path(attempt["diff_path"])
            if path.exists():
                return path
    for attempt in attempts:
        if attempt.get("diff_path"):
            path = Path(attempt["diff_path"])
            if path.exists():
                return path
    return None


if __name__ == "__main__":
    raise SystemExit(main())
