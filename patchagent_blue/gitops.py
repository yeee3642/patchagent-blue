from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


class GitError(RuntimeError):
    pass


def ensure_git_repo(target: Path | str, allow_unsafe_no_git: bool = False) -> None:
    if allow_unsafe_no_git:
        return
    completed = _git(["rev-parse", "--is-inside-work-tree"], Path(target), check=False)
    if completed.returncode != 0 or completed.stdout.strip() != "true":
        raise GitError(
            "Target must be inside a git repository. Use --allow-unsafe-no-git to bypass."
        )


def clean_worktree_required(target: Path | str) -> None:
    completed = _git(
        [
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            ".",
            ":(exclude).patchagent-blue",
        ],
        Path(target),
    )
    if completed.stdout.strip():
        raise GitError("Target git worktree must be clean before patching.")


def git_head(target: Path | str) -> str:
    return _git(["rev-parse", "HEAD"], Path(target)).stdout.strip()


def git_status(target: Path | str) -> str:
    return _git(["status", "--porcelain", "--untracked-files=all"], Path(target)).stdout


def get_diff(target: Path | str) -> str:
    completed = _git(["diff", "--binary", "--", ".", ":(exclude).patchagent-blue"], Path(target))
    return completed.stdout


def apply_diff(target: Path | str, diff_text: str) -> None:
    if not diff_text.strip():
        return
    fd, patch_path = tempfile.mkstemp(prefix="patchagent-blue-apply-", suffix=".patch")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(diff_text)
        _git(["apply", "--check", patch_path], Path(target))
        _git(["apply", "--whitespace=nowarn", patch_path], Path(target))
    finally:
        try:
            os.unlink(patch_path)
        except FileNotFoundError:
            pass


def rollback_diff(target: Path | str, diff_text: str) -> None:
    if not diff_text.strip():
        return
    fd, patch_path = tempfile.mkstemp(prefix="patchagent-blue-rollback-", suffix=".patch")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(diff_text)
        _git(["apply", "-R", "--whitespace=nowarn", patch_path], Path(target))
    finally:
        try:
            os.unlink(patch_path)
        except FileNotFoundError:
            pass


def create_worktree(target: Path | str, worktree_path: Path, ref: str = "HEAD") -> Path:
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    if worktree_path.exists():
        reset_worktree(worktree_path)
        return worktree_path
    _git(["worktree", "add", "--detach", str(worktree_path), ref], Path(target))
    return worktree_path


def reset_worktree(worktree_path: Path | str) -> None:
    worktree = Path(worktree_path)
    _git(["reset", "--hard", "HEAD"], worktree)
    _git(["clean", "-fdx"], worktree)


def _git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode != 0:
        raise GitError(completed.stderr.strip() or completed.stdout.strip() or "git command failed")
    return completed
