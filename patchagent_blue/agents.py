from __future__ import annotations

import difflib
import subprocess
from pathlib import Path
from typing import Any

from .models import AgentRunResult, Finding


class AgentError(RuntimeError):
    pass


class BaseAgent:
    name = "base"
    mode = "editing"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        raise NotImplementedError

    def run(
        self, target: Path | str, finding: Finding, test_commands: list[Any], run_dir: Path
    ) -> AgentRunResult:
        target_path = Path(target).resolve()
        command = self.build_command(target_path, finding, test_commands)
        completed = subprocess.run(
            command,
            cwd=target_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return AgentRunResult(
            agent=self.name,
            success=completed.returncode == 0,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            mode=self.mode,
        )


class CodexAgent(BaseAgent):
    name = "codex"
    mode = "editing"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        return [
            "codex",
            "exec",
            "--cd",
            str(target),
            "--sandbox",
            "workspace-write",
            "--ask-for-approval",
            "never",
            _patch_prompt(finding, test_commands),
        ]


class ClaudeAgent(BaseAgent):
    name = "claude"
    mode = "editing"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        return [
            "claude",
            "--bare",
            "-p",
            "--permission-mode",
            "acceptEdits",
            "--output-format",
            "stream-json",
            "--add-dir",
            str(target),
            _patch_prompt(finding, test_commands),
        ]


class MockAgent(BaseAgent):
    name = "mock"
    mode = "editing"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        return ["mock-agent", finding.id]

    def run(
        self, target: Path | str, finding: Finding, test_commands: list[Any], run_dir: Path
    ) -> AgentRunResult:
        target_path = Path(target).resolve()
        file_path = target_path / finding.path
        if not file_path.exists():
            return AgentRunResult(
                self.name,
                False,
                stderr=f"File not found: {finding.path}",
                returncode=1,
                mode=self.mode,
            )
        original = file_path.read_text(encoding="utf-8")
        changed = _mock_repair(file_path, original)
        if changed == original:
            return AgentRunResult(
                self.name,
                False,
                stderr="No supported mock repair was found.",
                returncode=2,
                mode=self.mode,
            )
        file_path.write_text(changed, encoding="utf-8")
        return AgentRunResult(
            self.name,
            True,
            stdout=f"Applied mock repair to {finding.path}\n",
            returncode=0,
            mode=self.mode,
        )


class MockDiffAgent(BaseAgent):
    name = "mock-diff"
    mode = "diff"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        return ["mock-diff-agent", finding.id]

    def run(
        self, target: Path | str, finding: Finding, test_commands: list[Any], run_dir: Path
    ) -> AgentRunResult:
        target_path = Path(target).resolve()
        file_path = target_path / finding.path
        if not file_path.exists():
            return AgentRunResult(
                self.name,
                False,
                stderr=f"File not found: {finding.path}",
                returncode=1,
                mode=self.mode,
            )
        original = file_path.read_text(encoding="utf-8")
        changed = _mock_repair(file_path, original)
        if changed == original:
            return AgentRunResult(
                self.name,
                False,
                stderr="No supported mock diff repair was found.",
                returncode=2,
                mode=self.mode,
            )
        diff_text = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                changed.splitlines(keepends=True),
                fromfile=finding.path,
                tofile=finding.path,
            )
        )
        return AgentRunResult(
            self.name,
            True,
            stdout=diff_text,
            returncode=0,
            mode=self.mode,
            diff_text=diff_text,
        )


class FailAgent(BaseAgent):
    name = "fail"
    mode = "editing"

    def build_command(self, target: Path, finding: Finding, test_commands: list[Any]) -> list[str]:
        return ["fail-agent", finding.id]

    def run(
        self, target: Path | str, finding: Finding, test_commands: list[Any], run_dir: Path
    ) -> AgentRunResult:
        return AgentRunResult(
            self.name, False, stderr="Configured failure agent.", returncode=1, mode=self.mode
        )


def default_agent_registry() -> dict[str, BaseAgent]:
    return {
        "codex": CodexAgent(),
        "claude": ClaudeAgent(),
        "mock": MockAgent(),
        "mock-diff": MockDiffAgent(),
        "fail": FailAgent(),
    }


def resolve_agent_chain(
    agent: str, registry: dict[str, BaseAgent], cascade_order: list[str] | None = None
) -> list[BaseAgent]:
    if agent in {"auto", "cascade"}:
        return _resolve_order(cascade_order or ["codex", "claude"], registry)
    if ">" in agent:
        return _resolve_order([name.strip() for name in agent.split(">") if name.strip()], registry)
    if "," in agent:
        return _resolve_order([name.strip() for name in agent.split(",") if name.strip()], registry)
    if agent not in registry:
        raise AgentError(f"Unknown agent: {agent}")
    return [registry[agent]]


def _resolve_order(order: list[str], registry: dict[str, BaseAgent]) -> list[BaseAgent]:
    missing = [name for name in order if name not in registry]
    if missing:
        raise AgentError(f"Unknown cascade provider: {', '.join(missing)}")
    return [registry[name] for name in order]


def _patch_prompt(finding: Finding, test_commands: list[Any]) -> str:
    tests = "\n".join(f"- {_command_text(command)}" for command in test_commands) or "- No unit command configured"
    return (
        "PatchAgent-Blue security fix task.\n"
        f"Finding: {finding.id}\n"
        f"Rule: {finding.rule_id}\n"
        f"Severity: {finding.severity}\n"
        f"Title: {finding.title}\n"
        f"Location: {finding.path}:{finding.start_line}-{finding.end_line}\n"
        f"Fingerprint: {finding.fingerprint}\n"
        f"Evidence:\n{finding.code}\n\n"
        "You may edit files directly. Do not modify tests, CI, lockfiles, Semgrep config, "
        "or attack replay files. After editing, stop; the orchestrator will run tests.\n"
        "Security invariant: remove the vulnerable behavior at the narrowest boundary while "
        "preserving legitimate behavior. Add or preserve focused tests when feasible.\n"
        "Run these validation commands before claiming success:\n"
        f"{tests}\n"
    )


def _command_text(command: Any) -> str:
    value = command.cmd if hasattr(command, "cmd") else command
    if isinstance(value, list):
        return subprocess.list2cmdline([str(item) for item in value])
    return str(value)


def _mock_repair(file_path: Path, text: str) -> str:
    suffix = file_path.suffix.lower()
    if suffix == ".py" and "eval(" in text:
        repaired = text.replace("eval(", "ast.literal_eval(")
        if "import ast" not in repaired:
            repaired = "import ast\n" + repaired
        return repaired
    if suffix in {".js", ".jsx", ".ts", ".tsx"} and "eval(" in text:
        return text.replace("eval(", "JSON.parse(")
    return text
