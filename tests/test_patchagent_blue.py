import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchagent_blue.agents import ClaudeAgent, CodexAgent, MockAgent, MockDiffAgent
from patchagent_blue.cli import main, patch_finding
from patchagent_blue.config import AppConfig, load_config, write_default_config
from patchagent_blue.gitops import GitError, clean_worktree_required, ensure_git_repo, get_diff, rollback_diff
from patchagent_blue.models import Finding
from patchagent_blue.sast import SastError, SastRunner, normalize_semgrep
from patchagent_blue.verify import run_attack_replays, verify_target


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def init_git_repo(path: Path) -> None:
    run(["git", "init"], path)
    run(["git", "config", "user.email", "test@example.invalid"], path)
    run(["git", "config", "user.name", "PatchAgent Test"], path)


def test_default_config_round_trips(tmp_path):
    config_path = tmp_path / "patchagent-blue.yml"

    write_default_config(config_path)
    config = load_config(tmp_path)

    assert config.version == 1
    assert config.sast.engine == "semgrep"
    assert config.sast.config == "auto"
    assert config.sast.metrics == "off"
    assert config.sast.timeout_sec == 60
    assert config.agent.default == "cascade"
    assert config.agent.cascade_order == ["codex", "claude"]
    assert config.agent.providers["codex"].type == "editing"
    assert config.agent.providers["claude"].type == "editing"
    assert config.tests.unit.commands == []
    assert config.tests.services == []
    assert config.tests.attack.replays == []
    assert config.limits.max_attempts == 2
    assert config.limits.max_changed_files == 8
    assert config.safety.require_git is True
    assert config.safety.require_clean_tree is True
    assert config.safety.direct_modify is False
    assert config.safety.use_worktree is True
    assert ".github/**" in config.safety.deny_modified_paths


def test_config_parses_structured_command_and_replay_schema(tmp_path):
    (tmp_path / "patchagent-blue.yml").write_text(
        "version: 1\n"
        "sast:\n"
        "  engine: semgrep\n"
        "  config: .patchagent-blue/rules\n"
        "  metrics: off\n"
        "  timeout_sec: 90\n"
        "agent:\n"
        "  default: cascade\n"
        "  cascade_order: [\"claude\", \"codex\"]\n"
        "tests:\n"
        "  unit:\n"
        "    commands:\n"
        "      - name: pytest-unit\n"
        "        cmd: [\"pytest\", \"-q\"]\n"
        "        timeout_sec: 120\n"
        "  attack:\n"
        "    replays:\n"
        "      - id: exploit-before-after\n"
        "        type: command\n"
        "        cmd: [\"python\", \"replay.py\"]\n"
        "        timeout_sec: 30\n"
        "        before_patch:\n"
        "          expect_exit_code: 0\n"
        "          expect_stdout_regex: VULNERABLE\n"
        "        after_patch:\n"
        "          expect_exit_code: 0\n"
        "          expect_stdout_regex: BLOCKED\n"
        "safety:\n"
        "  direct_modify: false\n"
        "  use_worktree: true\n",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.sast.config == ".patchagent-blue/rules"
    assert config.sast.timeout_sec == 90
    assert config.agent.cascade_order == ["claude", "codex"]
    assert config.tests.unit.commands[0].name == "pytest-unit"
    assert config.tests.unit.commands[0].cmd == ["pytest", "-q"]
    assert config.tests.attack.replays[0].id == "exploit-before-after"
    assert config.tests.attack.replays[0].before_patch.expect_stdout_regex == "VULNERABLE"
    assert config.tests.attack.replays[0].after_patch.expect_stdout_regex == "BLOCKED"


def test_normalize_semgrep_results_creates_stable_findings(tmp_path):
    raw = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": str(tmp_path / "app.py"),
                "start": {"line": 10, "col": 5},
                "end": {"line": 10, "col": 16},
                "extra": {
                    "message": "Use of eval on attacker controlled input",
                    "severity": "ERROR",
                    "lines": "return eval(expr)",
                    "metadata": {"cwe": ["CWE-95"]},
                },
            }
        ]
    }

    findings = normalize_semgrep(raw, tmp_path)

    assert findings[0].finding_id == "F0001"
    assert findings[0].id == "F0001"
    assert findings[0].tool == "semgrep"
    assert findings[0].rule_id == "python.lang.security.audit.eval-detected"
    assert findings[0].message == "Use of eval on attacker controlled input"
    assert findings[0].title == "Use of eval on attacker controlled input"
    assert findings[0].severity == "ERROR"
    assert findings[0].path == "app.py"
    assert findings[0].start_line == 10
    assert findings[0].start_col == 5
    assert findings[0].end_line == 10
    assert findings[0].end_col == 16
    assert findings[0].code_snippet == "return eval(expr)"
    assert findings[0].code == "return eval(expr)"
    assert findings[0].cwe == ["CWE-95"]
    assert len(findings[0].fingerprint) == 64

    shifted_raw = json.loads(json.dumps(raw))
    shifted_raw["results"][0]["start"]["line"] = 11
    shifted_raw["results"][0]["end"]["line"] = 11
    shifted = normalize_semgrep(shifted_raw, tmp_path)[0]
    assert shifted.fingerprint != findings[0].fingerprint


def test_agent_command_builders_are_noninteractive(tmp_path):
    finding = Finding(
        id="F0001",
        rule_id="demo.eval",
        title="eval detected",
        severity="ERROR",
        path="app.py",
        start_line=2,
        end_line=2,
        code="return eval(expr)",
        metadata={},
    )

    codex_cmd = CodexAgent().build_command(tmp_path, finding, ["python -m unittest"])
    claude_cmd = ClaudeAgent().build_command(tmp_path, finding, ["python -m unittest"])

    assert CodexAgent().mode == "editing"
    assert ClaudeAgent().mode == "editing"
    assert codex_cmd[:2] == ["codex", "exec"]
    assert "--cd" in codex_cmd
    assert "--sandbox" in codex_cmd
    assert "workspace-write" in codex_cmd
    assert "--ask-for-approval" in codex_cmd
    assert "never" in codex_cmd
    assert "eval detected" in codex_cmd[-1]

    assert "--bare" in claude_cmd
    assert claude_cmd[:2] == ["claude", "--bare"]
    assert "--permission-mode" in claude_cmd
    assert "acceptEdits" in claude_cmd
    assert "--output-format" in claude_cmd
    assert "stream-json" in claude_cmd
    assert "--add-dir" in claude_cmd
    assert "eval detected" in claude_cmd[-1]


def test_diff_provider_returns_unified_diff(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def parse_expr(expr):\n    return eval(expr)\n", encoding="utf-8")
    finding = Finding("F0001", "semgrep", "demo.eval", "app.py", 2, 12, 2, 22, "eval", "ERROR")

    result = MockDiffAgent().run(tmp_path, finding, [], tmp_path)

    assert result.mode == "diff"
    assert result.diff_text
    assert "--- app.py" in result.diff_text
    assert "+import ast" in result.diff_text


def test_git_preflight_and_rollback(tmp_path):
    with pytest.raises(GitError):
        ensure_git_repo(tmp_path, allow_unsafe_no_git=False)

    init_git_repo(tmp_path)
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run(["git", "add", "app.py"], tmp_path)
    run(["git", "commit", "-m", "initial"], tmp_path)

    ensure_git_repo(tmp_path, allow_unsafe_no_git=False)
    source.write_text("value = 2\n", encoding="utf-8")

    with pytest.raises(GitError):
        clean_worktree_required(tmp_path)

    diff = get_diff(tmp_path)
    assert "value = 2" in diff
    rollback_diff(tmp_path, diff)
    assert source.read_text(encoding="utf-8") == "value = 1\n"


def test_attack_replay_expectations(tmp_path):
    replay = tmp_path / "attack.json"
    replay.write_text(
        json.dumps(
            {
                "name": "blocks payload",
                "command": f'"{sys.executable}" -c "import sys; print(\'blocked\'); sys.exit(1)"',
                "expect_exit": 1,
                "expect_stdout_contains": "blocked",
                "expect_stderr_not_contains": "Traceback",
            }
        ),
        encoding="utf-8",
    )
    config = AppConfig()
    config.tests.attack.replays = [str(replay)]

    result = run_attack_replays(tmp_path, config, tmp_path / "logs", phase="after_patch")

    assert result.passed is True
    assert result.results[0]["name"] == "blocks payload"
    assert result.results[0]["passed"] is True


def test_attack_replay_before_after_schema(tmp_path):
    replay_script = tmp_path / "replay.py"
    replay_script.write_text(
        "import os\n"
        "phase = os.environ.get('PHASE')\n"
        "print('VULNERABLE' if phase == 'before_patch' else 'BLOCKED')\n",
        encoding="utf-8",
    )
    config = AppConfig()
    config.tests.attack.replays = [
        {
            "id": "before-after",
            "type": "command",
            "cmd": [sys.executable, str(replay_script)],
            "env": {"PHASE": "before_patch"},
            "before_patch": {"expect_exit_code": 0, "expect_stdout_regex": "VULNERABLE"},
            "after_patch": {"expect_exit_code": 0, "expect_stdout_regex": "BLOCKED"},
        }
    ]

    before = run_attack_replays(tmp_path, config, tmp_path / "before", phase="before_patch")
    config.tests.attack.replays[0]["env"]["PHASE"] = "after_patch"
    after = run_attack_replays(tmp_path, config, tmp_path / "after", phase="after_patch")

    assert before.passed is True
    assert after.passed is True


def test_verification_reports_unit_and_attack_failures(tmp_path):
    replay = tmp_path / "attack.json"
    replay.write_text(
        json.dumps(
            {
                "name": "missing output",
                "command": f'"{sys.executable}" -c "print(\'actual\')"',
                "expect_exit": 0,
                "expect_stdout_contains": "expected",
            }
        ),
        encoding="utf-8",
    )
    config = AppConfig()
    config.tests.unit.commands = [f'"{sys.executable}" -c "import sys; sys.exit(3)"']
    config.tests.attack.replays = [str(replay)]

    result = verify_target(tmp_path, config, tmp_path / "run")

    assert result.passed is False
    assert result.unit.results[0]["returncode"] == 3
    assert result.attack.results[0]["passed"] is False
    assert "expected stdout" in result.attack.results[0]["failures"][0]


def test_sast_runner_reports_missing_semgrep(tmp_path, monkeypatch):
    import patchagent_blue.sast as sast_module

    monkeypatch.delenv("PATCHAGENT_BLUE_SEMGREP_CMD", raising=False)
    monkeypatch.setattr(sast_module.shutil, "which", lambda name: None)

    with pytest.raises(SastError, match="Semgrep is not installed"):
        SastRunner().scan(tmp_path, AppConfig(), tmp_path / "run")


def test_mock_agent_repairs_python_and_js_eval(tmp_path):
    python_file = tmp_path / "app.py"
    python_file.write_text("def parse_expr(expr):\n    return eval(expr)\n", encoding="utf-8")
    js_file = tmp_path / "app.js"
    js_file.write_text("function parseExpr(expr) {\n  return eval(expr);\n}\n", encoding="utf-8")

    agent = MockAgent()
    agent.run(tmp_path, Finding("F1", "demo.eval", "eval", "ERROR", "app.py", 2, 2, "eval", {}), [], tmp_path)
    agent.run(tmp_path, Finding("F2", "demo.eval", "eval", "ERROR", "app.js", 2, 2, "eval", {}), [], tmp_path)

    assert "import ast" in python_file.read_text(encoding="utf-8")
    assert "ast.literal_eval(expr)" in python_file.read_text(encoding="utf-8")
    assert "JSON.parse(expr)" in js_file.read_text(encoding="utf-8")


def test_auto_agent_falls_back_to_mock_after_failed_agent(tmp_path, monkeypatch):
    init_git_repo(tmp_path)
    source = tmp_path / "app.py"
    source.write_text("def parse_expr(expr):\n    return eval(expr)\n", encoding="utf-8")
    (tmp_path / "patchagent-blue.yml").write_text(
        "sast:\n"
        "  config: auto\n"
        "agent:\n"
        "  default: cascade\n"
        "tests:\n"
        "  unit:\n"
        "    commands: []\n"
        "  attack:\n"
        "    replays: []\n"
        "limits:\n"
        "  max_attempts: 2\n"
        "safety:\n"
        "  require_git: true\n"
        "  direct_modify: true\n"
        "  use_worktree: false\n",
        encoding="utf-8",
    )
    run(["git", "add", "."], tmp_path)
    run(["git", "commit", "-m", "initial"], tmp_path)
    run_dir = tmp_path / ".patchagent-blue" / "runs" / "fallback"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text(
        json.dumps(
            [
                Finding(
                    "F0001",
                    "demo.eval",
                    "eval detected",
                    "ERROR",
                    "app.py",
                    2,
                    2,
                    "return eval(expr)",
                    {},
                ).to_dict()
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATCHAGENT_BLUE_CASCADE_CHAIN", "fail,mock")

    assert patch_finding(tmp_path, run_dir, "F0001", "cascade") is True

    attempts = json.loads((run_dir / "attempts.json").read_text(encoding="utf-8"))
    assert [attempt["agent"] for attempt in attempts] == ["fail", "mock"]
    assert attempts[0]["status"] == "agent_failed"
    assert attempts[1]["status"] == "passed"
    assert "ast.literal_eval(expr)" in source.read_text(encoding="utf-8")


def test_worktree_mode_leaves_target_unchanged_and_stores_diff(tmp_path, monkeypatch):
    init_git_repo(tmp_path)
    source = tmp_path / "app.py"
    source.write_text("def parse_expr(expr):\n    return eval(expr)\n", encoding="utf-8")
    replay_dir = tmp_path / "tests" / "attack"
    replay_dir.mkdir(parents=True)
    replay = replay_dir / "content_check.json"
    replay.write_text(
        json.dumps(
            {
                "id": "patched-content",
                "type": "command",
                "cmd": [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; "
                    "print('PATCHED' if 'ast.literal_eval' in Path('app.py').read_text() else 'ORIGINAL')",
                ],
                "after_patch": {"expect_exit_code": 0, "expect_stdout_regex": "PATCHED"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "patchagent-blue.yml").write_text(
        "agent:\n"
        "  default: mock\n"
        "tests:\n"
        "  unit:\n"
        "    commands: []\n"
        "  attack:\n"
        "    replays:\n"
        "      - tests/attack/content_check.json\n"
        "safety:\n"
        "  require_git: true\n"
        "  require_clean_tree: true\n"
        "  direct_modify: false\n"
        "  use_worktree: true\n",
        encoding="utf-8",
    )
    run(["git", "add", "."], tmp_path)
    run(["git", "commit", "-m", "initial"], tmp_path)
    run_dir = tmp_path / ".patchagent-blue" / "runs" / "worktree"
    run_dir.mkdir(parents=True)
    finding = Finding("F0001", "semgrep", "demo.eval", "app.py", 2, 12, 2, 22, "eval", "ERROR")
    (run_dir / "findings.json").write_text(json.dumps([finding.to_dict()]), encoding="utf-8")

    assert patch_finding(tmp_path, run_dir, "F0001", "mock") is True

    assert source.read_text(encoding="utf-8") == "def parse_expr(expr):\n    return eval(expr)\n"
    attempts = json.loads((run_dir / "attempts.json").read_text(encoding="utf-8"))
    diff_path = Path(attempts[0]["diff_path"])
    assert diff_path.exists()
    assert "ast.literal_eval(expr)" in diff_path.read_text(encoding="utf-8")
    assert (run_dir / "base_commit.txt").exists()
    assert (run_dir / "environment.json").exists()
    assert (run_dir / "manifest.snapshot.json").exists()
    assert main(["verify", "--target", str(tmp_path), "--run", str(run_dir)]) == 0


def test_cli_run_with_mock_agent_creates_artifacts_and_report(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    init_git_repo(target)
    (target / "app.py").write_text("def parse_expr(expr):\n    return eval(expr)\n", encoding="utf-8")
    (target / "test_app.py").write_text(
        "import unittest\n"
        "from app import parse_expr\n\n"
        "class ParseTests(unittest.TestCase):\n"
        "    def test_safe_literal(self):\n"
        "        self.assertEqual(parse_expr(\"{'safe': 1}\"), {'safe': 1})\n",
        encoding="utf-8",
    )
    attack_dir = target / "tests" / "attack"
    attack_dir.mkdir(parents=True)
    attack_payload = "__import__('os').system('echo PWNED')"
    (attack_dir / "eval_payload.json").write_text(
        json.dumps(
            {
                "name": "eval payload is rejected",
                "command": (
                    f'"{sys.executable}" -c '
                    f'"from app import parse_expr; parse_expr({attack_payload!r})"'
                ),
                "expect_exit": 1,
                "expect_stdout_not_contains": "PWNED",
            }
        ),
        encoding="utf-8",
    )
    (target / "patchagent-blue.yml").write_text(
        "sast:\n"
        "  config: auto\n"
        "agent:\n"
        "  default: mock\n"
        "tests:\n"
        "  unit:\n"
        "    commands:\n"
        f"      - \"{sys.executable}\" -m unittest discover\n"
        "  attack:\n"
        "    replays:\n"
        "      - tests/attack/eval_payload.json\n"
        "limits:\n"
        "  max_attempts: 2\n"
        "safety:\n"
        "  require_git: true\n"
        "  direct_modify: true\n"
        "  use_worktree: false\n",
        encoding="utf-8",
    )
    fake_semgrep = tmp_path / "fake_semgrep.py"
    fake_semgrep.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "target = Path(sys.argv[-1])\n"
        "print(json.dumps({'results': [{'check_id': 'demo.eval', 'path': str(target / 'app.py'), "
        "'start': {'line': 2, 'col': 12}, 'end': {'line': 2, 'col': 22}, "
        "'extra': {'message': 'eval detected', 'severity': 'ERROR', 'lines': 'return eval(expr)', "
        "'metadata': {'category': 'code-injection'}}}]}))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATCHAGENT_BLUE_SEMGREP_CMD", f'"{sys.executable}" "{fake_semgrep}"')
    run(["git", "add", "."], target)
    run(["git", "commit", "-m", "initial"], target)

    exit_code = main(["run", "--target", str(target), "--agent", "mock"])

    assert exit_code == 0
    assert "ast.literal_eval(expr)" in (target / "app.py").read_text(encoding="utf-8")
    run_root = target / ".patchagent-blue" / "runs"
    run_dirs = list(run_root.iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    assert (run_dir / "semgrep.raw.json").exists()
    assert (run_dir / "findings.json").exists()
    assert (run_dir / "attempts.json").exists()
    assert (run_dir / "verify.json").exists()
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "PatchAgent-Blue Report" in report
    assert "F0001" in report
    assert "mock" in report


def test_doctor_reports_missing_semgrep(monkeypatch, capsys):
    import patchagent_blue.doctor as doctor_module

    monkeypatch.setattr(doctor_module.shutil, "which", lambda name: None if name == "semgrep" else f"/bin/{name}")

    assert main(["doctor"]) == 0
    output = capsys.readouterr().out
    assert "[MISSING] semgrep" in output
    assert "python -m pip install semgrep" in output
