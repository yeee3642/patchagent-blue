from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_NAME = "patchagent-blue.yml"


@dataclass
class SastConfig:
    engine: str = "semgrep"
    config: str = "auto"
    metrics: str = "off"
    timeout_sec: int = 60
    save_raw_json: bool = True
    pin_semgrep_version: bool = True
    save_rule_hash: bool = True


@dataclass
class ProviderConfig:
    type: str = "editing"
    command: list[str] = field(default_factory=list)


@dataclass
class AgentConfig:
    default: str = "cascade"
    cascade_order: list[str] = field(default_factory=lambda: ["codex", "claude"])
    providers: dict[str, ProviderConfig] = field(
        default_factory=lambda: {
            "codex": ProviderConfig(
                type="editing",
                command=[
                    "codex",
                    "exec",
                    "--sandbox",
                    "workspace-write",
                    "--ask-for-approval",
                    "never",
                ],
            ),
            "claude": ProviderConfig(
                type="editing",
                command=[
                    "claude",
                    "--bare",
                    "-p",
                    "--permission-mode",
                    "acceptEdits",
                    "--output-format",
                    "stream-json",
                ],
            ),
        }
    )


@dataclass
class CommandSpec:
    name: str
    cmd: list[str] | str
    timeout_sec: int | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class UnitTestConfig:
    commands: list[CommandSpec | str] = field(default_factory=list)


@dataclass
class ServiceConfig:
    name: str
    start: list[str] | str
    readiness: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ReplayExpectation:
    expect_exit_code: int | None = None
    expect_stdout_regex: str | None = None
    expect_stderr_regex: str | None = None
    expect_stdout_contains: str | list[str] | None = None
    expect_stderr_contains: str | list[str] | None = None
    expect_stdout_not_contains: str | list[str] | None = None
    expect_stderr_not_contains: str | list[str] | None = None


@dataclass
class AttackReplay:
    id: str
    type: str = "command"
    cmd: list[str] | str = ""
    timeout_sec: int | None = None
    env: dict[str, str] = field(default_factory=dict)
    before_patch: ReplayExpectation | None = None
    after_patch: ReplayExpectation | None = None


@dataclass
class AttackTestConfig:
    replays: list[AttackReplay | str | dict[str, Any]] = field(default_factory=list)


@dataclass
class TestsConfig:
    unit: UnitTestConfig = field(default_factory=UnitTestConfig)
    services: list[ServiceConfig | dict[str, Any]] = field(default_factory=list)
    attack: AttackTestConfig = field(default_factory=AttackTestConfig)


@dataclass
class LimitsConfig:
    max_attempts: int = 2
    max_changed_files: int = 8
    max_changed_lines: int = 500
    command_timeout_sec: int = 1800


@dataclass
class SafetyConfig:
    require_git: bool = True
    require_clean_tree: bool = True
    direct_modify: bool = False
    use_worktree: bool = True
    allow_unsafe_no_git: bool = False
    deny_modified_paths: list[str] = field(
        default_factory=lambda: [
            ".github/**",
            "tests/**",
            "test/**",
            ".patchagent-blue/replays/**",
            ".semgrep*",
            "semgrep.yml",
            "package-lock.json",
            "poetry.lock",
            "requirements*.txt",
        ]
    )


@dataclass
class AppConfig:
    version: int = 1
    sast: SastConfig = field(default_factory=SastConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    tests: TestsConfig = field(default_factory=TestsConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)


DEFAULT_CONFIG = """version: 1
sast:
  engine: semgrep
  config: auto
  metrics: off
  timeout_sec: 60
  save_raw_json: true
  pin_semgrep_version: true
  save_rule_hash: true
agent:
  default: cascade
  cascade_order: ["codex", "claude"]
  providers:
    codex:
      type: editing
      command: ["codex", "exec", "--sandbox", "workspace-write", "--ask-for-approval", "never"]
    claude:
      type: editing
      command: ["claude", "--bare", "-p", "--permission-mode", "acceptEdits", "--output-format", "stream-json"]
tests:
  unit:
    commands: []
  services: []
  attack:
    replays: []
limits:
  max_attempts: 2
  max_changed_files: 8
  max_changed_lines: 500
  command_timeout_sec: 1800
safety:
  require_git: true
  require_clean_tree: true
  direct_modify: false
  use_worktree: true
  allow_unsafe_no_git: false
  deny_modified_paths:
    - ".github/**"
    - "tests/**"
    - "test/**"
    - ".patchagent-blue/replays/**"
    - ".semgrep*"
    - "semgrep.yml"
    - "package-lock.json"
    - "poetry.lock"
    - "requirements*.txt"
"""


class ConfigError(ValueError):
    pass


def config_path_for(target_or_file: Path | str) -> Path:
    path = Path(target_or_file)
    if path.is_dir() or path.suffix == "":
        return path / CONFIG_NAME
    return path


def write_default_config(path: Path | str, force: bool = False) -> Path:
    config_path = Path(path)
    if config_path.is_dir() or config_path.suffix == "":
        config_path = config_path / CONFIG_NAME
    if config_path.exists() and not force:
        raise ConfigError(f"Config already exists: {config_path}")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    return config_path


def load_config(target_or_file: Path | str) -> AppConfig:
    config_path = config_path_for(target_or_file)
    if not config_path.exists():
        return AppConfig()
    data = _parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    return _config_from_dict(data)


def normalize_command(command: CommandSpec | str | dict[str, Any], default_name: str) -> CommandSpec:
    if isinstance(command, CommandSpec):
        return command
    if isinstance(command, str):
        return CommandSpec(name=default_name, cmd=command)
    return CommandSpec(
        name=str(command.get("name") or command.get("id") or default_name),
        cmd=command.get("cmd", command.get("command", "")),
        timeout_sec=_optional_int(command.get("timeout_sec")),
        env={str(k): str(v) for k, v in dict(command.get("env") or {}).items()},
    )


def normalize_replay(replay: AttackReplay | str | dict[str, Any], default_id: str) -> AttackReplay | str:
    if isinstance(replay, AttackReplay):
        return replay
    if isinstance(replay, str):
        return replay
    command = replay.get("cmd", replay.get("command", ""))
    before = _expectation_from_dict(replay.get("before_patch"))
    after = _expectation_from_dict(replay.get("after_patch"))
    if before is None and after is None:
        after = _expectation_from_dict(replay)
    return AttackReplay(
        id=str(replay.get("id") or replay.get("name") or default_id),
        type=str(replay.get("type") or "command"),
        cmd=command,
        timeout_sec=_optional_int(replay.get("timeout_sec")),
        env={str(k): str(v) for k, v in dict(replay.get("env") or {}).items()},
        before_patch=before,
        after_patch=after,
    )


def _config_from_dict(data: dict[str, Any]) -> AppConfig:
    config = AppConfig()
    config.version = int(data.get("version", config.version) or 1)
    config.sast.engine = str(_get(data, "sast", "engine", default=config.sast.engine))
    config.sast.config = str(_get(data, "sast", "config", default=config.sast.config))
    config.sast.metrics = str(_get(data, "sast", "metrics", default=config.sast.metrics))
    config.sast.timeout_sec = int(_get(data, "sast", "timeout_sec", default=config.sast.timeout_sec))
    config.sast.save_raw_json = bool(
        _get(data, "sast", "save_raw_json", default=config.sast.save_raw_json)
    )
    config.sast.pin_semgrep_version = bool(
        _get(data, "sast", "pin_semgrep_version", default=config.sast.pin_semgrep_version)
    )
    config.sast.save_rule_hash = bool(
        _get(data, "sast", "save_rule_hash", default=config.sast.save_rule_hash)
    )
    config.agent.default = str(_get(data, "agent", "default", default=config.agent.default))
    config.agent.cascade_order = _as_string_list(
        _get(data, "agent", "cascade_order", default=config.agent.cascade_order)
    )
    provider_data = _get(data, "agent", "providers", default={})
    if isinstance(provider_data, dict):
        providers = dict(config.agent.providers)
        for name, provider in provider_data.items():
            if isinstance(provider, dict):
                providers[str(name)] = ProviderConfig(
                    type=str(provider.get("type", providers.get(str(name), ProviderConfig()).type)),
                    command=_as_string_list(provider.get("command", [])),
                )
        config.agent.providers = providers
    config.tests.unit.commands = [
        normalize_command(item, f"unit-{index}")
        for index, item in enumerate(
            _as_list(_get(data, "tests", "unit", "commands", default=[])), start=1
        )
    ]
    config.tests.services = _as_list(_get(data, "tests", "services", default=[]))
    config.tests.attack.replays = [
        normalize_replay(item, f"attack-{index}")
        for index, item in enumerate(
            _as_list(_get(data, "tests", "attack", "replays", default=[])), start=1
        )
    ]
    config.limits.max_attempts = int(
        _get(data, "limits", "max_attempts", default=config.limits.max_attempts)
    )
    config.limits.max_changed_files = int(
        _get(data, "limits", "max_changed_files", default=config.limits.max_changed_files)
    )
    config.limits.max_changed_lines = int(
        _get(data, "limits", "max_changed_lines", default=config.limits.max_changed_lines)
    )
    config.limits.command_timeout_sec = int(
        _get(data, "limits", "command_timeout_sec", default=config.limits.command_timeout_sec)
    )
    config.safety.require_git = bool(
        _get(data, "safety", "require_git", default=config.safety.require_git)
    )
    config.safety.require_clean_tree = bool(
        _get(data, "safety", "require_clean_tree", default=config.safety.require_clean_tree)
    )
    config.safety.direct_modify = bool(
        _get(data, "safety", "direct_modify", default=config.safety.direct_modify)
    )
    config.safety.use_worktree = bool(
        _get(data, "safety", "use_worktree", default=config.safety.use_worktree)
    )
    config.safety.allow_unsafe_no_git = bool(
        _get(data, "safety", "allow_unsafe_no_git", default=config.safety.allow_unsafe_no_git)
    )
    deny_modified_paths = _get(
        data, "safety", "deny_modified_paths", default=config.safety.deny_modified_paths
    )
    config.safety.deny_modified_paths = _as_string_list(deny_modified_paths)
    return config


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2:
            raise ConfigError(f"Only two-space indentation is supported: {raw_line}")
        lines.append((indent, raw_line.strip()))
    if not lines:
        return {}
    parsed, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise ConfigError(f"Could not parse line: {lines[index][1]}")
    if not isinstance(parsed, dict):
        raise ConfigError("Top-level config must be a mapping")
    return parsed


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        return _parse_list(lines, index, indent)
    return _parse_map(lines, index, indent)


def _parse_map(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or content.startswith("- "):
            break
        if ":" not in content:
            raise ConfigError(f"Expected key: value line: {content}")
        key, value = content.split(":", 1)
        key = key.strip()
        value = value.strip()
        index += 1
        if value:
            result[key] = _parse_scalar(value)
            continue
        if index < len(lines) and lines[index][0] > line_indent:
            child, index = _parse_block(lines, index, lines[index][0])
            result[key] = child
        else:
            result[key] = {}
    return result, index


def _parse_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or not content.startswith("- "):
            break
        item_content = content[2:].strip()
        index += 1
        if not item_content:
            item: Any = {}
            if index < len(lines) and lines[index][0] > line_indent:
                item, index = _parse_block(lines, index, lines[index][0])
            result.append(item)
            continue
        if _looks_like_key_value(item_content):
            key, value = item_content.split(":", 1)
            item_dict: dict[str, Any] = {key.strip(): _parse_scalar(value.strip()) if value.strip() else {}}
            if not value.strip() and index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_block(lines, index, lines[index][0])
                item_dict[key.strip()] = child
            if index < len(lines) and lines[index][0] > line_indent:
                continuation, index = _parse_map(lines, index, lines[index][0])
                item_dict.update(continuation)
            result.append(item_dict)
        else:
            result.append(_parse_scalar(item_content))
    return result, index


def _parse_scalar(value: str) -> Any:
    if value == "":
        return ""
    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower in {"null", "none"}:
        return None
    if value.isdigit():
        return int(value)
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            try:
                return ast.literal_eval(value)
            except (SyntaxError, ValueError):
                return value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _looks_like_key_value(value: str) -> bool:
    if ":" not in value:
        return False
    key = value.split(":", 1)[0].strip()
    return bool(key) and " " not in key


def _expectation_from_dict(data: Any) -> ReplayExpectation | None:
    if not isinstance(data, dict):
        return None
    return ReplayExpectation(
        expect_exit_code=_optional_int(data.get("expect_exit_code", data.get("expect_exit"))),
        expect_stdout_regex=data.get("expect_stdout_regex"),
        expect_stderr_regex=data.get("expect_stderr_regex"),
        expect_stdout_contains=data.get("expect_stdout_contains"),
        expect_stderr_contains=data.get("expect_stderr_contains"),
        expect_stdout_not_contains=data.get("expect_stdout_not_contains"),
        expect_stderr_not_contains=data.get("expect_stderr_not_contains"),
    )


def _get(data: dict[str, Any], *path: str, default: Any) -> Any:
    current: Any = data
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_string_list(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value)]


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)
