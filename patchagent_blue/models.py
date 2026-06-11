from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


def fingerprint_finding(
    rule_id: str, path: str, start_line: int, end_line: int, message: str, snippet: str
) -> str:
    stable = {
        "rule_id": rule_id,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "message": message,
        "snippet_hash": hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:16],
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(init=False, eq=True)
class Finding:
    finding_id: str
    tool: Literal["semgrep"]
    rule_id: str
    path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    message: str
    severity: str | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    metavars: dict[str, Any] = field(default_factory=dict)
    code_snippet: str = ""
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs:
            values = self._from_kwargs(kwargs)
        elif len(args) >= 10 and args[1] == "semgrep":
            values = {
                "finding_id": args[0],
                "tool": args[1],
                "rule_id": args[2],
                "path": args[3],
                "start_line": args[4],
                "start_col": args[5],
                "end_line": args[6],
                "end_col": args[7],
                "message": args[8],
                "severity": args[9],
            }
        elif len(args) >= 8:
            values = {
                "finding_id": args[0],
                "tool": "semgrep",
                "rule_id": args[1],
                "message": args[2],
                "severity": args[3],
                "path": args[4],
                "start_line": args[5],
                "start_col": 0,
                "end_line": args[6],
                "end_col": 0,
                "code_snippet": args[7],
                "metadata": args[8] if len(args) > 8 else {},
            }
        else:
            raise TypeError("Finding requires either keyword values or a supported positional shape")
        self.finding_id = str(values.get("finding_id", values.get("id", "")))
        self.tool = "semgrep"
        self.rule_id = str(values.get("rule_id", ""))
        self.path = str(values.get("path", ""))
        self.start_line = int(values.get("start_line", 0) or 0)
        self.start_col = int(values.get("start_col", 0) or 0)
        self.end_line = int(values.get("end_line", self.start_line) or 0)
        self.end_col = int(values.get("end_col", self.start_col) or 0)
        self.message = str(values.get("message", values.get("title", "")))
        self.severity = values.get("severity")
        self.cwe = [str(item) for item in values.get("cwe", [])]
        self.owasp = [str(item) for item in values.get("owasp", [])]
        self.metavars = dict(values.get("metavars") or {})
        self.code_snippet = str(values.get("code_snippet", values.get("code", "")))
        self.metadata = dict(values.get("metadata") or {})
        if not self.cwe:
            self.cwe = _metadata_list(self.metadata, "cwe")
        if not self.owasp:
            self.owasp = _metadata_list(self.metadata, "owasp")
        self.fingerprint = str(
            values.get("fingerprint")
            or fingerprint_finding(
                self.rule_id,
                self.path,
                self.start_line,
                self.end_line,
                self.message,
                self.code_snippet,
            )
        )

    @staticmethod
    def _from_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
        values = dict(kwargs)
        if "id" in values and "finding_id" not in values:
            values["finding_id"] = values["id"]
        if "title" in values and "message" not in values:
            values["message"] = values["title"]
        if "code" in values and "code_snippet" not in values:
            values["code_snippet"] = values["code"]
        values.setdefault("tool", "semgrep")
        values.setdefault("start_col", 0)
        values.setdefault("end_col", values.get("start_col", 0))
        return values

    @property
    def id(self) -> str:
        return self.finding_id

    @property
    def title(self) -> str:
        return self.message

    @property
    def code(self) -> str:
        return self.code_snippet

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["id"] = self.id
        data["title"] = self.title
        data["code"] = self.code
        return data


@dataclass
class AgentRunResult:
    agent: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    message: str = ""
    mode: Literal["editing", "diff"] = "editing"
    raw_output_path: str | None = None
    diff_text: str | None = None

    @property
    def provider(self) -> str:
        return self.agent

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PatchAttempt:
    finding_id: str
    agent: str
    status: str
    diff_path: str | None = None
    log_path: str | None = None
    message: str = ""
    provider_mode: str = "editing"
    worktree_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def path_to_jsonable(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _metadata_list(metadata: dict[str, Any], key: str) -> list[str]:
    value = metadata.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
