from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_report(run_dir: Path) -> Path:
    findings = _read_json(run_dir / "findings.json", [])
    attempts = _read_json(run_dir / "attempts.json", [])
    verification = _read_json(run_dir / "verify.json", {})
    lines = [
        "# PatchAgent-Blue Report",
        "",
        f"Run directory: `{run_dir}`",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            lines.append(
                f"- `{finding.get('id')}` `{finding.get('severity')}` "
                f"{finding.get('title')} at `{finding.get('path')}:{finding.get('start_line')}`"
            )
    else:
        lines.append("- No findings recorded.")
    lines.extend(["", "## Patch Attempts", ""])
    if attempts:
        for attempt in attempts:
            lines.append(
                f"- `{attempt.get('finding_id')}` via `{attempt.get('agent')}`: "
                f"{attempt.get('status')}"
            )
    else:
        lines.append("- No patch attempts recorded.")
    lines.extend(["", "## Verification", ""])
    if verification:
        lines.append(f"- Passed: `{verification.get('passed')}`")
        lines.append(f"- Unit commands: `{len((verification.get('unit') or {}).get('results') or [])}`")
        lines.append(
            f"- Attack replays: `{len((verification.get('attack') or {}).get('results') or [])}`"
        )
    else:
        lines.append("- Verification has not run.")
    report_path = run_dir / "report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
