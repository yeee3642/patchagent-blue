# PatchAgent-Blue

PatchAgent-Blue is a Python CLI prototype for automated vulnerability repair:

1. run Semgrep SAST,
2. normalize findings with stable fingerprints,
3. reproduce configured baseline behavior,
4. ask an editing or diff provider to patch one finding in a git worktree,
5. run unit tests and before/after attack regression replays,
6. write replayable artifacts under `.patchagent-blue/runs/<run_id>/`.

The framework is dependency-light by design. Runtime scanning expects Semgrep to be installed, or a compatible command to be provided through `PATCHAGENT_BLUE_SEMGREP_CMD`.

## Install

```powershell
python -m pip install -e .
python -m pip install semgrep
```

If Semgrep is not installed globally, set:

```powershell
$env:PATCHAGENT_BLUE_SEMGREP_CMD = "python -m semgrep"
```

## CLI

```powershell
patchagent-blue init --target path\to\target
patchagent-blue doctor
patchagent-blue scan --target path\to\target
patchagent-blue patch --target path\to\target --finding F0001 --agent codex
patchagent-blue verify --target path\to\target --run <run_id>
patchagent-blue run --target path\to\target --agent cascade
```

Agents:

- `codex`: runs `codex exec --cd <target> --sandbox workspace-write --ask-for-approval never ...`
- `claude`: runs `claude --bare -p --permission-mode acceptEdits --output-format stream-json --add-dir <target> ...`
- `cascade`: tries configured providers in order, default `codex` then `claude`
- `mock`: deterministic editing adapter for tests and demos
- `mock-diff`: deterministic diff adapter for orchestrator tests

Direct modification is disabled by default. `safety.use_worktree=true` creates an isolated git worktree under the run directory; the original checkout remains unchanged and the proposed patch is saved as a diff artifact. Use `direct_modify=true` only for disposable targets.

## Config

`patchagent-blue.yml`:

```yaml
version: 1
sast:
  engine: semgrep
  config: auto
  metrics: off
  timeout_sec: 60
agent:
  default: cascade
  cascade_order: ["codex", "claude"]
tests:
  unit:
    commands:
      - name: unit
        cmd: ["pytest", "-q"]
        timeout_sec: 120
  services: []
  attack:
    replays:
      - tests/attack/eval_payload.json
limits:
  max_attempts: 2
  max_changed_files: 8
  max_changed_lines: 500
safety:
  require_git: true
  require_clean_tree: true
  direct_modify: false
  use_worktree: true
```

Attack replay files are JSON objects or arrays:

```json
{
  "id": "payload-before-after",
  "type": "command",
  "cmd": ["python", "tests/attack/replay.py"],
  "timeout_sec": 30,
  "before_patch": {
    "expect_exit_code": 0,
    "expect_stdout_regex": "VULNERABLE"
  },
  "after_patch": {
    "expect_exit_code": 0,
    "expect_stdout_regex": "BLOCKED"
  }
}
```

## Demo Fixtures

The `examples/vulnerable-python` and `examples/vulnerable-js` folders include small vulnerable projects, pinned local Semgrep rules, unit tests, and before/after attack replay files. Copy one to a disposable git repo before running the worktree flow.

Each run stores `semgrep.raw.json`, `findings.json`, `baseline.verify.json`, `verify.json`, provider logs, patch diffs, `base_commit.txt`, git status snapshots, `environment.json`, `manifest.snapshot.json`, and `report.md`.
