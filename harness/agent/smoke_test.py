"""Skeleton smoke test -- the Week-2 Track C definition of done.

Runs the A0 skeleton end-to-end against a stub policy + stub oracle and asserts:
  1. the loop runs and persists a well-formed trace.jsonl;
  2. the SOLVED path terminates on an accepted submission;
  3. the MAX_STEPS budget hook fires;
  4. the MAX_TOKENS budget hook fires on budget_tokens;
  5. the ShellTool actually executes a whitelisted tool on a real binary;
  6. parity by construction: assemble(A0) is a prefix of A1 is a prefix of A2.

Run from the repo root:  python3 agent/smoke_test.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Allow running as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.config import RunConfig  # noqa: E402
from agent.loop import AgentLoop  # noqa: E402
from agent.policy import StubPolicy  # noqa: E402
from agent.prompting import assemble_system_prompt  # noqa: E402
from agent.state import Arm, TerminationReason  # noqa: E402
from agent.submit import StubOracle, SubmissionController  # noqa: E402
from agent.tools.registry import ToolRegistry  # noqa: E402
from agent.tools.shell import ShellTool  # noqa: E402
from agent.execution import LocalExecutionBackend  # noqa: E402

_REAL_BINARY = "/bin/true"  # any ELF the ShellTool can inspect
_PASS, _FAIL = "  [PASS]", "  [FAIL]"
_failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print((_PASS if condition else _FAIL) + " " + label)
    if not condition:
        _failures.append(label)


def _build_loop(cfg: RunConfig, accept_value: str) -> AgentLoop:
    shell = ShellTool(backend=LocalExecutionBackend(allow_unsandboxed=True),
                      target_host_path=_REAL_BINARY, timeout_s=cfg.shell_timeout_s,
                      max_output_bytes=cfg.max_tool_output_bytes)
    controller = SubmissionController(oracle=StubOracle(accept_value=accept_value))
    registry = ToolRegistry(shell=shell, controller=controller)
    policy = StubPolicy(binary_path=cfg.binary_path, accept_value=accept_value)
    return AgentLoop(config=cfg, policy=policy, registry=registry)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="rr_smoke_"))

    # --- 1 & 2: happy path -> SOLVED + well-formed trace ----------------------
    print("\n[1] happy path: skeleton runs, trace persisted, SOLVED")
    cfg = RunConfig(arm=Arm.A0, task_id="smoke", attempt_id="a1",
                    binary_path=_REAL_BINARY, runs_dir=str(tmp / "runs"))
    state = _build_loop(cfg, accept_value="stub-flag").run()
    trace = cfg.trace_path()
    check("trace.jsonl was written", trace.is_file())
    lines = [json.loads(x) for x in trace.read_text().splitlines()]
    check("trace has a meta line + step lines", len(lines) >= 2 and lines[0]["record_type"] == "meta")
    check("terminated as SOLVED", state.termination_reason == TerminationReason.SOLVED)
    check("exactly one accepted submission", len(state.submissions) == 1 and state.submissions[0].accepted)
    check("hypothesis + validation ledgers populated",
          len(state.hypothesis_ledger) == 1 and len(state.validation_ledger) == 1)
    check("processed-token total is recorded", lines[0]["processed_tokens_total"] > 0)

    # --- 3: MAX_STEPS hook ----------------------------------------------------
    print("\n[3] budget hook: MAX_STEPS")
    cfg_s = RunConfig(arm=Arm.A0, task_id="smoke", attempt_id="steps",
                      binary_path=_REAL_BINARY, runs_dir=str(tmp / "runs"), max_steps=2)
    st_s = _build_loop(cfg_s, accept_value="never").run()
    check("terminated as MAX_STEPS", st_s.termination_reason == TerminationReason.MAX_STEPS)
    check("stopped at the step cap", len(st_s.steps) == 2)

    # --- 4: MAX_TOKENS hook ---------------------------------------------------
    print("\n[4] budget hook: MAX_TOKENS (budget_tokens)")
    cfg_t = RunConfig(arm=Arm.A0, task_id="smoke", attempt_id="tokens",
                      binary_path=_REAL_BINARY, runs_dir=str(tmp / "runs"),
                      max_total_tokens=2_500)
    st_t = _build_loop(cfg_t, accept_value="never").run()
    check("terminated as MAX_TOKENS", st_t.termination_reason == TerminationReason.MAX_TOKENS)

    # --- 5: ShellTool runs a real tool ---------------------------------------
    print("\n[5] ShellTool executes a whitelisted tool")
    res = ShellTool(backend=LocalExecutionBackend(allow_unsandboxed=True),
                    target_host_path=_REAL_BINARY).run("file", step_idx=0)
    check("`file` exited 0", res.exit_code == 0)
    check("stdout captured + hashed", bool(res.stdout) and len(res.stdout_sha256) == 64)

    # --- 6: parity by construction -------------------------------------------
    print("\n[6] parity: assemble(A0) prefix-of A1 prefix-of A2")
    p0 = assemble_system_prompt(Arm.A0)
    p1 = assemble_system_prompt(Arm.A1)
    p2 = assemble_system_prompt(Arm.A2)
    check("A0 is a prefix of A1", p1.startswith(p0))
    check("A1 is a prefix of A2", p2.startswith(p1))
    check("deltas are non-empty", len(p1) > len(p0) and len(p2) > len(p1))

    print()
    if _failures:
        print(f"SMOKE TEST FAILED -- {len(_failures)} check(s) failed:")
        for f in _failures:
            print("  - " + f)
        return 1
    print("SMOKE TEST PASSED -- skeleton runs against the stub.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
