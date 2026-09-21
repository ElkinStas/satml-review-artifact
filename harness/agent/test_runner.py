#!/usr/bin/env python3
"""Runner robustness tests (no LLM).

  #12 the runner fails closed on an existing trace (no silent overwrite); --overwrite bypasses.
  #13 run_meta provenance is merged into the trace meta line.
  #14 an API/network error in propose_action becomes an ERROR trace (persisted) after bounded retry,
      instead of an uncaught exception that aborts the run.

Run from repo root:  python agent/test_runner.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.config import RunConfig
from agent.loop import AgentLoop
from agent.policy import Policy, StubPolicy
from agent.state import Arm, TerminationReason
from agent.submit import StubOracle, SubmissionController
from agent.tools.registry import ToolRegistry
from agent.tools.shell import ShellTool
from agent.execution import LocalExecutionBackend

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


def _loop(cfg, accept="stub-flag", run_meta=None):
    shell = ShellTool(backend=LocalExecutionBackend(allow_unsandboxed=True),
                      timeout_s=cfg.shell_timeout_s, max_output_bytes=cfg.max_tool_output_bytes)
    controller = SubmissionController(oracle=StubOracle(accept_value=accept))
    registry = ToolRegistry(shell=shell, controller=controller)
    policy = StubPolicy(binary_path=cfg.binary_path, accept_value=accept)
    return AgentLoop(config=cfg, policy=policy, registry=registry, run_meta=run_meta or {})


class RaisingPolicy(Policy):
    def __init__(self): self.calls = 0; self.last_retrieved = []
    def propose_action(self, state):
        self.calls += 1
        raise RuntimeError("simulated API 500")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="rr_runner_"))
    BIN = "/bin/true"

    # #13: provenance merged into the trace meta
    meta = {"model": "m", "binary_sha256": "deadbeef", "pool_hash_sha256": "pool123",
            "retrieval_py_sha256": "ret123", "git_commit": "abc", "started_at": "t0"}
    cfg = RunConfig(arm=Arm.A0, task_id="prov", attempt_id="a1", binary_path=BIN, runs_dir=str(tmp / "runs"))
    _loop(cfg, run_meta=meta).run()
    line0 = json.loads(cfg.trace_path().read_text().splitlines()[0])
    expect("#13 run_meta merged into trace meta", all(line0.get(k) == v for k, v in meta.items()))
    expect("#13 base meta fields still present",
           line0["record_type"] == "meta" and "termination_reason" in line0 and "tokens_total" in line0)

    # #12: fail-closed on re-run of the same trace path; overwrite=True bypasses
    try:
        _loop(cfg).run(); raised = False
    except FileExistsError:
        raised = True
    expect("#12 re-run without overwrite raises FileExistsError", raised)
    cfg_ow = RunConfig(arm=Arm.A0, task_id="prov", attempt_id="a1", binary_path=BIN,
                       runs_dir=str(tmp / "runs"), overwrite=True)
    try:
        _loop(cfg_ow).run(); ok = True
    except FileExistsError:
        ok = False
    expect("#12 overwrite=True re-runs cleanly", ok)

    # #14: policy/API error -> ERROR trace, persisted, after bounded retry (1 + 2)
    cfg_e = RunConfig(arm=Arm.A0, task_id="err", attempt_id="a1", binary_path=BIN, runs_dir=str(tmp / "runs"))
    controller = SubmissionController(oracle=StubOracle(accept_value="never"))
    registry = ToolRegistry(shell=ShellTool(backend=LocalExecutionBackend(allow_unsandboxed=True)),
                            controller=controller)
    rp = RaisingPolicy()
    st_e = AgentLoop(config=cfg_e, policy=rp, registry=registry).run()
    expect("#14 terminates as ERROR", st_e.termination_reason == TerminationReason.ERROR)
    expect("#14 loop calls propose_action once then ERRORs (retry now lives in the policy)", rp.calls == 1)
    expect("#14 ERROR trace persisted", cfg_e.trace_path().is_file())
    m_e = json.loads(cfg_e.trace_path().read_text().splitlines()[0])
    expect("#14 termination_detail names the error", "simulated API 500" in m_e.get("termination_detail", ""))

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"RUNNER TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"RUNNER TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
