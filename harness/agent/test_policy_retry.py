#!/usr/bin/env python3
"""Transactional API-retry tests for ClaudePolicy (no LLM, flaky fake client).

#3: retry must NOT corrupt policy state. Before the fix, propose_action appended the user message and
set _started BEFORE the API call, so a retry at step 0 hit IndexError (state.steps[-1]) and a retry
after a tool call duplicated the tool_result. Now the turn is committed only after a successful call.

Verifies:
  - step 0: fail once then succeed -> no IndexError; history is exactly [user, assistant]; both attempts
    sent the identical request (not a corrupted one);
  - step 1 (after a tool call): fail once then succeed -> exactly one tool_result in history, correct
    tool_use/tool_result pairing, no duplicate;
  - across the run the tool_result count equals the number of tool-producing turns.

Run from repo root:  python agent/test_policy_retry.py
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.policy import ClaudePolicy
from agent.state import AgentState, Arm, StepRecord, ToolCall, ToolResult

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


class _Blk:
    type = "tool_use"; id = "tu_1"; name = "record_hypothesis"
    def __init__(self): self.input = {"text": "h"}

class _Usage:
    input_tokens = 10; cache_read_input_tokens = 0; cache_creation_input_tokens = 0; output_tokens = 5

class _Resp:
    def __init__(self): self.content = [_Blk()]; self.usage = _Usage()

class FlakyClient:
    """Fails the next `_fail` create() calls, then succeeds. Snapshots each attempt's messages."""
    def __init__(self): self.attempts = []; self._fail = 0; self.messages = self._M(self)
    def arm(self, n): self._fail = n
    class _M:
        def __init__(self, o): self.o = o
        def create(self, **kw):
            self.o.attempts.append(copy.deepcopy(kw["messages"]))
            if self.o._fail > 0:
                self.o._fail -= 1
                raise RuntimeError("simulated transient API failure")
            return _Resp()


def _count_tool_results(messages) -> int:
    n = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            n += sum(1 for b in c if isinstance(b, dict) and b.get("type") == "tool_result")
    return n

def _add_step(state, i):
    tr = ToolResult(step_idx=i, tool="run_binary", exit_code=0, stdout="o", stderr="",
                    stdout_sha256="", stderr_sha256="", truncated=False, elapsed_ms=0,
                    verdict="inconclusive", ran_candidate="x", input_method="argv")
    state.steps.append(StepRecord(step_idx=i, tool_call=ToolCall(step_idx=i, tool="run_binary", args={}),
                                  tool_result=tr))
    state.step_idx = i


def main() -> int:
    fc = FlakyClient()
    pol = ClaudePolicy(arm=Arm.A0, binary_path="./target", model="m", client=fc, cards=[],
                       retry_count=2, retry_backoff_s=0.0)
    st = AgentState(task_id="t", attempt_id="a", arm=Arm.A0)

    # --- step 0: fail once, then succeed ---
    fc.arm(1)
    try:
        pol.propose_action(st); ok = True
    except IndexError:
        ok = False
    expect("#3 step-0 retry does not raise IndexError", ok)
    expect("#3 step-0 history is exactly [user, assistant] (no duplicated user)", len(pol.messages) == 2)
    expect("#3 step-0 took 2 attempts (fail + success)", len(fc.attempts) == 2)
    expect("#3 step-0 both attempts sent the identical request", fc.attempts[0] == fc.attempts[1])
    expect("#3 step-0 no tool_result yet", _count_tool_results(pol.messages) == 0)

    # --- step 1 after a tool call: fail once, then succeed ---
    _add_step(st, 1)
    attempts_before = len(fc.attempts)
    fc.arm(1)
    pol.propose_action(st)
    new_attempts = fc.attempts[attempts_before:]
    def _user_msgs(msgs): return [m for m in msgs if m.get("role") == "user"]
    expect("#3 step-1 took 2 attempts (fail + success)", len(new_attempts) == 2)
    expect("#3 step-1 identical user messages across retries (no duplicated tool_result mid-retry)",
           _user_msgs(new_attempts[0]) == _user_msgs(new_attempts[1]))
    expect("#3 history is [u0, a0, u1, a1]", len(pol.messages) == 4)
    expect("#3 exactly ONE tool_result across history (no duplicate)", _count_tool_results(pol.messages) == 1)

    # pairing: the tool_result's tool_use_id matches the tool_use id from the prior assistant turn
    u1 = pol.messages[2]["content"]
    tr_block = next((b for b in u1 if isinstance(b, dict) and b.get("type") == "tool_result"), None)
    expect("#3 tool_result cites the prior assistant tool_use id",
           tr_block is not None and tr_block.get("tool_use_id") == "tu_1")

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"POLICY RETRY TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"POLICY RETRY TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
