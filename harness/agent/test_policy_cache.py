#!/usr/bin/env python3
"""Policy prompt-construction tests (no API, fake client).

Locks the cost / retrieval-injection fixes:
  #7 no card block is injected before the first hypothesis (hypothesis-keyed retrieval);
  #8 an identical top-card set is NOT re-injected as a fresh block on later steps (still recorded
     per-step in last_retrieved for the trace); a changed hypothesis re-injects;
  #9 exactly one walking cache_control breakpoint sits on the last block of the most recent message,
     and total breakpoints (system + messages) stay <= 4.

Run from repo root:  python agent/test_policy_cache.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.policy import ClaudePolicy
from agent.retrieval import load_cards
from agent.state import (AgentState, Arm, Hypothesis, StepRecord, ToolCall, ToolResult)

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


class _Blk:
    type = "tool_use"; id = "tu_1"; name = "record_hypothesis"
    def __init__(self): self.input = {"text": "h"}

class _Usage:
    input_tokens = 10; cache_read_input_tokens = 0; cache_creation_input_tokens = 0; output_tokens = 5

class _Resp:
    def __init__(self): self.content = [_Blk()]; self.usage = _Usage()

class _Messages:
    def __init__(self, outer): self.outer = outer
    def create(self, **kw):
        import copy
        self.outer.calls.append(copy.deepcopy(kw))  # snapshot at call time (messages mutate after)
        return _Resp()

class FakeClient:
    def __init__(self): self.calls = []; self.messages = _Messages(self)


def _user_msg_of_last_call(fc):
    """The user message sent on the most recent create() call (messages[-1] at create time)."""
    return fc.calls[-1]["messages"][-1]

def _has_card_block(msg):
    c = msg["content"]
    blocks = c if isinstance(c, list) else [{"type": "text", "text": c}]
    return any(isinstance(b, dict) and b.get("type") == "text" and "Pattern cards" in b.get("text", "")
               for b in blocks)

def _msg_breakpoints(messages):
    n = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            n += sum(1 for b in c if isinstance(b, dict) and "cache_control" in b)
    return n

def _add_step(state, i):
    tr = ToolResult(step_idx=i, tool="run_binary", exit_code=0, stdout="o", stderr="",
                    stdout_sha256="", stderr_sha256="", truncated=False, elapsed_ms=0,
                    verdict="inconclusive", ran_candidate="x", input_method="argv")
    state.steps.append(StepRecord(step_idx=i,
                       tool_call=ToolCall(step_idx=i, tool="run_binary", args={}), tool_result=tr))
    state.step_idx = i

def _set_hyp(state, i, text):
    state.hypothesis_ledger.append(Hypothesis(step_idx=i, text=text, cites_card_ids=[]))


def main() -> int:
    cards = load_cards(REPO / "cards/cards_v1.0.json")
    fc = FakeClient()
    pol = ClaudePolicy(arm=Arm.A1, binary_path="/tmp/rerag/target", model="m", client=fc, cards=cards, k=3)
    st = AgentState(task_id="t", attempt_id="a", arm=Arm.A1)

    # step 1: no hypothesis yet -> NO cards (#7)
    pol.propose_action(st)
    expect("#7 no card block before the first hypothesis", not _has_card_block(_user_msg_of_last_call(fc)))

    # step 2: transform hypothesis -> cards injected (#8 first injection)
    _add_step(st, 1); _set_hyp(st, 1, "transform xor compare visible constant post-transform")
    pol.propose_action(st)
    expect("#8 cards injected when a new hypothesis appears", _has_card_block(_user_msg_of_last_call(fc)))
    ids1 = list(pol._last_injected_ids or [])
    expect("#8 top-card set is non-empty", len(ids1) > 0)

    # step 3: SAME hypothesis (same top IDs) -> NOT re-injected (#8)
    _add_step(st, 2)  # ledger unchanged
    pol.propose_action(st)
    expect("#8 identical card set NOT re-injected next step", not _has_card_block(_user_msg_of_last_call(fc)))
    expect("#8 last_retrieved still recorded for the trace", len(pol.last_retrieved) == 3)

    # step 4: CHANGED hypothesis (different family) -> re-injected (#8)
    _add_step(st, 3); _set_hyp(st, 3, "silent validation wrong input no output baseline differential")
    pol.propose_action(st)
    ids2 = list(pol._last_injected_ids or [])
    expect("#8 changed hypothesis re-injects", _has_card_block(_user_msg_of_last_call(fc)) and ids2 != ids1)

    # steps 5-6: X -> [] -> X. An intervening all-miss retrieval must reset the marker so the SAME cards
    # re-inject when the phase becomes relevant again (the reinject bug: [] left the old IDs stuck).
    _add_step(st, 4); _set_hyp(st, 4, "zzzqqq nomatch xyzzy plugh frobnicate")  # vocabulary miss -> []
    pol.propose_action(st)
    expect("#3 all-miss retrieval injects nothing", not _has_card_block(_user_msg_of_last_call(fc)))
    expect("#3 all-miss resets last_injected_ids to []", (pol._last_injected_ids or []) == [])
    _add_step(st, 5); _set_hyp(st, 5, "transform xor compare visible constant post-transform")  # == step 2 family
    pol.propose_action(st)
    expect("#3 cards RE-injected after an all-miss gap (X->[]->X)", _has_card_block(_user_msg_of_last_call(fc)))

    # #9: walking cache breakpoint — exactly one message-level breakpoint, on the last block; total <= 4
    last_call = fc.calls[-1]
    msgs = last_call["messages"]
    sys_bp = sum(1 for b in last_call.get("system", []) if isinstance(b, dict) and "cache_control" in b)
    msg_bp = _msg_breakpoints(msgs)
    expect("#9 exactly one message-history cache breakpoint", msg_bp == 1)
    last_blk = msgs[-1]["content"][-1]
    expect("#9 breakpoint is on the last block of the most recent message",
           isinstance(last_blk, dict) and "cache_control" in last_blk)
    expect("#9 total breakpoints (system + messages) <= 4", sys_bp + msg_bp <= 4)
    expect("#9 system prompt keeps its own breakpoint", sys_bp == 1)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"POLICY CACHE/INJECTION TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"POLICY CACHE/INJECTION TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
