#!/usr/bin/env python3
"""Replay the A2 level-1/level-2 verdicts over recorded traces (shadow scoring).

ACCEPTANCE CRITERION -- read this before changing anything on the strength of the output.

The criterion is on the INPUT side: the reconstructed view must be non-empty (functions, call
targets and conditional jumps recovered from what the agent actually ran) and the verdicts must be
informative rather than fail-open. It is NOT "the layers must block the known-wrong submissions".
Tuning a gate until it catches the wrong answers in a pool that has already been scored fits the
gate to the eval outcomes -- the same contamination that cost the card library a whole family in
W10c. How many wrong submissions a correctly-parsing layer blocks is a RESULT to report, not a
target to optimise.

Usage:  python3 analysis/shadow_replay.py <runs_dir>
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.derivation_check import (  # noqa: E402
    build_view, check_consumer_observed, check_reachability)


@dataclass
class _R:
    tool: str
    stdout: str = ""
    stderr: str = ""


@dataclass
class _S:
    step_idx: int
    tool_result: object


@dataclass
class _H:
    step_idx: int
    text: str


@dataclass
class _V:
    step_idx: int
    source_step_idx: int
    source_observation: str = ""
    result: str = ""
    candidate: str = ""
    qualifies: bool = True


@dataclass
class _St:
    steps: list = field(default_factory=list)
    validation_ledger: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)


def load(path: Path):
    recs = [json.loads(l) for l in path.open()]
    meta, st, cand = recs[0], _St(), None
    for r in recs[1:]:
        tr = r.get("tool_result") or {}
        if tr:
            st.steps.append(_S(r["step_idx"], _R(tr.get("tool", ""), tr.get("stdout") or "",
                                                 tr.get("stderr") or "")))
        for h in r.get("hypotheses_added", []):
            st.hypotheses.append(_H(r["step_idx"], h.get("text", "")))
        for v in r.get("validations_added", []):
            st.validation_ledger.append(_V(r["step_idx"], v.get("source_step_idx") or -1,
                                           v.get("source_observation", "") or "",
                                           str(v.get("result", "") or ""), v.get("candidate") or ""))
        if r.get("submission"):
            cand = r["submission"].get("value")
    return meta, st, cand


def main(root: str) -> int:
    buckets: dict[str, list] = {"WRONG": [], "SOLVED": []}
    no_ledger = 0
    for f in sorted(Path(root).rglob("trace.jsonl")):
        meta, st, cand = load(f)
        if cand is None:
            continue
        mine = [v for v in st.validation_ledger if v.candidate == cand]
        if not mine:
            no_ledger += 1
            continue
        v = mine[0]
        view = build_view(st, before_step=v.step_idx)
        t = check_consumer_observed(st, v, view)
        r = check_reachability(st, v, view)
        key = "WRONG" if meta["termination_reason"] == "submitted_wrong" else "SOLVED"
        buckets[key].append((meta["arm"], t.ok, t.code, r.ok, r.code,
                             len(view.func_at), len(view.call_targets), len(view.cond_jumps)))

    for key, rows in buckets.items():
        n = len(rows)
        if not n:
            continue
        print(f"\n=== {key}: n={n}")
        print(f"  view non-empty            : {sum(1 for x in rows if x[5] > 0)}/{n}")
        print(f"  L1 (consumer observation) : blocked {sum(1 for x in rows if not x[1])}/{n}  "
              f"{dict(Counter(x[2] for x in rows))}")
        print(f"  L2 (reachability, bounded): blocked {sum(1 for x in rows if not x[3])}/{n}  "
              f"{dict(Counter(x[4] for x in rows))}")
    print(f"\nsubmissions with no ledger entry for the submitted candidate: {no_ledger}")
    print("\nReminder: the pass condition is a non-empty view and informative verdict codes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "runs"))
