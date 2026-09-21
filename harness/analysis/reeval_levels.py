#!/usr/bin/env python3
"""Re-evaluate the A2 semantic levels offline, on already-recorded traces.

WHY THIS EXISTS
---------------
The recorded A2 battery cannot be read as a measurement of evidence gating. The controller selected
the FIRST well-formed validation for a candidate and re-judged that same entry on every retry
(confirmed in 16 of 16 blocked runs, each with 2-3 newer validations written after the first block).
So the gate never saw the evidence the agent produced in response to being blocked, and the recorded
verdicts describe that selection defect rather than the levels themselves.

Everything needed to redo the judgement correctly is already in the traces: the validation ledger,
the tool output the view is built from, and the hypotheses. This script replays the level checks
against the LATEST validation available at the moment of each submission -- the decision the fixed
controller (derivation-v5) would have made -- and scores the candidate with the real oracle.

No agent is run and no tokens are spent. Ground truth never reaches the agent: this is post-hoc
scoring of finished trajectories, exactly like re-scoring after a marker fix.

Usage:  python3 analysis/reeval_levels.py <runs_dir> [<runs_dir> ...]
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.adjudicate import adjudicate  # noqa: E402
from agent.derivation_check import (  # noqa: E402
    build_view, check_consumer_observed, check_reachability)


# --- minimal stand-ins: the checks read only these attributes -------------------------------
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
    action_type: str = ""
    tool_name: str = ""
    verdict: str = ""
    qualifies: bool = True


@dataclass
class _St:
    steps: list = field(default_factory=list)
    validation_ledger: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)


_ORACLE_CACHE: dict = {}


def oracle(tasks: dict, task_id: str, cand: str) -> str:
    """Run the real binary on the candidate. Post-hoc only -- never visible to the agent."""
    if cand is None:
        return "no-submission"
    key = (task_id, cand)
    if key in _ORACLE_CACHE:
        return _ORACLE_CACHE[key]
    v = tasks.get(task_id)
    if not v or not v.get("binary"):
        return "no-task"
    src = REPO / v["binary"]
    if not src.exists():
        return "no-binary"
    tmp = tempfile.mkdtemp()
    dst = Path(tmp) / src.name
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o700)
    # some targets are their own interpreter and only run from their own directory
    cwd = str(src.parent)
    exe = "./" + src.name
    try:
        if v.get("input_method") == "argv":
            r = subprocess.run([exe, cand], cwd=cwd, capture_output=True, text=True, timeout=20)
        else:
            r = subprocess.run([exe], cwd=cwd, input=cand + "\n",
                               capture_output=True, text=True, timeout=20)
        out = adjudicate(exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                         success_marker=v.get("success_marker"), fail_marker=v.get("fail_marker"),
                         known_flag=v.get("known_flag"), candidate=cand)
    except Exception:
        out = "run-error"
    _ORACLE_CACHE[key] = out
    return out


def load(path: Path):
    recs = [json.loads(l) for l in path.open() if l.strip()]
    if not recs:
        return None
    meta = recs[0]
    st = _St()
    submit_step = None
    submitted = None
    for r in recs:
        tr = r.get("tool_result") or {}
        if tr:
            st.steps.append(_S(r["step_idx"], _R(tr.get("tool", ""), tr.get("stdout") or "",
                                                 tr.get("stderr") or "")))
        for h in r.get("hypotheses_added", []):
            st.hypotheses.append(_H(r["step_idx"], h.get("text", "")))
        for v in r.get("validations_added", []):
            st.validation_ledger.append(_V(r["step_idx"], v.get("source_step_idx") or -1,
                                           v.get("source_observation", "") or "",
                                           str(v.get("result", "") or ""),
                                           v.get("candidate") or "",
                                           v.get("action_type", "") or "",
                                           v.get("tool_name", "") or "",
                                           v.get("verdict", "") or ""))
        if r.get("submission"):
            submitted = r["submission"]["value"]
            submit_step = r["step_idx"]
        if r.get("blocked_submission") and submitted is None:
            submitted = r["blocked_submission"].get("value")
            submit_step = r["step_idx"]
    return meta, st, submitted, submit_step


def verdicts_for(st: _St, cand: str, upto: int):
    """Level verdicts using the LATEST well-formed validation available at `upto`."""
    mine = [v for v in st.validation_ledger
            if (v.candidate or "") == cand and v.step_idx <= upto and v.source_step_idx is not None
            and v.source_step_idx < v.step_idx]
    if not mine:
        return None, None, 0
    best_t = best_r = None
    for v in sorted(mine, key=lambda x: x.step_idx, reverse=True):
        view = build_view(st, before_step=v.step_idx)
        t = check_consumer_observed(st, v, view)
        r = check_reachability(st, v, view)
        if best_t is None:
            best_t, best_r = t, r
        if t.ok and r.ok:               # the agent did eventually satisfy both
            return t, r, len(mine)
    return best_t, best_r, len(mine)


def main(dirs) -> int:
    tasks = json.loads((REPO / "pilot_tasks.json").read_text(encoding="utf-8"))
    rows = []
    for d in dirs:
        for f in sorted(Path(d).rglob("trace.jsonl")):
            got = load(f)
            if not got:
                continue
            meta, st, cand, sstep = got
            if meta["arm"] != "A2" or cand is None:
                continue
            t, r, n = verdicts_for(st, cand, sstep if sstep is not None else 10**9)
            rows.append({
                "task": meta["task_id"],
                "recorded": meta["termination_reason"],
                "cand": cand,
                "truth": oracle(tasks, meta["task_id"], cand),
                "n_validations": n,
                "t_ok": None if t is None else t.ok, "t_code": None if t is None else t.code,
                "r_ok": None if r is None else r.ok, "r_code": None if r is None else r.code,
            })

    print(f"A2 submissions re-evaluated: {len(rows)}\n")
    print("=== level verdicts under LATEST-evidence selection ===")
    print("  terminality :", dict(Counter(x["t_code"] for x in rows)))
    print("  reachability:", dict(Counter(x["r_code"] for x in rows)))

    would_block = [x for x in rows if (x["t_ok"] is False or x["r_ok"] is False)]
    print(f"\n=== would the FIXED gate still block? ===")
    print(f"  would block : {len(would_block)}/{len(rows)}")
    c = Counter(x["truth"] for x in would_block)
    print(f"  of those, oracle says: {dict(c)}")
    good = c.get("rejected", 0)
    bad = c.get("accepted", 0)
    if good + bad:
        print(f"  precision under latest-evidence: {good}/{good+bad} = {good/(good+bad):.0%}")
    allow = [x for x in rows if x not in would_block]
    ca = Counter(x["truth"] for x in allow)
    print(f"\n  would allow : {len(allow)}  -> oracle {dict(ca)}")
    if ca.get("accepted", 0) + ca.get("rejected", 0):
        print(f"  of allowed, wrong answers let through: {ca.get('rejected',0)}")

    print("\n=== candidates the fixed gate would still block ===")
    for x in would_block:
        print(f"  {x['task']:28s} truth={x['truth']:9s} n_val={x['n_validations']} "
              f"T={x['t_code']} R={x['r_code']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["runs"]))
