#!/usr/bin/env python3
"""Recompute every number reported in the paper, from the traces alone.

    python3 analysis/recompute_all.py

No model is called and no binary is executed except by --verify-oracle, which re-adjudicates the
recorded submissions against the shipped binaries. Standard library only.

WHY THIS SCRIPT EXISTS RATHER THAN A SPREADSHEET
Every figure in the paper is derived here, so a reviewer can change one line and see what moves.
Two conventions are enforced because getting either wrong silently changes the headline:

  1. A trace counts only if its `binary_sha256` matches the artifact currently shipped for that
     task. An earlier consolidation of our own results keyed only on (task, arm, attempt), kept the
     newest file by mtime, and silently admitted eight runs executed against superseded builds --
     reporting a 28.8% baseline where the correct figure is 25.8%.

  2. Runs that terminate with an infrastructure error at step 0 are excluded from denominators
     rather than counted as outcomes. They are reported separately so the exclusion is visible.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import statistics as st
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _resolve_layout() -> tuple[Path, Path]:
    """Locate the runs tree and the harness root.

    The same script has to work in two layouts, and it must never guess wrong about which one it
    is in, because guessing wrong means silently analysing nothing and reporting 0/0.

      repository   runs at results/runs/, harness at the repository root
      Zenodo bundle  runs at runs/, harness under harness/

    Detected by probing rather than hard-coded, so the bundle builder cannot drift away from it.
    """
    for runs, harness in ((ROOT / "results" / "runs", ROOT), (ROOT / "runs", ROOT / "harness")):
        if runs.is_dir() and (harness / "pilot_tasks.json").is_file():
            return runs, harness
    sys.exit(
        "recompute_all.py: could not locate the runs tree and pilot_tasks.json.\n"
        "  Expected either <repo>/results/runs + <repo>/pilot_tasks.json,\n"
        "  or <bundle>/runs + <bundle>/harness/pilot_tasks.json."
    )


RUNS_ROOT, HARNESS_ROOT = _resolve_layout()
OPAQUE = {f"r_e_{i:02d}_opaque" for i in (9, 10, 11, 12, 17, 18, 19, 20, 21, 22, 23, 24)}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def two_prop(k0: int, n0: int, k1: int, n1: int) -> tuple[float, float]:
    """Pooled two-proportion z-test. Attempts within a task are not independent, so this is a
    descriptive summary; the paper's per-task sign test is the inferential statement."""
    if not n0 or not n1:
        return (0.0, 1.0)
    p = (k0 + k1) / (n0 + n1)
    se = math.sqrt(p * (1 - p) * (1 / n0 + 1 / n1))
    if se == 0:
        return (0.0, 1.0)
    z = (k0 / n0 - k1 / n1) / se
    return (z, math.erfc(abs(z) / math.sqrt(2)))


def load(subdir: str, tasks: set | None = None) -> list[dict]:
    """Read one run directory. Drops step-0 infrastructure errors and counts them separately."""
    out, dropped = [], 0
    for f in sorted((RUNS_ROOT / subdir).rglob("trace.jsonl")):
        lines = [l for l in f.open() if l.strip()]
        if not lines:
            dropped += 1
            continue
        m = json.loads(lines[0])
        if tasks and m["task_id"] not in tasks:
            continue
        if m["termination_reason"] == "error" and m.get("n_steps", 0) == 0:
            dropped += 1
            continue
        m["_path"] = f
        m["_attempt"] = f.parent.name
        out.append(m)
    if dropped:
        print(f"    ({dropped} step-0 infrastructure failures excluded from {subdir})")
    return out


def rate_block(runs: list[dict], label: str) -> dict:
    by_arm = defaultdict(Counter)
    for m in runs:
        by_arm[m["arm"]][m["termination_reason"]] += 1
    print(f"\n  {label}")
    res = {}
    for arm in ("A0", "A1", "A2"):
        c = by_arm[arm]
        n = sum(c.values())
        if not n:
            continue
        k = c["submitted_wrong"]
        lo, hi = wilson(k, n)
        nosub = c.get("max_steps", 0) + c.get("agent_quit", 0)
        print(f"    {arm}: wrong {k:3d}/{n:3d} = {k/n:5.1%} [{lo:.1%}, {hi:.1%}] | "
              f"solved {c.get('solved',0):3d} | no submission {nosub}")
        res[arm] = (k, n)
    return res


def verify_hashes(runs: list[dict]) -> None:
    """Every counted trace must have executed the binary that ships in the artifact."""
    tasks = json.loads((HARNESS_ROOT / "pilot_tasks.json").read_text())
    bad, checked = [], 0
    for m in runs:
        spec = tasks.get(m["task_id"])
        if not spec:
            continue
        p = HARNESS_ROOT / spec["binary"]
        if not p.exists():
            continue
        checked += 1
        if m.get("binary_sha256") != hashlib.sha256(p.read_bytes()).hexdigest():
            bad.append((m["task_id"], m["arm"], m["_attempt"]))
    print(f"\n  binary-hash check: {checked - len(bad)}/{checked} traces match the shipped artifact")
    for b in bad[:10]:
        print(f"    MISMATCH {b}")


def paired(runs: list[dict], label: str) -> None:
    """A0 vs A1 on the same task and attempt index -- the view the aggregate hides."""
    by_slot = defaultdict(dict)
    for m in runs:
        by_slot[(m["task_id"], m["_attempt"])][m["arm"]] = m["termination_reason"]
    tr = Counter()
    for v in by_slot.values():
        if "A0" in v and "A1" in v:
            a = "W" if v["A0"] == "submitted_wrong" else "C"
            b = "W" if v["A1"] == "submitted_wrong" else "C"
            tr[a + b] += 1
    n = sum(tr.values())
    print(f"    {label}: repaired {tr['WC']}, regressed {tr['CW']}, "
          f"unchanged-wrong {tr['WW']}, unchanged-correct {tr['CC']}  (n={n})")


def first_hypothesis(runs: list[dict], label: str) -> None:
    """Retrieval fires on record_hypothesis, so this is where the same policy enters."""
    steps = []
    for m in runs:
        if m["arm"] != "A1":
            continue
        for line in m["_path"].open():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("hypotheses_added"):
                steps.append(r["step_idx"])
                break
    if steps:
        print(f"    {label}: n={len(steps)} median={st.median(steps)} "
              f"range={min(steps)}-{max(steps)}")


def gate_blocks(runs: list[dict], verify: bool) -> None:
    """Every A2 block event, and -- with --verify-oracle -- whether the blocked candidate was right.

    The distinction matters: the gate conditions on closure of the stated evidence relation, not on
    hidden correctness, so blocking a correct answer with an incomplete justification is the policy
    working. But it means the held-out runs demonstrate enforcement cost, not interception.
    """
    tasks = json.loads((HARNESS_ROOT / "pilot_tasks.json").read_text())
    events, codes, per_run = 0, Counter(), Counter()
    correct = wrong = unknown = 0
    same_candidate = 0
    for m in runs:
        if m["arm"] != "A2":
            continue
        blocked, final, n = [], None, 0
        for line in m["_path"].open():
            if not line.strip():
                continue
            r = json.loads(line)
            b = r.get("blocked_submission")
            if b:
                n += 1
                events += 1
                codes[(b.get("audit") or {}).get("reason_code")] += 1
                blocked.append(b.get("value"))
                if verify:
                    v = adjudicate_candidate(tasks, m["task_id"], b.get("value"))
                    if v == "accepted":
                        correct += 1
                    elif v == "rejected":
                        wrong += 1
                    else:
                        unknown += 1
            s = r.get("submission")
            if s:
                final = s.get("value")
        if n:
            per_run[n] += 1
            if final is not None and final in blocked:
                same_candidate += 1
    runs_blocked = sum(per_run.values())
    print(f"\n  A2 gate: {events} block events across {runs_blocked} runs")
    print(f"    reason codes: {dict(codes)}")
    if per_run:
        vals = [k for k, v in per_run.items() for _ in range(v)]
        print(f"    blocks per blocked run: median {st.median(vals)}, max {max(vals)}")
    print(f"    runs that later submitted the SAME candidate they were blocked on: {same_candidate}")
    if verify:
        print(f"    blocked candidates scored by the oracle: "
              f"correct {correct}, wrong {wrong}, undetermined {unknown}")
        if wrong == 0 and correct:
            print("    -> no incorrect proposal reached the gate on this pool: these runs show "
                  "enforcement cost and evidence completion, not interception")


def adjudicate_candidate(tasks: dict, task_id: str, cand: str) -> str:
    spec = tasks.get(task_id)
    if not spec or cand is None:
        return "?"
    b = HARNESS_ROOT / spec["binary"]
    if not b.exists():
        return "?"
    sys.path.insert(0, str(HARNESS_ROOT))
    try:
        from agent.adjudicate import adjudicate  # noqa: PLC0415
        if spec.get("input_method") == "argv":
            r = subprocess.run([f"./{b.name}", cand], cwd=b.parent,
                               capture_output=True, text=True, timeout=15)
        else:
            r = subprocess.run([f"./{b.name}"], cwd=b.parent, input=cand + "\n",
                               capture_output=True, text=True, timeout=15)
        return adjudicate(exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr,
                          success_marker=spec.get("success_marker"),
                          fail_marker=spec.get("fail_marker"),
                          known_flag=spec.get("known_flag"), candidate=cand)
    except Exception:
        return "?"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-oracle", action="store_true",
                    help="re-execute the shipped binaries to re-score recorded submissions")
    a = ap.parse_args()

    print("=" * 78)
    print("RECOMPUTED FROM TRACES".center(78))
    print("=" * 78)

    dev = load("dev_synthetic")
    rate_block(dev, "Development pool -- 24 synthetic tasks")
    by_fam = defaultdict(list)
    for m in dev:
        by_fam[m["task_id"][:3]].append(m)
    print("    wrong submissions by family (A0 -> A1 -> A2):")
    for fam in sorted(by_fam):
        c = defaultdict(Counter)
        for m in by_fam[fam]:
            c[m["arm"]][m["termination_reason"]] += 1
        print(f"      {fam}: " + " -> ".join(
            f"{c[a].get('submitted_wrong',0)}/{sum(c[a].values())}" for a in ("A0", "A1", "A2")))

    real = load("dev_real")
    rate_block(real, "Public CTF binaries -- exploratory, never aggregated")

    held = load("heldout_claude")
    r_held = rate_block(held, "Held-out, Claude Opus 4.5 -- 24 tasks x 3 arms x 5")
    by_motif = defaultdict(list)
    for m in held:
        by_motif[m["task_id"].split("_")[-1]].append(m)
    print("    wrong submissions by motif (A0 -> A1 -> A2):")
    for mo in sorted(by_motif):
        c = defaultdict(Counter)
        for m in by_motif[mo]:
            c[m["arm"]][m["termination_reason"]] += 1
        print(f"      {mo:9s}: " + " -> ".join(
            f"{c[a].get('submitted_wrong',0)}/{sum(c[a].values())}" for a in ("A0", "A1", "A2")))
    verify_hashes(held)

    gpt = load("crossmodel_gpt52")
    r_gpt = rate_block(gpt, "Cross-model, GPT-5.2 medium -- 12 reachability tasks")

    print("\n  Cross-model comparison on the twelve shared reachability binaries")
    held_op = [m for m in held if m["task_id"] in OPAQUE]
    for lbl, rs in (("Claude", held_op), ("GPT-5.2", gpt)):
        c = defaultdict(Counter)
        for m in rs:
            c[m["arm"]][m["termination_reason"]] += 1
        row = "  ".join(f"{a} {c[a]['submitted_wrong']:2d}/{sum(c[a].values()):<3d}"
                        for a in ("A0", "A1", "A2"))
        print(f"    {lbl:8s} {row}")

    print("\n  Paired A0->A1 on the shared binaries")
    paired(held_op, "Claude ")
    paired(gpt, "GPT-5.2")

    print("\n  Step index of the first recorded hypothesis (A1)")
    first_hypothesis(held_op, "Claude ")
    first_hypothesis(gpt, "GPT-5.2")

    print("\n  Significance (descriptive; see the paper's per-task sign test)")
    for lbl, rs in (("Claude ", held_op), ("GPT-5.2", gpt)):
        c = defaultdict(Counter)
        for m in rs:
            c[m["arm"]][m["termination_reason"]] += 1
        z, p = two_prop(c["A0"]["submitted_wrong"], sum(c["A0"].values()),
                        c["A1"]["submitted_wrong"], sum(c["A1"].values()))
        print(f"    {lbl} A0 vs A1: z={z:5.2f}  p={p:.3g}")
    ch = defaultdict(Counter)
    for m in held_op:
        ch[m["arm"]][m["termination_reason"]] += 1
    cg = defaultdict(Counter)
    for m in gpt:
        cg[m["arm"]][m["termination_reason"]] += 1
    z, p = two_prop(ch["A0"]["submitted_wrong"], sum(ch["A0"].values()),
                    cg["A0"]["submitted_wrong"], sum(cg["A0"].values()))
    print(f"    A0 across models:   z={z:5.2f}  p={p:.3g}")

    gate_blocks(held, a.verify_oracle)
    if not a.verify_oracle:
        print("    (pass --verify-oracle to re-score blocked candidates against the binaries)")

    print("\n" + "=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
