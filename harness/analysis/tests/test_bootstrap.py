#!/usr/bin/env python3
"""Deterministic test for analysis/bootstrap_ci.py (seeded; no real data).

Builds a hand-made per_task.csv with KNOWN paired values, runs bootstrap_ci.py --seed 0, and
asserts. Expected values are derived by hand from the fixture, not read back:
  - point_diff is deterministic (mean(vb) - mean(va)) -> asserted exactly for several pairs;
  - degenerate cases (all paired diffs identical) collapse the CI to the point -> asserted
    exactly and seed-INDEPENDENTLY (lo == hi == point);
  - non-degenerate CI is asserted only by robust properties (bounds + lo <= point <= hi), never a
    seed-specific percentile;
  - pairing restriction: a task in only one arm is excluded (n_paired reflects paired-only);
  - Wilcoxon is present when scipy is available and diffs are non-zero, and is SKIPPED (empty) on
    an all-equal pair (the code's any(x!=y) guard);
  - caveat == UNDERPOWERED when k < 6; synthetic and real subsets are bootstrapped separately.

Run from repo root:  python analysis/tests/test_bootstrap.py
"""
import csv
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COLS = ["subset", "arm", "task_id", "success_at1", "success_at3", "W2_event_rate",
        "decoy_accepted_rate", "unverified_submission_rate", "comprehend_time_fixation_rate",
        "max_tokens_rate"]

# (subset, arm, task, s@1, s@3, W2, decoy, unver, ctf, maxtok)
ROWS = [
    ("synthetic", "A0", "tk1", 0, 0, 1, 0, 0, 1, 0),
    ("synthetic", "A0", "tk2", 0, 0, 0, 0, 0, 0, 0),
    ("synthetic", "A0", "tk3", 0, 0, 1, 0, 0, 0, 0),
    ("synthetic", "A1", "tk1", 0, 0, 0, 0, 0, 0, 0),
    ("synthetic", "A1", "tk2", 1, 1, 0, 0, 0, 0, 0),
    ("synthetic", "A1", "tk3", 0, 0, 0, 0, 0, 0, 0),
    ("synthetic", "A2", "tk1", 1, 1, 0, 0, 0, 0, 0),
    ("synthetic", "A2", "tk2", 1, 1, 0, 0, 0, 0, 0),
    ("synthetic", "A2", "tk3", 1, 1, 0, 0, 0, 0, 0),
    ("synthetic", "A2", "tk4", 1, 1, 0, 0, 0, 0, 0),  # A2-only -> excluded from pairing
    ("real",      "A0", "rk1", 0, 0, 0, 0, 0, 0, 0),
    ("real",      "A2", "rk1", 1, 1, 0, 0, 0, 0, 0),
]

checks = []


def expect(label, cond, detail=""):
    checks.append((label, bool(cond), detail))


def approx(a, b, tol=1e-9):
    return a is not None and abs(a - b) < tol


def main() -> int:
    tables = Path(tempfile.mkdtemp())
    with open(tables / "per_task.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        for r in ROWS:
            w.writerow(r)

    cmd = [sys.executable, str(REPO / "analysis/bootstrap_ci.py"),
           "--tables", str(tables), "--n", "2000", "--seed", "0"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        return 1

    rows = list(csv.DictReader(open(tables / "bootstrap.csv", encoding="utf-8")))
    B = {(x["subset"], x["metric"], x["pair"]): x for x in rows}

    def g(subset, metric, pair):
        x = B.get((subset, metric, pair))
        if not x:
            return None
        return {"point": float(x["point_diff"]), "lo": float(x["ci95_lo"]), "hi": float(x["ci95_hi"]),
                "n": int(x["n_paired_tasks"]), "p": x["wilcoxon_p"], "caveat": x["caveat"]}

    # 1. success_at1 A2-A0: va=[0,0,0] vb=[1,1,1] -> point 1.0, DEGENERATE CI [1,1], n=3 (tk4 excluded)
    x = g("synthetic", "success_at1", "A2-A0")
    expect("success A2-A0 exists", x is not None)
    if x:
        expect("success A2-A0 point == 1.0", approx(x["point"], 1.0), str(x["point"]))
        expect("success A2-A0 CI collapses to [1,1] (degenerate, seed-independent)",
               approx(x["lo"], 1.0) and approx(x["hi"], 1.0), f"[{x['lo']},{x['hi']}]")
        expect("success A2-A0 n_paired == 3 (tk4 A2-only EXCLUDED)", x["n"] == 3, str(x["n"]))
        expect("success A2-A0 caveat == UNDERPOWERED (k<6)", x["caveat"] == "UNDERPOWERED", x["caveat"])
        expect("success A2-A0 wilcoxon present (non-zero diffs)", x["p"] != "", repr(x["p"]))

    # 2. success_at1 A1-A0: va=[0,0,0] vb=[0,1,0] -> point 1/3; non-degenerate CI must bracket point
    x = g("synthetic", "success_at1", "A1-A0")
    if x:
        expect("success A1-A0 point == 0.3333", approx(x["point"], 0.3333, 1e-4), str(x["point"]))
        expect("success A1-A0 CI brackets point & within [0,1]",
               x["lo"] <= x["point"] <= x["hi"] and x["lo"] >= 0.0 and x["hi"] <= 1.0,
               f"[{x['lo']},{x['hi']}]")

    # 3. success_at1 A2-A1: va=[0,1,0] vb=[1,1,1] -> point 2/3
    x = g("synthetic", "success_at1", "A2-A1")
    if x:
        expect("success A2-A1 point == 0.6667", approx(x["point"], 0.6667, 1e-4), str(x["point"]))

    # 4. W2_event_rate A2-A0: va=[1,0,1] vb=[0,0,0] -> point -2/3; CI in [-1,0], brackets point
    x = g("synthetic", "W2_event_rate", "A2-A0")
    if x:
        expect("W2 A2-A0 point == -0.6667", approx(x["point"], -0.6667, 1e-4), str(x["point"]))
        expect("W2 A2-A0 CI within [-1,0] & brackets point",
               x["lo"] >= -1.0 and x["hi"] <= 0.0 and x["lo"] <= x["point"] <= x["hi"],
               f"[{x['lo']},{x['hi']}]")
        expect("W2 A2-A0 wilcoxon present", x["p"] != "", repr(x["p"]))

    # 5. decoy_accepted_rate A2-A0: all zeros -> ALL-EQUAL -> point 0, CI [0,0], Wilcoxon SKIPPED (guard)
    x = g("synthetic", "decoy_accepted_rate", "A2-A0")
    if x:
        expect("decoy A2-A0 point == 0.0 (all-equal)", approx(x["point"], 0.0), str(x["point"]))
        expect("decoy A2-A0 CI == [0,0]", approx(x["lo"], 0.0) and approx(x["hi"], 0.0), f"[{x['lo']},{x['hi']}]")
        expect("decoy A2-A0 wilcoxon SKIPPED on all-equal (empty)", x["p"] == "", repr(x["p"]))

    # 6. real subset bootstrapped SEPARATELY: success A2-A0, single paired task rk1 -> point 1.0, n=1
    x = g("real", "success_at1", "A2-A0")
    expect("real subset produced separately", x is not None)
    if x:
        expect("real success A2-A0 point == 1.0", approx(x["point"], 1.0), str(x["point"]))
        expect("real success A2-A0 n_paired == 1", x["n"] == 1, str(x["n"]))

    fails = [c for c in checks if not c[1]]
    for label, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  ({detail})"))
    print()
    if fails:
        print(f"BOOTSTRAP TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"BOOTSTRAP TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
