#!/usr/bin/env python3
"""Task-level cluster bootstrap for paired arm differences (reads analysis/tables/per_task.csv).

For each metric M and arm pair (A2 vs A0, A1 vs A0, A2 vs A1), restricted to tasks present in
BOTH arms (paired):
    - resample tasks with replacement (cluster bootstrap, not attempt-level), 10,000 times;
    - per resample, compute mean(M[arm_b]) - mean(M[arm_a]) over the paired tasks;
    - report the point difference and the 95% CI (2.5th / 97.5th percentile);
    - Wilcoxon signed-rank on the paired task-level values (scipy if available), reported with an
      explicit underpowered caveat (prereg §11).

Synthetic and real subsets are bootstrapped separately. Output: analysis/tables/bootstrap.csv.

Usage:  python analysis/bootstrap_ci.py [--tables analysis/tables] [--n 10000] [--seed 0]
"""
from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean

METRICS = ["success_at1", "success_at3", "W2_event_rate", "decoy_accepted_rate",
           "unverified_submission_rate", "comprehend_time_fixation_rate", "max_tokens_rate"]
PAIRS = [("A0", "A2"), ("A0", "A1"), ("A1", "A2")]

try:
    from scipy.stats import wilcoxon  # type: ignore
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False


def load(tables: Path):
    rows = list(csv.DictReader(open(tables / "per_task.csv", encoding="utf-8")))
    for r in rows:
        for m in METRICS:
            r[m] = float(r[m]) if r.get(m) not in (None, "", "None") else None
    return rows


def ci(diffs):
    s = sorted(diffs)
    n = len(s)
    return s[int(0.025 * n)], s[int(0.975 * n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tables", default="analysis/tables")
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    random.seed(args.seed)
    tables = Path(args.tables)
    rows = load(tables)

    # index: (subset, arm, task) -> metric dict
    idx = {(r["subset"], r["arm"], r["task_id"]): r for r in rows}
    subsets = sorted({r["subset"] for r in rows})

    out = []
    for subset in subsets:
        for metric in METRICS:
            for a, b in PAIRS:
                # paired tasks: present in both arms with non-None metric
                tasks = sorted({r["task_id"] for r in rows if r["subset"] == subset})
                paired = [t for t in tasks
                          if idx.get((subset, a, t)) and idx.get((subset, b, t))
                          and idx[(subset, a, t)][metric] is not None
                          and idx[(subset, b, t)][metric] is not None]
                if len(paired) < 1:
                    continue
                va = [idx[(subset, a, t)][metric] for t in paired]
                vb = [idx[(subset, b, t)][metric] for t in paired]
                point = mean(vb) - mean(va)
                # cluster bootstrap over tasks
                diffs = []
                k = len(paired)
                for _ in range(args.n):
                    samp = [random.randrange(k) for _ in range(k)]
                    diffs.append(mean([vb[i] for i in samp]) - mean([va[i] for i in samp]))
                lo, hi = ci(diffs)
                p = None
                if HAVE_SCIPY and k >= 1 and any(x != y for x, y in zip(va, vb)):
                    try:
                        p = round(float(wilcoxon(vb, va).pvalue), 4)
                    except Exception:
                        p = None
                out.append({
                    "subset": subset, "metric": metric, "pair": f"{b}-{a}",
                    "n_paired_tasks": k, "point_diff": round(point, 4),
                    "ci95_lo": round(lo, 4), "ci95_hi": round(hi, 4),
                    "wilcoxon_p": p if p is not None else "",
                    "caveat": "UNDERPOWERED" if k < 6 else "",
                })

    if out:
        with open(tables / "bootstrap.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
            w.writeheader()
            for r in out:
                w.writerow(r)
        print(f"wrote {tables / 'bootstrap.csv'} ({len(out)} rows); scipy={'yes' if HAVE_SCIPY else 'no'}")
    else:
        print("no paired comparisons available (need a metric present in two arms for the same task)")


if __name__ == "__main__":
    main()
