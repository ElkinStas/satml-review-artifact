#!/usr/bin/env python3
"""Deterministic test for the metrics pipeline (no LLM, no real traces).

Runs compute_metrics.py on hand-built fixtures with KNOWN ground truth and asserts the derived
values. Expected values are derived by hand from the fixture design (NOT read back from output).

fixtures/      3 traces (A0/A2): core derivation -- success@k, MC2, MC3, ledger, blocked, W2 aggregation.
  fix_solve (A2): run accepted -> validated -> submitted accepted  => solved; MC2 correct allow
  fix_block (A2): submit with no accepting run -> blocked           => MC2 correct block; unverified (label)
  fix_decoy (A0): submit a static decoy, rejected                   => decoy_accepted (label)

fixtures_ext/  3 traces (A0/A1): coverage-gap closure --
  t_a_01_decoy_string  (A1): retrieves a decoy_static_string card AND cites it; a VALID run_binary
                             validation. Real task_id => MC1 fires and MATCHES (expected family).
  t_b_01_transform_compare (A1): retrieves a decoy_static_string card (WRONG family) and does NOT
                             cite it; an INVALID validation (verdict disagrees with the cited run).
                             Real task_id => MC1 MISSES. Label ctf=true, decompiler_artifact_trust=true.
  t_a_02_decoy_function (A0): an A0 trace that (for test purposes) contains retrieval + a citation
                             -- the A0-leak anomaly shape; asserts card_citation_rate SURFACES it.

Run from repo root:  python analysis/tests/test_metrics.py
"""
import csv
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "analysis/tests/fixtures"
FIX_EXT = REPO / "analysis/tests/fixtures_ext"


def run_metrics(fixdir: Path) -> Path:
    out = Path(tempfile.mkdtemp())
    cmd = [sys.executable, str(REPO / "analysis/compute_metrics.py"),
           "--runs-glob", str(fixdir / "**/trace.jsonl"),
           "--labels-glob", str(fixdir / "labels.json"),
           "--out", str(out), "--repo", str(REPO)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        raise SystemExit(1)
    return out


def rows_by(path, key):
    return {r[key]: r for r in csv.DictReader(open(path, encoding="utf-8"))}


def num(x):
    return float(x) if x not in (None, "", "None") else None


checks = []


def expect(label, got, want):
    ok = (got == want) if not isinstance(want, float) else (got is not None and abs(got - want) < 1e-6)
    checks.append((label, ok, got, want))


def main() -> int:
    # ===================== original fixtures: core derivation =====================
    out = run_metrics(FIX)
    prim = {(x["arm"], x["subset"]): x for x in csv.DictReader(open(out / "primary.csv", encoding="utf-8"))}
    man = rows_by(out / "manipulation.csv", "arm")
    sec = rows_by(out / "secondary.csv", "arm")

    a0 = prim[("A0", "real")]
    a2 = prim[("A2", "real")]
    expect("A0 W2_event_rate == 1.0 (decoy)", num(a0["W2_event_rate"]), 1.0)
    expect("A0 decoy_accepted_rate == 1.0", num(a0["decoy_accepted_rate"]), 1.0)
    expect("A2 success@1 == 0.5 (1 of 2 attempts solved)", num(a2["success@1"]), 0.5)
    expect("A2 success@3 == 0.5 (1 of 2 tasks solved)", num(a2["success@3"]), 0.5)
    expect("A2 unverified_submission_rate == 0.5", num(a2["unverified_submission_rate"]), 0.5)
    expect("A2 W2_event_rate == 0.5 (block=1 canonical event)", num(a2["W2_event_rate"]), 0.5)

    m2 = man["A2"]
    expect("A2 MC2 == 1.0 (correct allow + correct block)", num(m2["MC2_scaffold_enforcement_correctness"]), 1.0)
    expect("A2 MC2 decisions == 2", int(m2["MC2_n_submit_decisions"]), 2)
    expect("A2 MC3 (budget basis) == 0.0", num(m2["MC3_token_budget_exhaustion_rate"]), 0.0)

    s2 = sec["A2"]
    expect("A2 blocked_submission_count == 0.5", num(s2["blocked_submission_count"]), 0.5)
    expect("A2 ledger_completeness_rate == 1.0", num(s2["ledger_completeness_rate"]), 1.0)
    expect("A2 time_to_solve_steps == 2", num(s2["time_to_solve_steps"]), 2.0)

    # ===================== extended fixtures: coverage-gap closure =====================
    oute = run_metrics(FIX_EXT)
    mane = rows_by(oute / "manipulation.csv", "arm")
    sece = rows_by(oute / "secondary.csv", "arm")
    pte = {(x["task_id"], x["arm"]): x for x in csv.DictReader(open(oute / "per_task.csv", encoding="utf-8"))}
    e1, e0 = mane["A1"], mane["A0"]
    s1e, s0e = sece["A1"], sece["A0"]

    # MC1 (previously NA on fixtures -> now exercised via real task_ids)
    expect("EXT A1 MC1 == 0.5 (1 family-match + 1 miss)", num(e1["MC1_family_match_relevance"]), 0.5)
    expect("EXT A0 MC1 == 1.0 (retrieves matching family)", num(e0["MC1_family_match_relevance"]), 1.0)
    # card_citation_rate (the A0-anomaly metric) -- both arms exercised
    expect("EXT A1 card_citation_rate == 0.5 (1 cites, 1 ignores)", num(s1e["card_citation_rate"]), 0.5)
    expect("EXT A1 card_ignored_rate == 0.5", num(s1e["card_ignored_rate"]), 0.5)
    expect("EXT A0 card_citation_rate == 1.0 (SURFACES A0-retrieval anomaly)", num(s0e["card_citation_rate"]), 1.0)
    # secondary label rates (positive path now exercised)
    expect("EXT A1 comprehend_time_fixation_rate == 0.5 (ctf on 1 of 2)", num(s1e["comprehend_time_fixation_rate"]), 0.5)
    expect("EXT A1 decompiler_artifact_trust_rate == 0.5", num(s1e["decompiler_artifact_trust_rate"]), 0.5)
    # invalid_validation_rate (0.0 valid + 1.0 mismatch -> 0.5 pins BOTH paths)
    expect("EXT A1 invalid_validation_rate == 0.5 (1 valid + 1 verdict-mismatch)", num(s1e["invalid_validation_rate"]), 0.5)
    # per_task.csv (bootstrap input) is now read + ctf positive path
    expect("EXT per_task t_b_01/A1 ctf_rate == 1.0", num(pte[("t_b_01_transform_compare", "A1")]["comprehend_time_fixation_rate"]), 1.0)
    expect("EXT per_task t_a_01/A1 W2_event_rate == 0.0", num(pte[("t_a_01_decoy_string", "A1")]["W2_event_rate"]), 0.0)

    fails = [c for c in checks if not c[1]]
    for label, ok, got, want in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    print()
    if fails:
        print(f"METRICS PIPELINE TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"METRICS PIPELINE TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
