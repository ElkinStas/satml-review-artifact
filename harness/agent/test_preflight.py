#!/usr/bin/env python3
"""Tests for the fail-closed lock preflight (agent/preflight.py, #9).

Run from repo root:  python agent/test_preflight.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.preflight import _KEYS, compute_actual_locks, load_lock, verify_locks

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


def main() -> int:
    # 1. clean repo verifies
    ok, report, actual = verify_locks(REPO)
    expect("clean repo passes preflight", ok)
    expect("every reference key is reported", {r[0] for r in report} == set(_KEYS))
    expect("all reported entries are ok on a clean repo", all(r[1] for r in report))

    # 2. recompute is deterministic
    a2 = compute_actual_locks(REPO)
    expect("compute_actual_locks is deterministic", actual == a2)

    # 3. recompute matches the known frozen anchors
    expect("cards_sha256 == frozen library",
           actual["cards_sha256"] == "4f060500b4d7419d5555065ea2e7d77eaeee90f23e72364c7ede57af66dd603b")
    # W10e: pool re-anchored to on-disk binaries (byte-identical to the A0-run set); see
    # prereg/deviation_registry.md and preflight_lock.json _reanchor_log.
    expect("pool_hash_sha256 == frozen pool",
           actual["pool_hash_sha256"].startswith("f8ad91148a80"))
    expect("task_metadata_sha256 == taxonomy 1.0",
           actual["task_metadata_sha256"].startswith("98ac19c43ea7"))

    # 4. a single drifted SHA fails closed (that entry DRIFT, the rest ok)
    lk = dict(load_lock(REPO))
    lk["retrieval_py_sha256"] = "deadbeef" * 8
    ok_d, report_d, _ = verify_locks(REPO, lock=lk)
    expect("a drifted retrieval SHA fails preflight", not ok_d)
    drift = {r[0] for r in report_d if not r[1]}
    expect("exactly the drifted key is flagged", drift == {"retrieval_py_sha256"})

    # 5. a missing lock key fails closed
    lk2 = {k: v for k, v in load_lock(REPO).items() if k != "tool_surface_sha256"}
    ok_m, _, _ = verify_locks(REPO, lock=lk2)
    expect("a missing lock key fails preflight", not ok_m)

    # 6. run parameters are anchored: a changed marker/framing would drift run_params_sha256
    expect("run_params_sha256 is one of the anchored keys", "run_params_sha256" in _KEYS)
    lk3 = dict(load_lock(REPO))
    lk3["run_params_sha256"] = "0" * 64
    ok_r, report_r, _ = verify_locks(REPO, lock=lk3)
    expect("a drifted run_params SHA fails preflight",
           (not ok_r) and {r[0] for r in report_r if not r[1]} == {"run_params_sha256"})

    # 7. the broad runtime-code anchor catches a change to any run-affecting file (scaffold/loop/etc.)
    expect("runtime_code_sha256 is anchored", "runtime_code_sha256" in _KEYS)
    lk4 = dict(load_lock(REPO))
    lk4["runtime_code_sha256"] = "0" * 64
    ok_c, report_c, _ = verify_locks(REPO, lock=lk4)
    expect("a drifted runtime_code SHA fails preflight",
           (not ok_c) and {r[0] for r in report_c if not r[1]} == {"runtime_code_sha256"})

    fails = [c for c in checks if not c[1]]
    for label, ok_ in checks:
        print(f"  {'PASS' if ok_ else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"PREFLIGHT TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"PREFLIGHT TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
