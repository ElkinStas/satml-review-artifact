#!/usr/bin/env python3
"""Isolation self-test tests (no bwrap needed).

Without a real sandbox we can't prove ISOLATION here, but we CAN prove the self-test correctly DETECTS
non-isolation: run it against the unsandboxed local backend and confirm it fails closed and reports the
leaks (the repo path and/or the orchestrator's /proc secret are reachable). On the target machine the
same self-test, run against the bwrap backend, must instead PASS -- that is checked there, not here.

Run from repo root:  python agent/test_isolation.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.execution import LocalExecutionBackend
from agent.isolation import CANARY_ENV, format_selftest, isolation_selftest

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


class _LeakySandbox(LocalExecutionBackend):
    """Runs locally but CLAIMS to be sandboxed -- to exercise the probe's leak detection (a broken
    bwrap policy would look like this: sandbox_ok True, yet the repo / /proc secret are reachable)."""
    def execute(self, req):
        r = super().execute(req)
        r.sandbox_ok = True
        return r


def main() -> int:
    # Path 1: an honestly-unsandboxed backend is rejected before the probe even runs (sandbox_ok False).
    ok0, rep0 = isolation_selftest(LocalExecutionBackend(allow_unsandboxed=True), repo_path=REPO)
    expect("unsandboxed backend FAILS the self-test (fail-closed)", not ok0)
    expect("rejection reason is 'not a real sandbox'", "not a real sandbox" in rep0.get("reason", ""))

    # Path 2: a backend that CLAIMS sandboxing but leaks -> the probe catches concrete leaks.
    ok, report = isolation_selftest(_LeakySandbox(allow_unsandboxed=True), repo_path=REPO)
    expect("a leaky pseudo-sandbox FAILS the self-test", not ok)
    expect("probe returns a non-empty leak report", "leaks" in report and len(report["leaks"]) > 0)
    leaks = report.get("leaks", [])
    expect("probe detects the repo path or the orchestrator /proc secret",
           any(str(l).startswith("path:") for l in leaks) or "proc_env_secret" in leaks)
    expect("format_selftest reports FAILED with the leaks", "FAILED" in format_selftest(report))

    # the canary secret is only transient in the orchestrator env and is cleaned up afterwards
    expect("canary env var is removed after the self-test", CANARY_ENV not in os.environ)
    expect("a clean report formats as PASSED", "PASSED" in format_selftest({"ok": True, "leaks": []}))

    fails = [c for c in checks if not c[1]]
    for label, ok_ in checks:
        print(f"  {'PASS' if ok_ else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"ISOLATION TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"ISOLATION TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
