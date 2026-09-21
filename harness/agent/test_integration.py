#!/usr/bin/env python3
"""integration_selftest structural tests (bwrap-free).

The real self-test runs in the target image; here we verify the check registry + report shape against
the local backend, confirm the checks that DON'T need the RE toolchain pass locally, and confirm the
bwrap backend hard-fails when bwrap is absent.

Run from repo root:  python agent/test_integration.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.execution import LocalExecutionBackend
from agent.integration_selftest import _default_target, build_checks, run_integration_selftest

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


class _Sandboxed(LocalExecutionBackend):
    """Runs locally but reports sandbox_ok=True, so the sandbox-gated tool checks can be structurally
    exercised without bwrap. (Checks that need a REAL namespace -- bg-child reaping, isolation -- still
    fail here, correctly; they pass only under real bwrap.)"""
    def execute(self, req):
        r = super().execute(req)
        r.sandbox_ok = True
        return r


def main() -> int:
    be = _Sandboxed(allow_unsandboxed=True)
    target = _default_target()
    expect("a default target ELF is found", Path(target).exists())

    names = [n for n, _ in build_checks(be, target)]
    for needed in ("tool:file", "tool:nm", "python3:runs", "python3:tempfile (/tmp present)",
                   "run_binary:argv accepts the real flag", "run_binary:stdin accepts the real flag (framing)",
                   "trace_binary:strace argv", "trace_binary:strace stdin", "trace_binary:ltrace stdin",
                   "output cap fires", "wall timeout fires", "background child is reaped"):
        expect(f"check registry includes '{needed}'", needed in names)

    report = run_integration_selftest(be, target=target)
    expect("report has ok / n_checks / results", all(k in report for k in ("ok", "n_checks", "results")))
    expect("report stamps runtime + image + environment + executed_at (provenance)",
           all(k in report for k in ("runtime_code_sha256", "image_digest", "environment_lock_sha256",
                                     "executed_at")))
    expect("report includes the isolation check",
           any("isolation" in r["check"] for r in report["results"]))
    byname = {r["check"]: r["ok"] for r in report["results"]}

    # behavioral fixtures: the real flag must be ACCEPTED (a broken validator can't fake this)
    expect("run_binary:argv accepts the real flag under a sandboxed backend",
           byname.get("run_binary:argv accepts the real flag") is True)
    expect("run_binary:stdin accepts the real flag under a sandboxed backend",
           byname.get("run_binary:stdin accepts the real flag (framing)") is True)

    # NO false-green: a tracer that returns a structured 127 (unavailable / denied) must FAIL the trace
    # check. Tested via a fake backend so this holds identically in dev (no strace) and the target image.
    class _TraceFails(_Sandboxed):
        def execute(self, req):
            if req.argv and req.argv[0] in ("strace", "ltrace"):
                from agent.execution import ExecutionResult
                return ExecutionResult(exit_code=127, stderr="exec failed: tracer", sandbox_ok=True,
                                       sandbox_profile="validator")
            return super().execute(req)
    tf = {r["check"]: r["ok"] for r in run_integration_selftest(_TraceFails(allow_unsandboxed=True),
                                                                target=target)["results"]}
    expect("trace argv check FAILS on a 127 tracer (no false-green)",
           tf.get("trace_binary:strace argv") is False)
    expect("trace stdin check FAILS on a 127 tracer (no false-green)",
           tf.get("trace_binary:strace stdin") is False)

    # validate_report: enforce the WHOLE toolchain via a canonical schema, not a partial subset
    from agent.integration_selftest import (EXPECTED_CHECKS, INTEGRATION_REPORT_SCHEMA_VERSION,
                                            validate_report)
    produced = {n for n, _ in build_checks(be, target)} | {"isolation (no secrets/network/repo/pristine)"}
    expect("build_checks + isolation == EXPECTED_CHECKS (schema stays in sync)", produced == EXPECTED_CHECKS)

    minimal = {"ok": True, "runtime_code_sha256": "x", "image_digest": "y", "environment_lock_sha256": "z"}
    expect("validate_report rejects a minimal {ok, hashes} report", validate_report(minimal)[0] is False)

    def _full():
        rs = [{"check": c, "ok": True, "detail": ""} for c in EXPECTED_CHECKS]
        return {"ok": True, "n_checks": len(rs), "n_failed": 0,
                "schema_version": INTEGRATION_REPORT_SCHEMA_VERSION, "results": rs}

    expect("validate_report accepts a complete, all-passing report", validate_report(_full())[0] is True)

    one_fail = _full(); one_fail["results"][0]["ok"] = False
    expect("validate_report rejects a report with a failing check", validate_report(one_fail)[0] is False)

    # a report that drops the static-tool checks (the exact hole in the audit) must be rejected
    no_static = _full()
    no_static["results"] = [r for r in no_static["results"] if not r["check"].startswith("tool:")]
    no_static["n_checks"] = len(no_static["results"])
    expect("validate_report rejects a report missing the static-tool checks",
           validate_report(no_static)[0] is False)

    dupe = _full(); dupe["results"].append(dict(dupe["results"][0])); dupe["n_checks"] += 1
    expect("validate_report rejects duplicate check names", validate_report(dupe)[0] is False)

    old_v = _full(); old_v["schema_version"] = 999
    expect("validate_report rejects a wrong schema_version", validate_report(old_v)[0] is False)

    # regression for the audit's main bug: a backend whose VALIDATOR profile is broken must fail the
    # run_binary checks (previously they passed on tool==run_binary despite exit=-1).
    class _BrokenValidator(_Sandboxed):
        def execute(self, req):
            if req.profile == "validator":
                from agent.execution import ExecutionResult
                return ExecutionResult(sandbox_profile="validator", sandbox_ok=False,
                                       error="simulated validator failure")
            return super().execute(req)
    rep_b = run_integration_selftest(_BrokenValidator(allow_unsandboxed=True), target=target)
    bad = {r["check"]: r["ok"] for r in rep_b["results"]}
    expect("broken validator FAILS run_binary:argv (no false-green)",
           bad.get("run_binary:argv accepts the real flag") is False)
    expect("broken validator FAILS the overall self-test", rep_b["ok"] is False)

    # bwrap backend hard-fails when bwrap is missing (the CLI path)
    from agent.execution import BwrapExecutionBackend
    raised = False
    try:
        BwrapExecutionBackend(bwrap_path="no-bwrap-here-xyz", require=True)
    except RuntimeError:
        raised = True
    expect("integration CLI's bwrap backend hard-fails without bwrap", raised)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"INTEGRATION TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"INTEGRATION TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
