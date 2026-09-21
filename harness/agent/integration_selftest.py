"""In-sandbox integration self-test (#12).

isolation_selftest proves the sandbox BLOCKS things; this proves it still WORKS -- every tool the study
needs actually runs inside the real bwrap sandbox on the target machine, resource caps fire, background
children are reaped, and secrets/network/repo stay unreachable. Produces a JSON report that run_pilot can
fold into provenance. Fail-closed: nonzero exit if any check fails.

Run IN the rerag-re image (needs bwrap + the RE toolchain):

    python -m agent.integration_selftest [--target <elf>] [--json report.json]

This is NOT runnable in the minimal build container (no bwrap / angr / r2 / gdb); it is a target-image
gate. The check registry + report shape are unit-tested against the local backend in test_integration.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent.execution import ANALYSIS_RLIMITS, ExecutionRequest

REPO = Path(__file__).resolve().parents[1]

INTEGRATION_REPORT_SCHEMA_VERSION = 2

# The EXACT set of checks a valid report must contain -- the whole toolchain, not a hand-maintained
# subset. build_checks() + the isolation check must produce EXACTLY this set (a test enforces that); when
# the self-test grows, bump SCHEMA_VERSION rather than let build_checks and the validator drift apart.
EXPECTED_CHECKS = {
    "tool:file", "tool:strings", "tool:nm", "tool:objdump", "tool:readelf",
    "python3:runs", "python3:imports angr/z3/capstone", "python3:tempfile (/tmp present)",
    "r2:runs", "gdb:runs",
    "run_binary:argv accepts the real flag", "run_binary:stdin accepts the real flag (framing)",
    "trace_binary:strace argv", "trace_binary:ltrace argv",
    "trace_binary:strace stdin", "trace_binary:ltrace stdin",
    "output cap fires", "wall timeout fires", "process-count limit is enforced",
    "background child is reaped", "isolation (no secrets/network/repo/pristine)",
}


def validate_report(rep) -> tuple[bool, str]:
    """Structural + completeness validation of an integration report (independent of freshness):
    correct schema version, EXACTLY the expected check set (no missing / no extras / no duplicates), every
    check passed, and self-consistent counts."""
    if not isinstance(rep, dict):
        return False, "report is not a JSON object"
    if rep.get("schema_version") != INTEGRATION_REPORT_SCHEMA_VERSION:
        return False, f"report schema_version != {INTEGRATION_REPORT_SCHEMA_VERSION}"
    results = rep.get("results")
    if not isinstance(results, list) or not results:
        return False, "report has no results[]"
    name_list = [r.get("check") for r in results if isinstance(r, dict)]
    if len(name_list) != len(set(name_list)):
        return False, "report has duplicate check names"
    if set(name_list) != EXPECTED_CHECKS:
        missing = EXPECTED_CHECKS - set(name_list)
        extra = set(name_list) - EXPECTED_CHECKS
        return False, f"report check set mismatch (missing={sorted(missing)}, extra={sorted(extra)})"
    if not all(isinstance(r, dict) and r.get("ok") is True for r in results):
        return False, "report has failing checks"
    if rep.get("ok") is not True or rep.get("n_failed") != 0 or rep.get("n_checks") != len(results):
        return False, "report ok/n_failed/n_checks are inconsistent"
    return True, "ok"


def _run(backend, argv, *, profile="analysis", target=None, scratch=None, stdin=None,
         timeout_s=20.0, cap=8192, trace_path=None, rlimits=None):
    import tempfile
    sc = scratch or tempfile.mkdtemp(prefix="rerag_integ_")
    return backend.execute(ExecutionRequest(
        argv=argv, profile=profile, target_host_path=target, scratch_host_path=sc,
        stdin_data=stdin, timeout_s=timeout_s, max_output_bytes=cap,
        trace_output_sandbox_path=trace_path, rlimits=rlimits))


_FIXTURES = {"argv": "t_a_01_decoy_string", "stdin": "t_b_02_transform_compare"}


def _resolve_fixture(repo_path, input_method: str):
    """Resolve a FIXED fixture task (not 'first by JSON order', which isn't in any hash) -> its binary +
    real flag + markers. None if unavailable. In the orchestrator the repo is present, so we can emit the
    real flag via solve.py."""
    import json
    import subprocess
    repo = Path(repo_path)
    tid = _FIXTURES.get(input_method)
    pt = repo / "pilot_tasks.json"
    if not tid or not pt.exists():
        return None
    try:
        e = json.loads(pt.read_text()).get(tid, {})
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(e, dict) or e.get("input_method") != input_method:
        return None
    binrel = e.get("binary", "")
    binp = repo / binrel
    gt = repo / "tasks" / "synthetic" / tid / "groundtruth" / "solve.py"
    if not binp.exists() or not gt.exists():
        return None
    try:
        flag = subprocess.run(["python3", "solve.py", "--emit"], cwd=gt.parent,
                              capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:  # noqa: BLE001
        return None
    if not flag:
        return None
    return {"task_id": tid, "binary": str(binp), "flag": flag, "input_method": input_method,
            "success_marker": e.get("success_marker"), "fail_marker": e.get("fail_marker")}


def build_checks(backend, target: str, repo_path=REPO):
    """Return a list of (name, fn) where fn() -> (ok: bool, detail: str). Each runs a probe in-sandbox."""
    checks = []
    def add(name):
        def deco(fn): checks.append((name, fn)); return fn
        return deco

    # --- static toolchain ---
    # The criterion is "the tool ran and produced a result", not "the tool produced stdout". Since the
    # pool moved to -O2 -s, `nm` on a stripped target legitimately exits 0 with an EMPTY stdout and
    # writes "no symbols" to stderr. Demanding non-empty stdout would fail the toolchain check for a
    # target state that is now the norm -- and stripped is what a real-world binary looks like.
    for fam, argv in (("file", ["file", "{TARGET}"]), ("strings", ["strings", "{TARGET}"]),
                      ("nm", ["nm", "{TARGET}"]), ("objdump", ["objdump", "-d", "{TARGET}"]),
                      ("readelf", ["readelf", "-h", "{TARGET}"])):
        def mk(fam=fam, argv=argv):
            def fn():
                r = _run(backend, argv, target=target)
                produced = len(r.stdout) > 0 or "no symbols" in (r.stderr or "").lower()
                return (r.sandbox_ok and r.exit_code == 0 and produced,
                        f"exit={r.exit_code}" + ("" if len(r.stdout) else " (stripped: no symbols)"))
            return fn
        add(f"tool:{fam}")(mk())

    @add("python3:runs")
    def _py():
        r = _run(backend, ["python3", "-c", "print(6*7)"], target=target)
        return (r.exit_code == 0 and r.stdout.strip() == "42", f"exit={r.exit_code}")

    @add("python3:imports angr/z3/capstone")
    def _imp():
        r = _run(backend, ["python3", "-c", "import angr, z3, capstone; print('ok')"], target=target)
        return (r.exit_code == 0 and "ok" in r.stdout, r.stderr[:120] or f"exit={r.exit_code}")

    @add("python3:tempfile (/tmp present)")
    def _tmp():
        r = _run(backend, ["python3", "-c",
                           "import tempfile;\nf=tempfile.NamedTemporaryFile();f.write(b'x');print('tmp_ok')"],
                 target=target)
        return (r.exit_code == 0 and "tmp_ok" in r.stdout, r.stderr[:120] or f"exit={r.exit_code}")

    @add("r2:runs")
    def _r2():
        r = _run(backend, ["r2", "-q", "-c", "i", "{TARGET}"], target=target)
        return (r.exit_code == 0, f"exit={r.exit_code}")

    @add("gdb:runs")
    def _gdb():
        r = _run(backend, ["gdb", "-batch", "-ex", "info functions", "{TARGET}"], target=target)
        return (r.exit_code == 0, f"exit={r.exit_code}")

    # --- execution + framing: REAL behavioral fixtures (a broken validator must FAIL these, not pass on
    #     'did not crash'). Fixtures are resolved from the repo in the orchestrator; the candidates are fed
    #     to the sandboxed tools. ---
    argv_fx = _resolve_fixture(repo_path, "argv")
    stdin_fx = _resolve_fixture(repo_path, "stdin")

    @add("run_binary:argv accepts the real flag")
    def _rba():
        from agent.tools.run_binary import RunBinaryTool
        if not argv_fx:
            return (False, "no argv fixture resolved")
        tr = RunBinaryTool(backend=backend, binary_path=argv_fx["binary"], default_input_method="argv",
                           success_marker=argv_fx["success_marker"], fail_marker=argv_fx["fail_marker"])
        good = tr.run(step_idx=0, candidate=argv_fx["flag"], input_method="argv")
        bad = tr.run(step_idx=1, candidate="integration-not-the-flag", input_method="argv")
        return (good.exit_code != -1 and good.verdict == "accepted"
                and bad.exit_code != -1 and bad.verdict == "rejected",
                f"real={good.verdict}({good.exit_code}) junk={bad.verdict}({bad.exit_code})")

    @add("run_binary:stdin accepts the real flag (framing)")
    def _rbs():
        from agent.tools.run_binary import RunBinaryTool
        if not stdin_fx:
            return (False, "no stdin fixture resolved")
        tr = RunBinaryTool(backend=backend, binary_path=stdin_fx["binary"], default_input_method="stdin",
                           success_marker=stdin_fx["success_marker"], fail_marker=stdin_fx["fail_marker"])
        good = tr.run(step_idx=0, candidate=stdin_fx["flag"], input_method="stdin")
        bad = tr.run(step_idx=1, candidate="integration-not-the-flag", input_method="stdin")
        return (good.exit_code != -1 and good.verdict == "accepted"
                and bad.exit_code != -1 and bad.verdict == "rejected",
                f"real={good.verdict}({good.exit_code}) junk={bad.verdict}({bad.exit_code})")

    for tracer in ("strace", "ltrace"):
        for mname, fx in (("argv", argv_fx), ("stdin", stdin_fx)):
            def mk(tracer=tracer, mname=mname, fx=fx):
                def fn():
                    from agent.tools.trace_binary import TraceBinaryTool
                    if not fx:
                        return (False, f"no {mname} fixture resolved")
                    tt = TraceBinaryTool(backend=backend, binary_path=fx["binary"],
                                         default_input_method=mname)
                    res = tt.run(step_idx=0, tracer=tracer, candidate=fx["flag"], input_method=mname)
                    bad = ("exec failed" in res.stderr or "Operation not permitted" in res.stderr
                           or "Operation not permitted" in (res.trace_output or ""))
                    ok = (res.exit_code == 0 and bool(res.trace_output) and res.trace_output_sha256 != ""
                          and not bad)
                    return (ok, f"exit={res.exit_code} trace_bytes={res.trace_output_bytes_captured}")
                return fn
            add(f"trace_binary:{tracer} {mname}")(mk())

    # --- resource caps ---
    @add("output cap fires")
    def _cap():
        r = _run(backend, ["python3", "-c", "import sys;sys.stdout.write('X'*100000)"], target=target, cap=1000)
        return (r.output_limit_exceeded and len(r.stdout.encode("utf-8", "replace")) <= 1000, "capped")

    @add("wall timeout fires")
    def _to():
        r = _run(backend, ["python3", "-c", "import time;time.sleep(30)"], target=target, timeout_s=1.0)
        return (r.timed_out and r.elapsed_ms < 5000, f"elapsed={r.elapsed_ms}ms")

    @add("process-count limit is enforced")
    def _nproc():
        # bounded probe (NOT a real fork bomb): a test-only tight RLIMIT_NPROC=16 must make the ~17th
        # spawn hit EAGAIN, proving the rlimit actually took effect inside the user/PID namespace (the
        # _preexec setrlimit swallows failures, so this is the only thing that catches NPROC not working).
        import resource as _r
        rl = dict(ANALYSIS_RLIMITS); rl[_r.RLIMIT_NPROC] = (16, 16)
        code = ("import subprocess, sys\n"
                "ok = 0; procs = []\n"
                "try:\n"
                "    for i in range(32):\n"
                "        procs.append(subprocess.Popen(['sleep', '5'])); ok += 1\n"
                "except OSError:\n"
                "    pass\n"
                "for p in procs:\n"
                "    p.kill()\n"
                "sys.stdout.write(str(ok))\n")
        r = _run(backend, ["python3", "-c", code], target=target, rlimits=rl, timeout_s=12.0)
        try:
            n = int((r.stdout or "").strip() or "999")
        except ValueError:
            n = 999
        return (r.sandbox_ok and n < 32, f"spawned={n} before EAGAIN (cap 16)")

    @add("background child is reaped")
    def _bg():
        import os as _os
        import shutil as _sh
        import tempfile as _tf
        import time as _t
        sc = _tf.mkdtemp(prefix="rerag_bgtest_")
        # start_new_session=True: the child ESCAPES the tool's process group, so killpg(original pgid)
        # cannot reach it. Only the PID namespace (--unshare-pid) reaps it -> this proves namespace
        # cleanup of arbitrary agent-controlled processes, not just same-group kill.
        code = ("import subprocess, sys\n"
                "subprocess.Popen(['sh', '-c', 'sleep 2; : > {SCRATCH}/background_survived'],"
                " start_new_session=True)\n"
                "sys.stdout.write('spawned')\n")
        r = _run(backend, ["python3", "-c", code], target=target, scratch=sc, timeout_s=8.0)
        _t.sleep(3.0)   # longer than the child's sleep: if it survived, the marker now exists
        survived = _os.path.exists(_os.path.join(sc, "background_survived"))
        _sh.rmtree(sc, ignore_errors=True)
        return (not r.timed_out and "spawned" in r.stdout and not survived,
                f"survived={survived} (marker absent == namespace-reaped)")

    return checks


def run_integration_selftest(backend, *, target: str, repo_path=REPO) -> dict:
    import time
    from agent.isolation import isolation_selftest
    results = []
    for name, fn in build_checks(backend, target, repo_path):
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"exception: {e!r}"
        results.append({"check": name, "ok": bool(ok), "detail": detail})
    iso_ok, iso_rep = isolation_selftest(backend, repo_path=repo_path)
    results.append({"check": "isolation (no secrets/network/repo/pristine)", "ok": iso_ok,
                    "detail": json.dumps(iso_rep.get("leaks", iso_rep.get("reason", "")))})
    ok = all(r["ok"] for r in results)
    # provenance: bind this report to the exact runtime code + image it was produced under (#4)
    try:
        from agent.preflight import compute_actual_locks
        runtime_sha = compute_actual_locks(repo_path).get("runtime_code_sha256", "")
    except Exception:  # noqa: BLE001
        runtime_sha = ""
    from agent.pin_environment import _image_digest
    import hashlib as _hl
    import platform as _plat
    envp = Path(repo_path) / "environment_lock.json"
    env_sha = _hl.sha256(envp.read_bytes()).hexdigest() if envp.exists() else ""
    bwrap_ver = ""
    getver = getattr(backend, "bwrap_version", None)
    if callable(getver):
        try:
            bwrap_ver = getver()
        except Exception:  # noqa: BLE001
            bwrap_ver = ""
    return {"ok": ok, "n_checks": len(results), "n_failed": sum(1 for r in results if not r["ok"]),
            "schema_version": INTEGRATION_REPORT_SCHEMA_VERSION,
            "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "image_digest": _image_digest(), "runtime_code_sha256": runtime_sha,
            "environment_lock_sha256": env_sha, "platform": _plat.platform(), "bwrap_version": bwrap_ver,
            "results": results}


def _default_target() -> str:
    # any committed ELF works for the static-tool checks
    for p in sorted((REPO / "tasks" / "synthetic").glob("t_*/binary/*")):
        if p.suffix != ".c" and p.is_file():
            return str(p)
    return "/bin/true"


if __name__ == "__main__":
    import argparse
    from agent.execution import BwrapExecutionBackend
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=_default_target())
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    backend = BwrapExecutionBackend()  # fail-closed if bwrap missing -> hard failure, as required
    report = run_integration_selftest(backend, target=args.target)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n")
    for r in report["results"]:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['check']:<44} {r['detail']}")
    print(f"\nINTEGRATION SELF-TEST: {'PASSED' if report['ok'] else 'FAILED'} "
          f"({report['n_checks'] - report['n_failed']}/{report['n_checks']})")
    raise SystemExit(0 if report["ok"] else 1)
