#!/usr/bin/env python3
"""Execution-backend tests.

Two testable layers WITHOUT bubblewrap (this container has no bwrap / namespaces):
  1. BwrapExecutionBackend.build_argv -- the sandbox POLICY (strict unshares, runtime roots, target ro,
     scratch rw, forbidden paths absent, placeholders substituted). Isolation is a function of this argv.
  2. LocalExecutionBackend mechanics -- real elapsed_ms, hard byte cap + kill, raw-byte truncation,
     timeout kill, stdin framing, target fresh-copy + SHA guard. These are the fixes shared by all tools.

The actual namespace isolation is validated only by the on-target isolation self-test, not here.

Run from repo root:  python agent/test_execution.py
"""
from __future__ import annotations

import hashlib
import os
import resource
import stat
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.execution import (BwrapExecutionBackend, ExecutionRequest, LocalExecutionBackend,
                             SANDBOX_SCRATCH, SANDBOX_TARGET)

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))

# rlimits that won't interfere with the (non-namespaced) test process: cap CPU + AS only.
SAFE_RL = {resource.RLIMIT_CPU: (5, 5), resource.RLIMIT_AS: (2 * 1024**3, 2 * 1024**3),
           resource.RLIMIT_CORE: (0, 0)}
PY = sys.executable


def test_bwrap_validator_no_scratch():
    """REGRESSION: a validator call (run_binary / BinaryOracle) binds NO scratch, so /work/scratch does
    not exist in the sandbox. An unconditional `--chdir /work/scratch` made bwrap abort before exec ->
    exit 1 + empty stdout -> adjudicate() saw no marker -> EVERY verdict 'inconclusive', in every arm.
    The old test only ever built a request WITH scratch, so it could not catch this."""
    be = BwrapExecutionBackend(require=False)
    req = ExecutionRequest(argv=["{TARGET}", "cand"], profile="validator", target_host_path="/x/target")
    a = be.build_argv(req, "/host/pristine/target")

    expect("no-scratch: scratch is NOT rw-bound", "--bind" not in a)
    chdir = a[a.index("--chdir") + 1]
    expect("no-scratch: --chdir does NOT point at the unmounted scratch", chdir != SANDBOX_SCRATCH)
    expect("no-scratch: --chdir points at a path mounted in the sandbox",
           f"--tmpfs {chdir}" in " ".join(a) or chdir == "/tmp")
    expect("no-scratch: HOME does NOT point at the unmounted scratch",
           a[a.index("HOME") + 1] != SANDBOX_SCRATCH)
    # the target must still be exposed read-only at the fixed sandbox path
    expect("argv sets USER (pyvex getpass.getuser() at import; no /etc/passwd in sandbox)",
           "USER" in a and bool(a[a.index("USER") + 1]))
    expect("argv sets LOGNAME", "LOGNAME" in a and bool(a[a.index("LOGNAME") + 1]))
    expect("no-scratch: target still ro-bound at /work/target",
           f"--ro-bind /host/pristine/target {SANDBOX_TARGET}" in " ".join(a))

    # with scratch bound, the chdir/HOME contract is unchanged
    req2 = ExecutionRequest(argv=["{TARGET}"], profile="validator", target_host_path="/x/target",
                            scratch_host_path="/host/scratch")
    a2 = be.build_argv(req2, "/host/pristine/target")
    expect("with-scratch: --chdir is /work/scratch", a2[a2.index("--chdir") + 1] == SANDBOX_SCRATCH)
    expect("with-scratch: HOME is /work/scratch", a2[a2.index("HOME") + 1] == SANDBOX_SCRATCH)


def test_bwrap_launch_env_scrubbed():
    """REGRESSION: bwrap stays alive as PID 1 inside the new PID namespace, so its OWN environ is
    readable at /proc/1/environ from inside the sandbox. --clearenv only scrubs the child bwrap execs.
    Inheriting os.environ therefore leaked ANTHROPIC_API_KEY to the agent's tools (isolation_selftest
    -> proc_env_secret)."""
    from agent.execution import bwrap_launch_env
    os.environ["RERAG_TEST_FAKE_SECRET"] = "sk-ant-CANARY-do-not-leak"
    try:
        env = bwrap_launch_env()
        expect("launch env is a fresh dict, not os.environ", env is not os.environ)
        expect("launch env does not carry the orchestrator secret",
               "RERAG_TEST_FAKE_SECRET" not in env
               and not any("CANARY" in str(v) for v in env.values()))
        expect("launch env carries no ANTHROPIC_* key", not any(k.startswith("ANTHROPIC") for k in env))
        expect("launch env still provides PATH (bwrap must be resolvable)", bool(env.get("PATH")))
    finally:
        os.environ.pop("RERAG_TEST_FAKE_SECRET", None)


def test_bwrap_argv():
    be = BwrapExecutionBackend(require=False)  # build argv even where bwrap is absent
    req = ExecutionRequest(argv=["nm", "{TARGET}"], profile="analysis",
                           target_host_path="/x/target", scratch_host_path="/host/scratch")
    a = be.build_argv(req, "/host/pristine/target")
    s = " ".join(a)

    # strict, EXPLICIT unshares (not --unshare-all, which implies --unshare-user-try)
    for flag in ("--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts"):
        expect(f"argv has {flag}", flag in a)
    expect("argv does NOT use --unshare-all", "--unshare-all" not in a)
    expect("argv has --unshare-cgroup-try", "--unshare-cgroup-try" in a)
    for flag in ("--clearenv", "--new-session", "--die-with-parent"):
        expect(f"argv has {flag}", flag in a)
    expect("argv drops all caps", "--cap-drop" in a and a[a.index("--cap-drop") + 1] == "ALL")
    expect("argv mounts a fresh /proc", "--proc" in a and a[a.index("--proc") + 1] == "/proc")
    expect("argv mounts /dev", "--dev" in a)
    expect("argv sets HOME to scratch", "HOME" in a and a[a.index("HOME") + 1] == SANDBOX_SCRATCH)
    expect("argv clears then sets PATH", "PATH" in a)
    expect("argv pins single-thread BLAS/OMP env", "OPENBLAS_NUM_THREADS" in a and "OMP_NUM_THREADS" in a)
    expect("argv mounts a private /tmp (angr/gdb/tempfile)", "/tmp" in a and "--tmpfs" in a)

    # mounts: runtime roots ro; target ro at /work/target; scratch rw at /work/scratch
    expect("runtime root /usr ro-bound", "--ro-bind-try" in a and "/usr" in a)
    expect("target ro-bound at /work/target",
           "--ro-bind" in a and f"/host/pristine/target {SANDBOX_TARGET}" in s)
    expect("scratch rw-bound at /work/scratch", f"--bind /host/scratch {SANDBOX_SCRATCH}" in s)
    expect("target is read-only (no --bind of the target path)", "--bind /host/pristine/target" not in s)

    # denylist: nothing sensitive is ever mounted
    for bad in ("pilot_tasks.json", ".env", "cards", "rerag_pristine", "groundtruth", "reverse_rag"):
        expect(f"argv never mounts '{bad}'", bad not in s)

    # placeholder substitution: {TARGET} -> in-sandbox path (model never supplies it)
    expect("{TARGET} substituted to the in-sandbox path", "{TARGET}" not in s and a[-1] == SANDBOX_TARGET)

    # validator profile builds the same strict skeleton
    vreq = ExecutionRequest(argv=["{TARGET}"], profile="validator", target_host_path="/x/t")
    va = be.build_argv(vreq, "/fresh/copy")
    expect("validator argv also strict-unshares", all(f in va for f in
           ("--unshare-user", "--unshare-net", "--unshare-pid", "--clearenv", "--die-with-parent")))


def test_bwrap_fail_closed():
    raised = False
    try:
        BwrapExecutionBackend(bwrap_path="definitely-not-bwrap-xyz", require=True)
    except RuntimeError:
        raised = True
    expect("bwrap backend fails closed when bwrap is missing", raised)


def test_local_opt_in():
    raised = False
    try:
        LocalExecutionBackend()  # no allow_unsandboxed
    except RuntimeError:
        raised = True
    expect("LocalExecutionBackend refuses without explicit allow_unsandboxed", raised)


def test_local_mechanics():
    be = LocalExecutionBackend(allow_unsandboxed=True)

    # elapsed_ms is real (not 0) + exit code propagates
    r = be.execute(ExecutionRequest(argv=[PY, "-c", "import time;time.sleep(0.2)"], rlimits=SAFE_RL))
    expect("elapsed_ms is measured (>=150ms for a 0.2s sleep)", r.elapsed_ms >= 150)
    expect("exit_code propagates (0)", r.exit_code == 0)
    expect("local backend marks sandbox_ok False (honest provenance)", r.sandbox_ok is False)

    r2 = be.execute(ExecutionRequest(argv=[PY, "-c", "import sys;sys.exit(3)"], rlimits=SAFE_RL))
    expect("nonzero exit_code propagates (3)", r2.exit_code == 3)

    # hard byte cap: process prints 100k, cap 1000 -> capped + flagged, SHA over the read bytes
    big = be.execute(ExecutionRequest(argv=[PY, "-c", "import sys;sys.stdout.write('X'*100000)"],
                                      max_output_bytes=1000, rlimits=SAFE_RL))
    expect("output_limit_exceeded set when output > cap", big.output_limit_exceeded)
    expect("stdout truncated to the byte cap", len(big.stdout.encode("utf-8", "replace")) <= 1000)
    expect("truncated flag set", big.truncated)
    expect("stdout_sha256 is over exactly the captured bytes",
           big.stdout_sha256 == hashlib.sha256(("X" * 1000).encode()).hexdigest())

    # raw-BYTE truncation (not char): multibyte output capped at a byte boundary must not raise. cap=101
    # splits a 2-byte char; the RAW captured bytes must be exactly 101 (SHA proves byte-accuracy).
    mb = be.execute(ExecutionRequest(
        argv=[PY, "-c", "import sys;sys.stdout.buffer.write('\u00e9'.encode()*1000)"],
        max_output_bytes=101, rlimits=SAFE_RL))
    raw_capped = ("\u00e9" * 1000).encode()[:101]
    expect("multibyte cap counts BYTES not chars (raw capped at exactly 101)",
           mb.stdout_sha256 == hashlib.sha256(raw_capped).hexdigest())
    expect("split multibyte decodes with replacement (no crash)",
           mb.output_limit_exceeded and "\ufffd" in mb.stdout)

    # wall timeout kills the child
    to = be.execute(ExecutionRequest(argv=[PY, "-c", "import time;time.sleep(5)"],
                                     timeout_s=0.3, rlimits=SAFE_RL))
    expect("timed_out set when the child overruns", to.timed_out)
    expect("timeout elapsed is near the deadline, not the full sleep", to.elapsed_ms < 2000)

    # exact-cap boundary: output of exactly cap bytes is NOT truncated; cap+1 is (Bug #3)
    for n, exp in ((999, False), (1000, False), (1001, True)):
        rc = be.execute(ExecutionRequest(argv=[PY, "-c", f"import sys;sys.stdout.write('X'*{n})"],
                                         max_output_bytes=1000, rlimits=SAFE_RL))
        expect(f"{n} bytes at cap=1000 -> truncated={exp}",
               rc.truncated == exp and rc.output_limit_exceeded == exp)

    # deterministic threading env reaches the child (Bug #2)
    from agent.execution import local_min_env
    expect("local_min_env pins OpenBLAS/OMP to 1 thread",
           local_min_env().get("OPENBLAS_NUM_THREADS") == "1" and local_min_env().get("OMP_NUM_THREADS") == "1")
    et = be.execute(ExecutionRequest(
        argv=[PY, "-c", "import os;print(os.getenv('OPENBLAS_NUM_THREADS'),os.getenv('OMP_NUM_THREADS'))"],
        rlimits=SAFE_RL))
    expect("child sees single-thread env", et.stdout.strip() == "1 1")


def test_local_target_guard():
    be = LocalExecutionBackend(allow_unsandboxed=True)
    d = Path(tempfile.mkdtemp(prefix="rerag_exectgt_"))
    exe = d / "prog"
    exe.write_text("#!/bin/sh\necho ran\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    sha = hashlib.sha256(exe.read_bytes()).hexdigest()

    ok = be.execute(ExecutionRequest(argv=["{TARGET}"], profile="validator",
                                     target_host_path=str(exe), expected_target_sha256=sha, rlimits=SAFE_RL))
    expect("target runs via a fresh copy (validator)", ok.stdout.strip() == "ran" and ok.error is None)
    expect("target_sha256 recorded", ok.target_sha256 == sha)

    bad = be.execute(ExecutionRequest(argv=["{TARGET}"], profile="validator",
                                      target_host_path=str(exe), expected_target_sha256="0" * 64,
                                      rlimits=SAFE_RL))
    expect("SHA mismatch fails closed (no execution)", bad.error is not None and "integrity" in bad.error)

    try:
        exe.unlink(); d.rmdir()
    except OSError:
        pass


def test_trace_output_read():
    be = LocalExecutionBackend(allow_unsandboxed=True)
    d = Path(tempfile.mkdtemp(prefix="rerag_traceout_"))
    tgt = d / "prog"
    tgt.write_text("#!/bin/sh\necho program_out\n")
    tgt.chmod(tgt.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    # fake tracer: `-o FILE TARGET [args]` -> write a trace line to FILE, then exec the target
    tracer = d / "faketracer"
    tracer.write_text('#!/bin/sh\nof="$2"; shift 2\necho "TRACE_OF $*" > "$of"\nexec "$@"\n')
    tracer.chmod(tracer.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    scratch = Path(tempfile.mkdtemp(prefix="rerag_tracesc_"))
    sha = hashlib.sha256(tgt.read_bytes()).hexdigest()
    res = be.execute(ExecutionRequest(
        argv=[str(tracer), "-o", "{SCRATCH}/trace.log", "{TARGET}"], profile="validator",
        target_host_path=str(tgt), expected_target_sha256=sha, scratch_host_path=str(scratch),
        trace_output_sandbox_path="/work/scratch/trace.log", rlimits=SAFE_RL))
    expect("program stdout captured (separate from trace)", res.stdout.strip() == "program_out")
    expect("tracer -o output read back separately", bool(res.trace_output) and "TRACE_OF" in res.trace_output)
    expect("trace_output_sha256 + bytes recorded",
           res.trace_output_sha256 != "" and res.trace_output_bytes_captured > 0)
    expect("small trace is not truncated", res.trace_output_truncated is False)

    # a trace larger than the cap is streamed to the cap and flagged truncated
    big_tracer = d / "bigtracer"
    big_tracer.write_text('#!/bin/sh\nof="$2"; shift 2\nhead -c 5000 /dev/zero | tr "\\0" "Z" > "$of"\nexec "$@"\n')
    big_tracer.chmod(big_tracer.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    scratch2 = Path(tempfile.mkdtemp(prefix="rerag_tracesc2_"))
    resb = be.execute(ExecutionRequest(
        argv=[str(big_tracer), "-o", "{SCRATCH}/trace.log", "{TARGET}"], profile="validator",
        target_host_path=str(tgt), expected_target_sha256=sha, scratch_host_path=str(scratch2),
        trace_output_sandbox_path="/work/scratch/trace.log", max_output_bytes=1000, rlimits=SAFE_RL))
    expect("oversized trace is truncated at the cap", resb.trace_output_truncated is True)
    expect("captured trace bytes == cap", resb.trace_output_bytes_captured == 1000)
    import shutil as _sh2
    _sh2.rmtree(scratch2, ignore_errors=True)
    for x in (d, scratch):
        try:
            import shutil as _sh
            _sh.rmtree(x, ignore_errors=True)
        except OSError:
            pass


def main() -> int:
    test_bwrap_argv()
    test_bwrap_validator_no_scratch()
    test_bwrap_launch_env_scrubbed()
    test_bwrap_fail_closed()
    test_local_opt_in()
    test_local_mechanics()
    test_local_target_guard()
    test_trace_output_read()

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"EXECUTION BACKEND TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"EXECUTION BACKEND TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
