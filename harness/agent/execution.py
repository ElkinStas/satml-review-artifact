"""Sandboxed execution backend (isolation unit, variant A: bubblewrap).

All four executing tools (shell inspection, run_binary, oracle, trace_binary) go through ONE backend so
timeout / stdin framing / env / output cap / process cleanup / SHA / sandbox flags can't diverge. Tools
emit an argv with `{TARGET}` / `{SCRATCH}` placeholders; the backend substitutes the in-sandbox paths and
prepares the target. Two backends implement the same contract:

  BwrapExecutionBackend  -- per-call bubblewrap sandbox (the ONLY backend valid for registered runs).
                            Fail-closed: raises if bwrap is missing; NEVER falls back to a bare subprocess.
  LocalExecutionBackend  -- same mechanics WITHOUT namespaces (RLIMIT + streaming cap + real elapsed +
                            raw-byte truncation). Explicit opt-in only (tests / exploratory); never auto.

Shared mechanics in `_run_capped`: streaming stdout/stderr with a hard byte cap (kill the process group on
exceed), a wall timeout (kill the group), real elapsed_ms, RLIMIT via preexec, and a SHA over the RAW bytes
actually read (partial when the cap is hit -- signalled by output_limit_exceeded).

NOTE: bubblewrap is a low-level sandbox CONSTRUCTOR, not a ready policy; isolation is entirely a function
of the argv this file builds. Unit tests here check the argv is correct; registered readiness is decided
only by the on-target isolation self-test (see the isolation-preflight, added when tools are wired in).
"""
from __future__ import annotations

import hashlib
import os
import resource
import shutil
import signal
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

# In-sandbox mount points (bwrap). Tools reference these via placeholders.
SANDBOX_TARGET = "/work/target"
SANDBOX_SCRATCH = "/work/scratch"

# Runtime roots every RE tool needs (merged-usr Ubuntu: /bin,/lib,/lib64 are symlinks into /usr).
# Bound READ-ONLY; -try so a missing/symlinked path is skipped rather than aborting.
_RUNTIME_ROOTS = ("/usr", "/bin", "/lib", "/lib64", "/etc/alternatives", "/etc/ld.so.cache")

# Paths that must NEVER be mounted into any sandbox (used by tests as a denylist too).
FORBIDDEN_MOUNTS = ("pilot_tasks.json", ".env", "/cards/", "rerag_pristine_", "groundtruth", "/reverse_rag")


def _rlimits(cpu_s, as_bytes, nproc, nofile, fsize_bytes) -> dict:
    return {
        resource.RLIMIT_CPU: (cpu_s, cpu_s),
        resource.RLIMIT_AS: (as_bytes, as_bytes),      # must cover bwrap+loader+tool; angr needs headroom
        resource.RLIMIT_NPROC: (nproc, nproc),         # ns-dependent; integration test 'fork bomb' verifies
        resource.RLIMIT_NOFILE: (nofile, nofile),
        resource.RLIMIT_FSIZE: (fsize_bytes, fsize_bytes),
        resource.RLIMIT_CORE: (0, 0),
    }


# Profile resource ceilings. These are CALIBRATION knobs, not final: RLIMIT_AS in particular must be large
# enough that it never becomes a treatment (kills angr/z3), only a safety cap. Tune on the target image.
ANALYSIS_RLIMITS = _rlimits(cpu_s=60, as_bytes=4 * 1024**3, nproc=256, nofile=256, fsize_bytes=64 * 1024**2)
VALIDATOR_RLIMITS = _rlimits(cpu_s=10, as_bytes=512 * 1024**2, nproc=64, nofile=128, fsize_bytes=16 * 1024**2)


@dataclass
class ExecutionRequest:
    argv: list[str]                       # tokens; may contain {TARGET}/{SCRATCH} (substring-substituted)
    profile: str = "analysis"             # "analysis" | "validator"
    stdin_data: bytes | None = None       # already framed (e.g. candidate + b"\n"); None -> /dev/null
    target_host_path: str | None = None   # host binary to expose as {TARGET} (validator: fresh copy/call)
    expected_target_sha256: str | None = None  # integrity guard before exposing the target
    scratch_host_path: str | None = None  # host dir exposed rw as {SCRATCH} (analysis: per-attempt)
    timeout_s: float = 20.0
    max_output_bytes: int = 8192          # hard cap PER stream (stdout, stderr)
    trace_output_sandbox_path: str | None = None  # e.g. "/work/scratch/trace.log"; read back after run
    rlimits: dict | None = None           # override; else profile default


@dataclass
class ExecutionResult:
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    stdout_sha256: str = ""               # over RAW bytes actually read (partial if output_limit_exceeded)
    stderr_sha256: str = ""
    trace_output: str | None = None
    trace_output_sha256: str = ""         # SHA over the captured trace bytes (<= cap)
    trace_output_truncated: bool = False  # the tracer's -o file exceeded the cap
    trace_output_bytes_captured: int = 0
    elapsed_ms: int = 0
    timed_out: bool = False
    output_limit_exceeded: bool = False
    truncated: bool = False
    target_sha256: str | None = None      # SHA of the binary that actually executed
    sandbox_profile: str = ""             # "analysis" | "validator" | "local-unsandboxed"
    sandbox_ok: bool = False              # True iff run under a real namespace sandbox
    error: str | None = None              # set (and sandbox_ok False) on a fail-closed backend error


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _run_capped(argv, *, stdin_data, timeout_s, cap_bytes, rlimits, cwd=None, env=None):
    """Run argv with a per-stream byte cap, wall timeout, RLIMIT, and process-group kill. Returns
    (exit_code, out_bytes, err_bytes, elapsed_ms, timed_out, output_limit_exceeded). Never raises for a
    child failure; only a genuine spawn error propagates to the caller."""
    import subprocess

    def _preexec():
        os.setsid()  # own session/process group -> killpg reaches the whole tree
        for k, v in (rlimits or {}).items():
            try:
                resource.setrlimit(k, v)
            except (ValueError, OSError):
                pass  # a ceiling the kernel/ns won't accept is skipped, not fatal

    t0 = time.monotonic()
    try:
        p = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=env, preexec_fn=_preexec,
        )
    except (FileNotFoundError, PermissionError, OSError) as e:
        # a missing tool (e.g. ltrace not installed) or an exec failure is a NORMAL non-fatal condition,
        # not an exception: return a structured 127 so the tool records it and the attempt continues.
        return 127, b"", f"exec failed: {e!r}".encode(), int((time.monotonic() - t0) * 1000), False, False
    try:
        pgid = os.getpgid(p.pid)   # preexec setsid() -> leader, pgid == pid; capture before it can exit
    except OSError:
        pgid = p.pid
    out, err = bytearray(), bytearray()
    over = {"o": False, "e": False}

    def _reader(stream, buf, key):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                remaining = cap_bytes - len(buf)
                if len(chunk) <= remaining:
                    buf.extend(chunk)
                    if len(buf) == cap_bytes:
                        # exactly at the cap: peek one more byte to tell EOF (not truncated) from more
                        extra = stream.read(1)
                        if extra:
                            over[key] = True
                        break
                else:
                    buf.extend(chunk[:remaining])   # a byte beyond the cap exists -> real overflow
                    over[key] = True
                    break
        except (ValueError, OSError):
            pass

    def _writer():
        try:
            if stdin_data is not None and p.stdin:
                p.stdin.write(stdin_data)
                p.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    tw = threading.Thread(target=_writer)
    to = threading.Thread(target=_reader, args=(p.stdout, out, "o"))
    te = threading.Thread(target=_reader, args=(p.stderr, err, "e"))
    for th in (tw, to, te):
        th.start()

    timed_out = False
    deadline = t0 + timeout_s
    while True:
        if p.poll() is not None:
            break
        if over["o"] or over["e"]:
            break
        if time.monotonic() > deadline:
            timed_out = True
            break
        time.sleep(0.01)

    # ALWAYS kill the whole process group -- not only on timeout/cap. The main process may have exited
    # normally after spawning a BACKGROUND child that inherited our pipes; without this the child survives
    # the tool call and keeps the reader threads blocked. (Defense-in-depth over --unshare-pid /
    # --die-with-parent in the sandbox; the only reaper in the local backend.)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    if p.poll() is None:
        try:
            p.wait(timeout=2)
        except Exception:  # noqa: BLE001
            pass
    for stream in (p.stdout, p.stderr):
        try:
            stream.close()   # unblock any reader still waiting on a pipe held open by a killed child
        except (OSError, ValueError):
            pass
    for th in (tw, to, te):
        th.join(timeout=1)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return p.returncode, bytes(out), bytes(err), elapsed_ms, timed_out, (over["o"] or over["e"])


def _finish(req, exit_code, out_b, err_b, elapsed_ms, timed_out, over, *,
            profile_label, sandbox_ok, target_sha, scratch_host) -> ExecutionResult:
    """Common tail: decode with replace, hash raw bytes, read the trace file if any."""
    trace = None
    trace_sha, trace_trunc, trace_bytes = "", False, 0
    if req.trace_output_sandbox_path and scratch_host:
        # sandbox path /work/scratch/trace.log -> host <scratch>/trace.log
        rel = req.trace_output_sandbox_path.replace(SANDBOX_SCRATCH, "").lstrip("/")
        tp = Path(scratch_host) / rel
        if tp.exists():
            with open(tp, "rb") as fh:          # stream: read at most cap+1 bytes, never the whole file
                raw = fh.read(req.max_output_bytes)
                trace_trunc = bool(fh.read(1))  # a byte beyond the cap -> truncated
            trace = raw.decode("utf-8", "replace")
            trace_sha, trace_bytes = _sha_bytes(raw), len(raw)
    return ExecutionResult(
        exit_code=exit_code,
        stdout=out_b.decode("utf-8", "replace"),
        stderr=err_b.decode("utf-8", "replace"),
        stdout_sha256=_sha_bytes(out_b), stderr_sha256=_sha_bytes(err_b),
        trace_output=trace, trace_output_sha256=trace_sha,
        trace_output_truncated=trace_trunc, trace_output_bytes_captured=trace_bytes,
        elapsed_ms=elapsed_ms, timed_out=timed_out, output_limit_exceeded=over,
        truncated=(over or trace_trunc), target_sha256=target_sha,
        sandbox_profile=profile_label, sandbox_ok=sandbox_ok,
    )


def _subst(argv, target_path, scratch_path):
    return [tok.replace("{TARGET}", target_path or "").replace("{SCRATCH}", scratch_path or "")
            for tok in argv]


def _verify_target(req) -> tuple[str | None, str | None]:
    """Return (host_path_to_expose, sha) or (None, error)."""
    if not req.target_host_path:
        return None, None
    src = Path(req.target_host_path)
    if not src.exists():
        return None, f"target not found: {src}"
    sha = _sha_bytes(src.read_bytes())
    if req.expected_target_sha256 and sha != req.expected_target_sha256:
        return None, f"target integrity mismatch: expected {req.expected_target_sha256[:12]} got {sha[:12]}"
    return str(src), sha


# Deterministic threading: numpy/angr/z3 pull in OpenBLAS/OMP, which otherwise spawn N threads and emit
# startup chatter to stderr -- that can flood the output cap and perturb timing/reproducibility. Pin to 1.
_THREAD_ENV = {
    "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1", "BLIS_NUM_THREADS": "1", "VECLIB_MAXIMUM_THREADS": "1",
}


def bwrap_launch_env() -> dict:
    """Environment for the bwrap PROCESS ITSELF -- deliberately NOT the orchestrator's.

    bwrap stays alive as PID 1 inside the new PID namespace, so whatever it was launched with is
    readable at /proc/1/environ from inside the sandbox. `--clearenv` only scrubs the child bwrap
    execs, NOT bwrap's own environ -- so inheriting os.environ leaks ANTHROPIC_API_KEY (and the
    isolation canary) to the agent's tools. Verified by isolation_selftest -> proc_env_secret.
    """
    return {"PATH": "/usr/bin:/bin:/usr/local/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def local_min_env(scratch=None) -> dict:
    """Minimal env for the (unsandboxed) local backend: no ANTHROPIC_API_KEY / host secret inherited.
    (The bwrap backend uses --clearenv + --setenv instead.)"""
    return {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(scratch or "/tmp"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", **_THREAD_ENV}


class ExecutionBackend(Protocol):
    def execute(self, request: ExecutionRequest) -> ExecutionResult: ...


class BwrapExecutionBackend:
    """Per-call bubblewrap sandbox. The ONLY backend valid for registered runs. Fail-closed."""

    def __init__(self, bwrap_path: str = "bwrap", require: bool = True):
        self.bwrap = shutil.which(bwrap_path) or (bwrap_path if Path(bwrap_path).exists() else None)
        if require and not self.bwrap:
            raise RuntimeError(
                "bubblewrap (bwrap) not found -- refusing to run unsandboxed. Install bwrap in the target "
                "image; do NOT fall back to a bare subprocess for registered runs.")

    def bwrap_version(self) -> str:
        import subprocess
        try:
            out = subprocess.run([self.bwrap or "bwrap", "--version"], capture_output=True,
                                 timeout=5, text=True)
            return (out.stdout or out.stderr or "").strip()
        except Exception as e:  # noqa: BLE001
            return f"unknown ({e!r})"

    def build_argv(self, req: ExecutionRequest, target_expose_path: str | None) -> list[str]:
        """Construct the strict bwrap argv. Separated out so tests can assert the policy without bwrap."""
        # EXPLICIT unshares -- NOT --unshare-all, which implies --unshare-user-try and can silently skip the
        # user namespace, breaking fail-closed isolation.
        # A validator call (run_binary / BinaryOracle) binds NO scratch, so /work/scratch does not exist
        # inside the sandbox. --chdir and HOME must point at a path that EXISTS or bwrap aborts before
        # exec: exit 1 with empty stdout -> adjudicate() sees no marker -> every verdict 'inconclusive'
        # (i.e. nothing is ever accepted, in any arm). /tmp is always mounted (tmpfs, size-capped).
        work_dir = SANDBOX_SCRATCH if req.scratch_host_path else "/tmp"
        a = [self.bwrap or "bwrap",
             "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts",
             "--unshare-cgroup-try",
             "--clearenv",
             "--setenv", "PATH", "/usr/bin:/bin",
             "--setenv", "HOME", work_dir,
             # /etc/passwd is deliberately NOT bound into the sandbox, so pwd.getpwuid() has no
             # database and getpass.getuser() raises KeyError -- which pyvex calls at IMPORT time
             # (pyvex/native.py:_parse_ffi_str), so `import angr` died. getuser() consults
             # LOGNAME/USER before the pwd lookup, so this fixes it without mounting host identity.
             "--setenv", "USER", "rerag", "--setenv", "LOGNAME", "rerag",
             "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8", "--setenv", "TERM", "dumb",
             "--new-session", "--die-with-parent", "--cap-drop", "ALL",
             "--proc", "/proc", "--dev", "/dev",
             "--size", str(64 * 1024 * 1024), "--tmpfs", "/tmp",   # angr/gdb/python tempfile need /tmp
             "--tmpfs", "/work"]
        for k, v in _THREAD_ENV.items():   # deterministic threading (OpenBLAS/OMP) inside the sandbox
            a += ["--setenv", k, v]
        for root in _RUNTIME_ROOTS:
            a += ["--ro-bind-try", root, root]
        if target_expose_path:
            a += ["--ro-bind", target_expose_path, SANDBOX_TARGET]   # read-only: scoring binary is immutable
        if req.scratch_host_path:
            a += ["--bind", req.scratch_host_path, SANDBOX_SCRATCH]  # rw scratch (no repo/secrets bound)
        a += ["--chdir", work_dir, "--"]
        a += _subst(req.argv, SANDBOX_TARGET, SANDBOX_SCRATCH)
        return a

    def execute(self, req: ExecutionRequest) -> ExecutionResult:
        label = req.profile
        rl = req.rlimits or (VALIDATOR_RLIMITS if req.profile == "validator" else ANALYSIS_RLIMITS)
        fresh = None
        try:
            expose, sha_or_err = _verify_target(req)
            if req.target_host_path and expose is None:
                return ExecutionResult(sandbox_profile=label, sandbox_ok=False, error=sha_or_err)
            target_sha = sha_or_err if req.target_host_path else None  # sha on success
            if req.target_host_path and req.profile == "validator":
                # validator: expose a FRESH copy per call (no shared mutable path -> no TOCTOU)
                fd, fresh = tempfile.mkstemp(prefix="rerag_exec_")
                os.close(fd)
                shutil.copyfile(expose, fresh)
                os.chmod(fresh, 0o500)
                expose = fresh
            elif req.target_host_path and req.profile == "analysis":
                # ANALYSIS: expose a NON-EXECUTABLE copy (0400). The agent's tools may READ the target
                # (strings/nm/objdump/readelf/file, r2 and gdb disassembly, python3+capstone/angr) but
                # the copy itself cannot be exec'd: `./target`, `ld-linux ./target`, and a subprocess
                # of the file as-is all fail with EACCES.
                #
                # SCOPE OF THIS GUARD -- do not overstate it. The 0400 bit closes the DIRECT execution
                # routes only. It does NOT make execution impossible: the whitelisted `python3 -c`
                # family is a general interpreter, so an agent can copy this read-only file to a fresh
                # path, chmod +x the copy, and run that -- a working oracle -- and memfd_create+fexecve
                # is a second route that never touches disk. Both are demonstrated in
                # agent/test_execution_adversarial.py. Dropping run_binary from the tool surface plus
                # this bit removes the FREE/obvious oracle and is what the 120 A0 runs relied on; the
                # traces show no bypass, so the defensible claim is "no bypass was OBSERVED", never
                # "the agent could not execute the target". A capability guarantee needs a real sandbox
                # (bwrap with exec disabled, seccomp on execve to non-allowlisted paths, or a
                # ro+noexec mount) validated by that adversarial suite -- see W10e CHANGES.
                #
                # The oracle keeps its own executable copy via the validator profile -- scoring is done
                # by the harness, not by the agent.
                fd, fresh = tempfile.mkstemp(prefix="rerag_ro_")
                os.close(fd)
                shutil.copyfile(expose, fresh)
                os.chmod(fresh, 0o400)
                expose = fresh
            argv = self.build_argv(req, expose)
            rc, ob, eb, ms, to, over = _run_capped(
                argv, stdin_data=req.stdin_data, timeout_s=req.timeout_s,
                cap_bytes=req.max_output_bytes, rlimits=rl, env=bwrap_launch_env())
            return _finish(req, rc, ob, eb, ms, to, over, profile_label=label, sandbox_ok=True,
                           target_sha=target_sha, scratch_host=req.scratch_host_path)
        except Exception as e:  # noqa: BLE001 -- fail closed, never fall back to a bare subprocess
            return ExecutionResult(sandbox_profile=label, sandbox_ok=False, error=f"bwrap execution error: {e!r}")
        finally:
            if fresh:
                try:
                    os.unlink(fresh)
                except OSError:
                    pass


class LocalExecutionBackend:
    """Same mechanics WITHOUT namespaces. Explicit opt-in only (tests / exploratory) -- NEVER a registered
    backend and NEVER selected automatically. Marks results sandbox_ok=False so provenance is honest."""

    def __init__(self, allow_unsandboxed: bool = False):
        if not allow_unsandboxed:
            raise RuntimeError("LocalExecutionBackend requires allow_unsandboxed=True (no isolation).")

    def execute(self, req: ExecutionRequest) -> ExecutionResult:
        rl = req.rlimits or (VALIDATOR_RLIMITS if req.profile == "validator" else ANALYSIS_RLIMITS)
        # RLIMIT_NPROC is per-UID system-wide; unsandboxed (no user ns) it would affect the whole host,
        # so drop it here. It IS applied in the bwrap backend, where it is scoped to the sandbox ns.
        rl = {k: v for k, v in rl.items() if k != resource.RLIMIT_NPROC}
        fresh = None
        try:
            expose, err = _verify_target(req)
            if req.target_host_path and expose is None:
                return ExecutionResult(sandbox_profile="local-unsandboxed", sandbox_ok=False, error=err)
            target_sha = None
            if req.target_host_path:
                target_sha = _sha_bytes(Path(expose).read_bytes())
                fd, fresh = tempfile.mkstemp(prefix="rerag_local_")
                os.close(fd)
                shutil.copyfile(expose, fresh)
                os.chmod(fresh, 0o500)
                expose = fresh
            argv = _subst(req.argv, expose or "", req.scratch_host_path or "")
            rc, ob, eb, ms, to, over = _run_capped(
                argv, stdin_data=req.stdin_data, timeout_s=req.timeout_s,
                cap_bytes=req.max_output_bytes, rlimits=rl, cwd=req.scratch_host_path,
                env=local_min_env(req.scratch_host_path))
            res = _finish(req, rc, ob, eb, ms, to, over, profile_label="local-unsandboxed",
                          sandbox_ok=False, target_sha=target_sha, scratch_host=req.scratch_host_path)
            return res
        finally:
            if fresh:
                try:
                    os.unlink(fresh)
                except OSError:
                    pass
