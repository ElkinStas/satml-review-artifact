"""Tool execution wrapper -- safe shell wrappers around the RE toolchain.

Runs whitelisted command families inside the agent's Docker container
(--network=none, no internet during runs). Captures stdout/stderr/exit code as a
ToolResult, with a timeout, per-stream output truncation, and SHA-256 hashes of the
full (pre-truncation) output so a trace line uniquely identifies what the tool saw.

Whitelisting is at the command-family granularity. Interactive radare2 is disabled:
r2 is only invoked as `r2 -q -c '<cmd>'`. The agent never gets a raw shell.

Robustness: run() is TOTAL -- it always returns a ToolResult, never raises and never null.
Any failure (missing executable -> 127, timeout -> 124, ptrace denied / permission / OS error
launching the tool / non-UTF-8 output -> 125) becomes a nonzero-exit ToolResult with the error
in stderr, so one failed tool (e.g. strace in a container without SYS_PTRACE) never ends the
attempt. The full toolchain (radare2, gdb, strace, ltrace, angr) is present in the Docker image.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import time

from agent.state import ToolResult
from agent.execution import ExecutionRequest

# family -> argv builder. {target} = binary path, {cmd}/{code} = family-specific arg.
_FAMILIES: dict[str, list[str]] = {
    "file": ["file", "{TARGET}"],
    "strings": ["strings", "{TARGET}"],
    "readelf": ["readelf", "-a", "{TARGET}"],
    "objdump": ["objdump", "-d", "{TARGET}"],
    "nm": ["nm", "{TARGET}"],
    "r2": ["r2", "-q", "-c", "{cmd}", "{TARGET}"],  # interactive r2 disabled
    "gdb": ["gdb", "-batch", "-ex", "{cmd}", "{TARGET}"],
    # strace/ltrace intentionally absent -- dynamic tracing is the unified trace_binary tool.
    "python3": ["python3", "-c", "{code}"],  # scripted angr / capstone / z3 (runs INSIDE the sandbox)
}

SHELL_FAMILIES: frozenset[str] = frozenset(_FAMILIES)

# A tool subprocess gets a MINIMAL, scrubbed environment: no ANTHROPIC_API_KEY or any other host
# secret ever reaches agent-controlled code (python3 -c / gdb shell / r2 !). This is defense-in-depth
# on top of workspace staging; the real trust boundary is the tool sandbox container (no secrets, no
# network, only the scratch workspace mounted).
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def scrubbed_env(home=None) -> dict:
    """Minimal environment for ANY agent-triggered subprocess (shell tools AND run_binary/oracle):
    no ANTHROPIC_API_KEY or host secret ever reaches agent-controlled code or an executed target."""
    return {"PATH": SAFE_PATH, "HOME": str(home or os.environ.get("TMPDIR", "/tmp")),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb"}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()  # exact fingerprint of RAW tool output (pre-decode)


class ShellTool:
    """Whitelisted RE-tool families, executed through the ExecutionBackend (analysis profile).

    The agent calls a family (nm / strings / readelf / objdump / file / r2(cmd) / gdb(cmd) /
    python3(code)); the harness injects the target ({TARGET} -> /work/target, read-only) and a
    persistent-per-attempt scratch ({SCRATCH} -> /work/scratch, read-write). The model never supplies a
    target path. python3 runs INSIDE the sandbox, so scripted angr/z3 cannot read the repo/secrets or
    reach the network. run() is TOTAL -- always a ToolResult, never raises, never null.
    """

    def __init__(self, *, backend, target_host_path: str | None = None,
                 scratch_host_path: str | None = None, timeout_s: int = 30,
                 max_output_bytes: int = 8_192) -> None:
        self.backend = backend
        self.target_host_path = target_host_path      # bound ro at {TARGET}
        self.scratch_host_path = scratch_host_path    # bound rw at {SCRATCH} (writable workspace)
        self.timeout_s = timeout_s
        self.max_output_bytes = max_output_bytes

    def _err(self, step_idx: int, family: str, code: int, msg: str) -> ToolResult:
        return ToolResult(step_idx=step_idx, tool=family, exit_code=code, stdout="", stderr=msg,
                          stdout_sha256="", stderr_sha256="", truncated=False, elapsed_ms=0)

    def run(self, family: str, *, step_idx: int, target: str = "", cmd: str = "",
            code: str = "") -> ToolResult:
        # `target` is accepted for wire-compat and IGNORED -- the backend injects {TARGET}. (The final
        # tool schema drops it entirely, together with trace_binary.)
        if family not in _FAMILIES:
            return self._err(step_idx, family, 126, f"family not whitelisted: {family}")
        if family in ("r2", "gdb") and not cmd:
            return self._err(step_idx, family, 126, f"{family} requires a non-empty cmd")
        if family == "python3" and not code:
            return self._err(step_idx, family, 126, "python3 requires non-empty code")
        argv = [tok.replace("{cmd}", cmd).replace("{code}", code) for tok in _FAMILIES[family]]
        res = self.backend.execute(ExecutionRequest(
            argv=argv, profile="analysis", target_host_path=self.target_host_path,
            scratch_host_path=self.scratch_host_path, timeout_s=self.timeout_s,
            max_output_bytes=self.max_output_bytes))
        if res.error:  # sandbox / spawn failure -> a nonzero ToolResult, never raise
            return self._err(step_idx, family, 125, f"sandbox error: {res.error}")
        return ToolResult(
            step_idx=step_idx, tool=family, exit_code=res.exit_code,
            stdout=res.stdout, stderr=res.stderr,
            stdout_sha256=res.stdout_sha256, stderr_sha256=res.stderr_sha256,
            truncated=res.truncated, elapsed_ms=res.elapsed_ms)


def shlex_safe(s: str) -> str:
    """Helper for building r2/gdb command strings safely."""
    return shlex.quote(s)
