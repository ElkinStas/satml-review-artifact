"""trace_binary: run the target under strace/ltrace with a candidate, in the validator sandbox.

Same input framing as run_binary (stdin/argv + stdin_append_newline) on a FRESH SHA-checked copy of the
target, but the tracer's own output goes to a separate file (`-o {SCRATCH}/trace.log`) so it never mixes
with the program's stdout/stderr. The result is DIAGNOSTIC only: trace_binary is deliberately tool
"trace_binary", never "run_binary", so the A2 scaffold never treats a trace as an acceptance signal.

A missing tracer (ltrace not installed) or a statically-linked target that a tracer can't follow is a
structured, non-fatal result (nonzero exit + the tracer's message in stderr), never a raised exception.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agent.execution import ExecutionRequest
from agent.state import ToolResult

_TRACERS = ("strace", "ltrace")
_TRACE_LOG = "{SCRATCH}/trace.log"


class TraceBinaryTool:
    def __init__(self, *, backend, binary_path, default_input_method="stdin", timeout_s=30,
                 max_output_bytes=8_192, expected_sha256=None, stdin_append_newline=True):
        self.backend = backend
        self.binary_path = str(binary_path)
        self.default_input_method = default_input_method
        self.timeout_s = timeout_s
        self.max_output_bytes = max_output_bytes
        self.expected_sha256 = expected_sha256
        self.stdin_append_newline = stdin_append_newline

    def _err(self, step_idx, tracer, candidate, method, msg) -> ToolResult:
        return ToolResult(step_idx=step_idx, tool="trace_binary", exit_code=-1, stdout="", stderr=msg,
                          stdout_sha256="", stderr_sha256="", truncated=False, elapsed_ms=0,
                          verdict="inconclusive", ran_candidate=candidate, input_method=method, tracer=tracer)

    def run(self, *, step_idx, tracer, candidate="", input_method=None) -> ToolResult:
        if tracer not in _TRACERS:
            return self._err(step_idx, tracer, candidate, input_method or self.default_input_method,
                             f"unknown tracer {tracer!r} (expected 'strace' or 'ltrace')")
        method = input_method or self.default_input_method
        if method not in ("stdin", "argv"):
            return self._err(step_idx, tracer, candidate, method,
                             f"bad input_method {method!r} (expected 'stdin' or 'argv')")

        base = (["strace", "-f", "-o", _TRACE_LOG, "{TARGET}"] if tracer == "strace"
                else ["ltrace", "-o", _TRACE_LOG, "{TARGET}"])
        if method == "argv":
            argv, stdin_data = base + [candidate], None
        else:
            argv = base
            stdin_data = (candidate + ("\n" if self.stdin_append_newline else "")).encode("utf-8", "surrogateescape")

        scratch = tempfile.mkdtemp(prefix="rerag_trace_")  # ephemeral (validator): holds only trace.log
        try:
            res = self.backend.execute(ExecutionRequest(
                argv=argv, profile="validator", stdin_data=stdin_data,
                target_host_path=self.binary_path, expected_target_sha256=self.expected_sha256,
                scratch_host_path=scratch, timeout_s=self.timeout_s,
                max_output_bytes=self.max_output_bytes,
                trace_output_sandbox_path=_TRACE_LOG.replace("{SCRATCH}", "/work/scratch")))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

        if res.error:  # integrity / spawn failure -> structured, non-fatal
            return self._err(step_idx, tracer, candidate, method, f"trace_binary: {res.error}")
        return ToolResult(
            step_idx=step_idx, tool="trace_binary", exit_code=res.exit_code,
            stdout=res.stdout, stderr=res.stderr,                 # the PROGRAM's stdout/stderr
            stdout_sha256=res.stdout_sha256, stderr_sha256=res.stderr_sha256,
            truncated=res.truncated, elapsed_ms=res.elapsed_ms,
            verdict="inconclusive",                               # NEVER an acceptance signal
            ran_candidate=candidate, input_method=method, tracer=tracer,
            trace_output=(res.trace_output or ""),                 # the TRACER's output, kept separate
            trace_output_sha256=res.trace_output_sha256, trace_truncated=res.trace_output_truncated,
            trace_output_bytes_captured=res.trace_output_bytes_captured)
