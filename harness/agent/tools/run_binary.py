"""run_binary: the ONLY auditable path that executes the target binary with a candidate.

Runs via the sandboxed ExecutionBackend (validator profile: a fresh, SHA-checked copy of the target,
no repo / secrets / network / pristine path). Captures the real exit code / stdout / stderr and
adjudicates a verdict from the binary's OBSERVABLE behaviour (success_marker -> accepted, fail_marker ->
rejected, else inconclusive). It deliberately does NOT know any known_flag -- matching a flag we already
hold is SCORING, which belongs to BinaryOracle, not to an observation tool. The verdict + the exact
candidate + method are written into the ToolResult, so the A2 scaffold trusts behaviour, not prose.
"""
from __future__ import annotations

from agent.adjudicate import adjudicate
from agent.execution import ExecutionRequest
from agent.state import ToolResult


class RunBinaryTool:
    def __init__(self, *, backend, binary_path, default_input_method="stdin", success_marker=None,
                 fail_marker=None, timeout_s=20, max_output_bytes=8_192, expected_sha256=None,
                 stdin_append_newline=True):
        self.backend = backend
        self.binary_path = str(binary_path)
        self.default_input_method = default_input_method
        self.success_marker = success_marker
        self.fail_marker = fail_marker
        self.timeout_s = timeout_s
        self.max_output_bytes = max_output_bytes
        self.expected_sha256 = expected_sha256          # integrity guard (checked inside the backend)
        self.stdin_append_newline = stdin_append_newline  # stdin framing (recorded in provenance)

    def _fail(self, step_idx, candidate, method, msg) -> ToolResult:
        return ToolResult(step_idx=step_idx, tool="run_binary", exit_code=-1, stdout="", stderr=msg,
                          stdout_sha256="", stderr_sha256="", truncated=False, elapsed_ms=0,
                          verdict="inconclusive", ran_candidate=candidate, input_method=method)

    def run(self, *, step_idx, candidate="", input_method=None) -> ToolResult:
        method = input_method or self.default_input_method
        if method not in ("stdin", "argv"):
            return self._fail(step_idx, candidate, method,
                              f"bad input_method {method!r} (expected 'stdin' or 'argv')")
        if method == "argv":
            argv, stdin_data = ["{TARGET}", candidate], None
        else:
            argv = ["{TARGET}"]
            stdin_data = (candidate + ("\n" if self.stdin_append_newline else "")).encode("utf-8", "surrogateescape")
        res = self.backend.execute(ExecutionRequest(
            argv=argv, profile="validator", stdin_data=stdin_data,
            target_host_path=self.binary_path, expected_target_sha256=self.expected_sha256,
            timeout_s=self.timeout_s, max_output_bytes=self.max_output_bytes))
        if res.error:  # integrity mismatch / spawn / sandbox failure -> NOT a real run
            return self._fail(step_idx, candidate, method, res.error)
        # OBSERVATION only: verdict from the binary's output, never from a held flag.
        verdict = adjudicate(exit_code=res.exit_code, stdout=res.stdout, stderr=res.stderr,
                             success_marker=self.success_marker, fail_marker=self.fail_marker,
                             known_flag=None, candidate=candidate)
        if res.timed_out:
            verdict = "inconclusive"  # a killed run can't claim the binary's behaviour
        return ToolResult(
            step_idx=step_idx, tool="run_binary", exit_code=res.exit_code,
            stdout=res.stdout, stderr=res.stderr,
            stdout_sha256=res.stdout_sha256, stderr_sha256=res.stderr_sha256,
            truncated=res.truncated, elapsed_ms=res.elapsed_ms,
            verdict=verdict, ran_candidate=candidate, input_method=method)
