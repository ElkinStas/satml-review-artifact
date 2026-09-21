"""submit_candidate tool + submission controller + ground-truth oracle.

The controller checks a candidate against the task's ground-truth oracle. For arm
A2 the candidate must first pass the scaffold seam (scaffold.py); a blocked
submission is recorded but does NOT count as an attempt, so A2 is never penalised
by the gate. success@k is computed over actual (non-blocked) attempts.

Oracles: BinaryOracle is the real ground-truth judge (runs the task binary and adjudicates
via agent/adjudicate.py); StubOracle is a fixed-value stub used only by smoke tests. The A2
scaffold (LedgerScaffold) is wired in run_pilot; A0/A1 run with scaffold=None.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent.scaffold import Scaffold
from agent.state import AgentState, BlockedSubmission, Submission


class Oracle(ABC):
    @abstractmethod
    def check(self, value: str) -> tuple[bool, str]:
        """Return (accepted, detail)."""


class StubOracle(Oracle):
    """Test stub: accepts one preset value. The real oracle is BinaryOracle (below)."""

    def __init__(self, accept_value: str | None = None) -> None:
        self.accept_value = accept_value

    def check(self, value: str) -> tuple[bool, str]:
        ok = self.accept_value is not None and value == self.accept_value
        return ok, "stub-oracle: exact-match" + ("" if ok else " (no match)")


class SubmissionController:
    """Routes a candidate through the optional A2 scaffold, then the oracle."""

    def __init__(self, oracle: Oracle, scaffold: Scaffold | None = None) -> None:
        self.oracle = oracle
        self.scaffold = scaffold  # None for A0/A1; LedgerScaffold for A2

    def submit(
        self, state: AgentState, *, value: str, step_idx: int
    ) -> Submission | BlockedSubmission:
        audit: dict = {}
        if self.scaffold is not None:  # A2 path -- the seam
            decision = self.scaffold.validate(state, value)
            audit = decision.audit
            if not decision.allowed:
                return BlockedSubmission(step_idx=step_idx, value=value,
                                         reason=decision.reason, audit=audit)
        accepted, detail = self.oracle.check(value)
        return Submission(step_idx=step_idx, value=value, accepted=accepted,
                          oracle_detail=detail, audit=audit)


# --- BinaryOracle: run the task binary with the candidate and adjudicate ---
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

from agent.adjudicate import adjudicate  # noqa: E402
from agent.tools.shell import scrubbed_env  # noqa: E402


class BinaryOracle(Oracle):
    """Adjudicate a candidate by running the real binary (final ground-truth judge).

    input_method: 'stdin' (candidate piped) or 'argv' (candidate as argv[1]).
    Adjudication is STRICT (shared with run_binary, see agent/adjudicate.py):
    known_flag -> exact-match; fail_marker present -> rejected; success_marker present ->
    accepted; otherwise INCONCLUSIVE. Absence of a failure is NOT success: without a
    success_marker or a known flag, a candidate can never be marked accepted (no false
    positives from crash/usage/help output). Runs from the binary's own directory.
    """

    def __init__(self, *, backend, binary_path, input_method="stdin", success_marker=None,
                 fail_marker=None, known_flag=None, timeout_s=20, expected_sha256=None,
                 stdin_append_newline=True):
        self.backend = backend
        self.binary_path = str(binary_path)
        self.input_method = input_method
        self.success_marker = success_marker
        self.fail_marker = fail_marker
        self.known_flag = known_flag
        self.timeout_s = timeout_s
        self.expected_sha256 = expected_sha256  # integrity guard (checked inside the backend)
        self.stdin_append_newline = stdin_append_newline  # stdin framing (must match run_binary)

    def check(self, value: str) -> tuple[bool, str]:
        from agent.execution import ExecutionRequest
        # ALWAYS run the binary and adjudicate its observable behaviour. The objective is to find an
        # input the binary ACCEPTS, not to match the author's exemplar -- so an alternative accepted
        # input (a tally collision, an FNV pre-image, ...) must score as solved. Runs via the validator
        # sandbox (fresh SHA-checked target copy per call).
        if self.input_method == "argv":
            argv, stdin_data = ["{TARGET}", value], None
        else:
            argv = ["{TARGET}"]
            stdin_data = (value + ("\n" if self.stdin_append_newline else "")).encode("utf-8", "surrogateescape")
        res = self.backend.execute(ExecutionRequest(
            argv=argv, profile="validator", stdin_data=stdin_data, target_host_path=self.binary_path,
            expected_target_sha256=self.expected_sha256, timeout_s=self.timeout_s))
        if res.error:
            return False, f"oracle: {res.error}"
        if res.timed_out:
            return False, "oracle: run timed out -- cannot score"
        verdict = adjudicate(exit_code=res.exit_code, stdout=res.stdout, stderr=res.stderr,
                             success_marker=self.success_marker, fail_marker=self.fail_marker,
                             known_flag=None, candidate=value)
        if verdict == "accepted":
            return True, "verdict=accepted (marker-adjudicated)"
        # Fallback ONLY for tasks with no measurable success signal (rejection-detectable only): match a
        # held known_flag exactly. Never overrides an observed acceptance; disabled if a success_marker exists.
        if self.success_marker is None and self.known_flag is not None:
            fb = adjudicate(exit_code=res.exit_code, stdout=res.stdout, stderr=res.stderr,
                            known_flag=self.known_flag, candidate=value)
            return fb == "accepted", f"verdict={fb} (known-flag fallback; no success_marker)"
        return False, f"verdict={verdict} (marker-adjudicated)"
