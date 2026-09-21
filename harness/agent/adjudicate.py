"""Shared, STRICT run-outcome adjudication.

run_binary and BinaryOracle share the same MARKER rules. BinaryOracle may ADDITIONALLY use a
known_flag as a FALLBACK only for tasks with no measurable success signal (see submit.py);
run_binary NEVER uses known_flag (it judges only observable behaviour).

Rules (strict by design):
  - known_flag set       -> accepted iff candidate == known_flag EXACTLY, else rejected.
                            No whitespace normalization: the candidate is the experimental object
                            and for argv " FLAG " != "FLAG".
  - fail_marker present   -> rejected, when it appears as an EXACT output line.
  - success_marker present-> accepted, when it appears as an EXACT output line AND exit_code == 0.
                            (line-exact + clean-exit guards against candidate echo, a marker that is
                            only a substring of another line, and "printed a success word then errored".)
  - otherwise            -> inconclusive  (absence of a failure is NOT success).
Marker matching is case-insensitive on the stripped line.
"""
from __future__ import annotations


def _output_lines(stdout, stderr) -> list[str]:
    joined = (stdout or "") + "\n" + (stderr or "")
    return [ln.strip().lower() for ln in joined.splitlines() if ln.strip()]


def adjudicate(*, exit_code, stdout, stderr, success_marker=None, fail_marker=None,
               known_flag=None, candidate="") -> str:
    if known_flag is not None:
        return "accepted" if candidate == known_flag else "rejected"
    lines = _output_lines(stdout, stderr)
    if fail_marker and fail_marker.strip().lower() in lines:
        return "rejected"
    if success_marker and exit_code == 0 and success_marker.strip().lower() in lines:
        return "accepted"
    return "inconclusive"
