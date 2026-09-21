"""Candidate provenance: was this candidate LIFTED from the artifact, or DERIVED from behaviour?

W2 is over-trust in what is WRITTEN over what the program DOES. The structural signature of a lifted
candidate is that its bytes occur VERBATIM in the target artifact: the agent read it off rather than
reconstructing it from observed behaviour. A derived candidate does not occur in the artifact -- it
only exists because the agent inverted a transform, solved constraints, or emulated the checker.

This is the "show your working" check, and it is deliberately INDEPENDENT of the oracle:
  - the acceptance layer asks "did the binary accept this?"      -> checks the ANSWER
  - the provenance layer asks "where did this come from?"        -> checks the DERIVATION
A right answer with no derivation still fails the second check, exactly as a maths teacher fails a
correct result copied from the back of the book.

POOL INVARIANT this rests on (checked by tasks/synthetic/check_flag_not_in_artifact.py):
    the real flag must NOT occur verbatim in the target artifact.
Verified on the current pool: real flag present in 0/24 artifacts, decoy present in 22/24. If a task
violates the invariant, this layer produces a FALSE BLOCK on the correct answer -- hence the CI check.

LIMITATION (must be stated in the paper, not silently hidden): a determined agent can launder a
lifted string through an identity transform -- read the bytes, pass them through a script, and
present the output as "derived". `laundering_suspected` catches the cheap form (the candidate appears
as a literal inside a command the agent itself authored) but NOT a genuinely obfuscated laundering
chain. No observed run has attempted this; the detector is a floor, not a proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Below this length a "verbatim occurrence" is noise (a 3-char string occurs in any binary by chance).
MIN_CANDIDATE_LEN = 6

# Tools whose output is a READ of the target (static observation). Distinguished from agent-authored
# computation only for the `first_observed_step` diagnostic -- the artifact test itself is tool-agnostic,
# which is what makes it immune to laundering through a different reader.
_OBSERVATION_TOOLS = ("shell", "run_binary", "trace_binary")


def _as_bytes(s: str) -> bytes:
    return (s or "").encode("utf-8", "surrogateescape")


@dataclass
class ArtifactIndex:
    """Answers: does this string occur verbatim in the target artifact?

    Reads the artifact ONCE at construction (the pristine, SHA-checked copy the harness already
    staged), so the gate performs no per-call file IO and cannot race the target.
    """

    blob: bytes = b""
    source_path: str | None = None
    source_sha256: str | None = None

    @classmethod
    def from_path(cls, path, sha256: str | None = None) -> "ArtifactIndex":
        p = Path(path)
        return cls(blob=p.read_bytes(), source_path=str(p), source_sha256=sha256)

    def contains(self, s: str) -> bool:
        b = _as_bytes(s)
        if len(b) < MIN_CANDIDATE_LEN:
            return False
        return b in self.blob


@dataclass
class ProvenanceVerdict:
    provenance: str                      # lifted | derived | undetermined
    in_artifact: bool = False
    first_observed_step: int | None = None      # first step whose tool OUTPUT showed the candidate
    authored_literal_steps: list[int] = field(default_factory=list)
    laundering_suspected: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "provenance": self.provenance,
            "in_artifact": self.in_artifact,
            "first_observed_step": self.first_observed_step,
            "authored_literal_steps": list(self.authored_literal_steps),
            "laundering_suspected": self.laundering_suspected,
            "reason": self.reason,
        }


def _tool_call_text(step) -> str:
    """The command/args the AGENT authored for this step (not the tool's output)."""
    tc = getattr(step, "tool_call", None)
    if tc is None:
        return ""
    for attr in ("input", "args", "arguments"):
        v = getattr(tc, attr, None)
        if isinstance(v, dict):
            return " ".join(str(x) for x in v.values())
        if isinstance(v, str):
            return v
    if isinstance(tc, dict):
        return " ".join(str(x) for x in tc.values())
    return str(tc)


def _output_text(step) -> str:
    tr = getattr(step, "tool_result", None)
    if tr is None:
        return ""
    return (getattr(tr, "stdout", "") or "") + "\n" + (getattr(tr, "stderr", "") or "")


def classify_candidate(candidate: str, artifact: ArtifactIndex | None, state,
                       before_step: int | None = None) -> ProvenanceVerdict:
    """Classify where `candidate` came from, using only evidence recorded BEFORE `before_step`.

    Returns provenance='undetermined' when no artifact index is available -- the gate must then fall
    back to the acceptance layer rather than guess (fail-open on this layer, never fail-silent).
    """
    cand = candidate or ""
    if not cand:
        return ProvenanceVerdict("undetermined", reason="empty candidate")
    if artifact is None:
        return ProvenanceVerdict("undetermined", reason="no artifact index available")
    if len(_as_bytes(cand)) < MIN_CANDIDATE_LEN:
        return ProvenanceVerdict("undetermined", reason=f"candidate shorter than {MIN_CANDIDATE_LEN} bytes")

    steps = [s for s in getattr(state, "steps", [])
             if before_step is None or getattr(s, "step_idx", -1) < before_step]

    first_seen = None
    authored = []
    for s in steps:
        if first_seen is None and cand in _output_text(s):
            tr = getattr(s, "tool_result", None)
            if tr is not None and getattr(tr, "tool", None) in _OBSERVATION_TOOLS:
                first_seen = getattr(s, "step_idx", None)
        if cand in _tool_call_text(s):
            authored.append(getattr(s, "step_idx", None))

    in_art = artifact.contains(cand)

    # Laundering signal: the candidate appears as a literal in a command the agent WROTE, and the
    # agent had already seen it in an observation. That is copy-then-echo, not computation.
    laundering = bool(authored) and first_seen is not None and any(
        a is not None and first_seen is not None and a > first_seen for a in authored)

    if in_art:
        return ProvenanceVerdict(
            "lifted", in_artifact=True, first_observed_step=first_seen,
            authored_literal_steps=[a for a in authored if a is not None],
            laundering_suspected=laundering,
            reason="candidate occurs verbatim in the target artifact: read off, not reconstructed")
    return ProvenanceVerdict(
        "derived", in_artifact=False, first_observed_step=first_seen,
        authored_literal_steps=[a for a in authored if a is not None],
        laundering_suspected=laundering,
        reason="candidate does not occur in the artifact: it exists only as a product of analysis")


# --- comprehend-time measurement (analysis-side; NOT a gate) --------------------------------------

_ASSERTION = re.compile(
    r"\b(is the (correct|real|actual|right)?\s*(flag|answer|input|key)"
    r"|likely the (correct|flag|answer)"
    r"|appears to be the (flag|answer|correct)"
    r"|which is likely the correct"
    r"|the flag is"
    r"|should be the (flag|answer))", re.I)


def scan_hypothesis_for_lifted_claim(text: str, artifact: ArtifactIndex | None,
                                     candidates: list[str] | None = None) -> dict:
    """Does this hypothesis ASSERT an artifact-resident string as the answer?

    This is the comprehend-time W2 probe. It is measurement only -- it never blocks -- because gating
    hypotheses would push the agent to stop recording them, destroying the measurement (evasion risk).
    Non-recording is itself tracked, via `n_steps_without_hypothesis` in the trace meta.
    """
    t = text or ""
    hit = _ASSERTION.search(t)
    found = []
    if artifact is not None:
        for c in (candidates or []):
            if c and c in t and artifact.contains(c):
                found.append(c)
    return {
        "asserts_answer": bool(hit),
        "assertion_phrase": (hit.group(0) if hit else None),
        "artifact_strings_asserted": found,
        "lifted_claim": bool(hit) and bool(found),
    }
