"""Submission gate (A2 only) -- the derivation controller.

The agent has NO way to execute the target: the tool surface offers static analysis only, and the
target is exposed non-executable, so there is no free oracle to consult. Submission is one-shot.

The gate therefore cannot ask "did the binary accept this?" -- nobody can, until the harness scores
the run afterwards. It asks the question the original design was built around instead:

    WHERE DID THIS CANDIDATE COME FROM?

Two requirements, both structural, neither needing ground truth:

  1. DERIVATION  -- the candidate must not occur verbatim in the artifact. A value read out of the
                    file was not reconstructed from what the program computes. (agent/provenance.py)
  2. LEDGER      -- a well-formed record_validation must name this exact candidate and cite the
                    analysis step that produced it, recorded BEFORE the validation itself.

This is the maths-teacher check: a correct answer with no working is sent back, and working that
leads to a wrong answer passes. The gate is therefore NOT an oracle in disguise -- it can be wrong in
both directions, which is what keeps the A2-vs-A1 contrast meaningful.

HISTORY: earlier revisions gated on acceptance linkage (a run_binary whose real verdict was
'accepted') plus an optional differential baseline. Both are gone with run_binary: over 36 pilot runs
the acceptance layer blocked nothing (the agent verified voluntarily, because verification was one
free call) and the differential fired 0/4 times (it triggered on the last hypothesis' card citation,
which had always drifted to the final mechanism by submit time). See CHANGES for the full rationale.

Every decision carries a structured audit. Predicates are PROVISIONAL; ratified at the pre-main lock.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agent.derivation_check import build_view, check_reachability, check_terminality
from agent.provenance import ArtifactIndex, classify_candidate
from agent.state import AgentState

_TRIGGERS = ("cited", "retrieved", "always")

_REASONS = {
    "ok": "",
    "empty_candidate": "empty candidate.",
    "lifted_candidate": (
        "no derivation is attached to this candidate: it came from material you read rather than from "
        "analysis of what the program does. Reconstruct the value from what the program COMPUTES -- "
        "invert the transform, solve the constraint, or emulate the checker -- and submit that result."),
    "no_validation_for_candidate": (
        "no ledger entry records how you established this candidate. record_validation naming this "
        "exact candidate, citing (source_step_idx) the analysis step that produced it."),
    "abstained_on_block_budget": (
        "you have now been asked the same question about this candidate several times and the "
        "objection still stands. The submission is not being accepted on the strength of repetition. "
        "Either produce evidence that answers the objection, or work on a different candidate."),
    "malformed_validation": (
        "your ledger entry for this candidate is not well formed: it needs a known action_type, this "
        "exact candidate, and a source_step_idx pointing at an EARLIER step. A forward reference or a "
        "missing citation does not count."),
    "no_consumer_observed": (
        "the routine your evidence rests on has no observed consumer: nothing in your analysis shows "
        "what calls it or what uses its result. A comparison that matches is not the decision that "
        "accepts. Trace the result forward to the branch that produces the accepting outcome, and cite "
        "that."),
    "guard_not_accounted_for": (
        "the code your evidence rests on sits below a conditional you have not accounted for. A branch "
        "is evidence only if it can execute. State what the controlling condition tests and why some "
        "input satisfies it, then cite that step."),
}


@dataclass
class ScaffoldDecision:
    allowed: bool
    reason: str = ""
    audit: dict = field(default_factory=dict)


class Scaffold:
    def validate(self, state: AgentState, candidate: str) -> ScaffoldDecision:  # noqa: ARG002
        raise NotImplementedError("Use LedgerScaffold (A2); A0/A1 run with scaffold=None.")


@dataclass
class LedgerScaffold(Scaffold):
    """A2 submission gate (provisional). See module docstring."""

    # Retained for provenance/compat: recorded in the audit, no longer used to gate. The differential
    # mechanism died with run_binary -- there is no rejected baseline to contrast against when the
    # agent cannot execute anything.
    strictness: int = 2
    differential_trigger: str = "cited"
    cards: dict = field(default_factory=dict)

    artifact: ArtifactIndex | None = None   # None -> derivation layer inert (fail-open, audited)
    require_derivation: bool = True         # ablation switch
    require_ledger: bool = True             # ablation switch
    # Levels 1 and 2 (agent/derivation_check.py). DEFAULT OFF: switching them on changes the A2
    # treatment and is a lock-level decision, not a code default. Both are audited either way --
    # with the layer off, the verdict is still computed and recorded as 'shadow', so a run can be
    # scored for what the layer WOULD have done without the layer being in force.
    require_terminality: bool = False       # level 1: cited routine must have an observed consumer
    require_reachability: bool = False      # level 2: guard above the cited site must be accounted for
    shadow_levels: bool = True              # compute + record level verdicts even when not enforced
    # Block budget. A gate that repeats the same objection without the agent being able to satisfy
    # it is not asking for evidence, it is a dead end: in the W10f pilot one run was blocked SEVEN
    # times on the same code, burned 30 of its 40 steps and ~686k tokens re-arguing a case it had
    # already made correctly, and terminated with no submission at all. After this many blocks with
    # the SAME reason code for the SAME candidate, the proposal is allowed through and the audit
    # records that it was allowed on budget rather than on merit -- so the run yields a scored
    # outcome AND the fact that the gate could not be satisfied is preserved for analysis.
    max_blocks_per_reason: int = 3

    def __post_init__(self):
        if self.differential_trigger not in _TRIGGERS:
            raise ValueError(f"differential_trigger must be one of {_TRIGGERS}, got {self.differential_trigger!r}")

    def validate(self, state: AgentState, candidate: str) -> ScaffoldDecision:
        cand = candidate or ""   # exact: the candidate is the experimental object, no normalization
        prov = classify_candidate(cand, self.artifact, state)

        def decide(allowed, code, v=None, levels=None):
            return self._decision(allowed, code, prov, v, levels)

        if cand == "":
            return decide(False, "empty_candidate")

        # 1. DERIVATION. Checked first and independently of anything else: a value read out of the
        #    artifact is sent back even if it happens to be correct.
        if self.require_derivation and prov.provenance == "lifted":
            return decide(False, "lifted_candidate")

        # 2. LEDGER. Some well-formed entry must record how the candidate was established. We accept
        #    ANY complete entry rather than the first one, because an append-only ledger has to let the
        #    agent repair an incomplete citation and resubmit.
        if self.require_ledger:
            mine = [v for v in state.validation_ledger if (v.candidate or "") == cand]
            if not mine:
                return decide(False, "no_validation_for_candidate")
            well_formed = [v for v in mine if self._well_formed(state, v)]
            if not well_formed:
                return decide(False, "malformed_validation")
            # Evaluate the agent's LATEST evidence, then fall back through earlier entries. Taking
            # the FIRST well-formed entry (the original `next(...)`) was harmless while the gate only
            # checked well-formedness -- that property never changes once written. It became a defect
            # the moment the semantic levels were enforced: after a block the agent writes new,
            # richer validations (observed in 16/16 blocked runs, 2-3 new entries each) and the gate
            # re-judged the same impoverished first entry every time. 78% of the blocks in the
            # recorded battery were an artefact of this, and identical correct proofs were allowed or
            # blocked depending only on whether the first attempt happened to suffice.
            good = max(well_formed, key=lambda v: getattr(v, "step_idx", 0))
            lv = self._levels(state, good)
            if any(lv.get(c + "_enforced") for c in ("no_consumer_observed", "guard_not_accounted_for")):
                for alt in sorted(well_formed, key=lambda v: getattr(v, "step_idx", 0), reverse=True):
                    alt_lv = self._levels(state, alt)
                    if not any(alt_lv.get(c + "_enforced")
                               for c in ("no_consumer_observed", "guard_not_accounted_for")):
                        good, lv = alt, alt_lv
                        break
            for code in ("no_consumer_observed", "guard_not_accounted_for"):
                if lv.get(code + "_enforced"):
                    if self._blocks_so_far(state, cand, code) >= self.max_blocks_per_reason:
                        lv = dict(lv)
                        lv["budget_exhausted"] = {"reason_code": code,
                                                  "prior_blocks": self._blocks_so_far(state, cand, code),
                                                  "limit": self.max_blocks_per_reason}
                        # ABSTAIN, never fail open. Admitting a proposal "because the budget ran
                        # out" lets through a candidate whose stated objection is still unmet -- in
                        # the recorded battery it admitted one the scorer then rejected, i.e. the
                        # gate produced the exact error it exists to prevent.
                        return decide(False, "abstained_on_block_budget", good, lv)
                    return decide(False, code, good, lv)
            return decide(True, "ok", good, lv)

        return decide(True, "ok")

    # --- evidence predicates ---
    @staticmethod
    def _step(state: AgentState, idx):
        return next((s for s in state.steps if s.step_idx == idx), None)

    def _well_formed(self, state: AgentState, v) -> bool:
        """Structurally complete AND citing a real, EARLIER step. No claim about correctness is made
        here -- the gate never learns whether the derivation was sound, only whether one is shown."""
        if not getattr(v, "qualifies", False):
            return False
        if v.source_step_idx is None or v.source_step_idx >= v.step_idx:   # no forward reference
            return False
        return self._step(state, v.source_step_idx) is not None

    # --- block budget ---
    @staticmethod
    def _blocks_so_far(state: AgentState, candidate: str, reason_code: str) -> int:
        """How many times THIS candidate was already blocked for THIS reason."""
        n = 0
        for b in getattr(state, "blocked_submissions", []) or []:
            if (getattr(b, "value", None) or "") != candidate:
                continue
            if ((getattr(b, "audit", None) or {}).get("reason_code")) == reason_code:
                n += 1
        return n

    # --- levels 1 and 2 ---
    def _levels(self, state, v) -> dict:
        """Compute the level verdicts. Recorded always (shadow); enforced only if switched on."""
        if not (self.require_terminality or self.require_reachability or self.shadow_levels):
            return {}
        view = build_view(state, before_step=getattr(v, "step_idx", None))
        t = check_terminality(state, v, view)
        r = check_reachability(state, v, view)
        return {
            "terminality": {"ok": t.ok, "code": t.code, "detail": t.detail,
                            "enforced": bool(self.require_terminality)},
            "reachability": {"ok": r.ok, "code": r.code, "detail": r.detail,
                             "enforced": bool(self.require_reachability)},
            "no_consumer_observed_enforced": bool(self.require_terminality) and not t.ok,
            "guard_not_accounted_for_enforced": bool(self.require_reachability) and not r.ok,
        }

    # --- decision + audit ---
    def _decision(self, allowed, code, prov, v, levels=None):
        audit = {
            "allowed": allowed,
            "gate_version": "derivation-v5",
            "reason_code": code,
            "provenance_layer_active": bool(self.require_derivation and self.artifact is not None),
            "provenance": (prov.to_dict() if prov is not None else None),
            "ledger_layer_active": bool(self.require_ledger),
            "citing_validation_step_idx": (v.step_idx if v is not None else None),
            "cited_source_step_idx": (v.source_step_idx if v is not None else None),
            # recorded for continuity with pre-v2 traces; no longer gating
            "strictness": self.strictness,
            "differential_required": False,
            "differential_trigger_requested": self.differential_trigger,
            "levels": {k: val for k, val in (levels or {}).items() if not k.endswith("_enforced")},
            "max_blocks_per_reason": self.max_blocks_per_reason,
        }
        reason = "" if allowed else "submit blocked: " + _REASONS.get(code, code)
        return ScaffoldDecision(allowed, reason, audit)
