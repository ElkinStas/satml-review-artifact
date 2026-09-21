"""Structured observation state + trace schema. Shared across all three arms.

The "common substrate" guarantee: A0/A1/A2 see the same observation schema and the
same tool surface. Arm differences live in retrieval (A1+) and scaffold (A2 only),
never in state.

The trace (a list of StepRecord, persisted as JSONL) is load-bearing: W2 events must
be mechanically detectable from it (decoy_accepted, unverified_candidate_submission,
... -- see annotation/rubric.md). That is the whole reason W2 was chosen over W4.

Status: Track C foundation (Weeks 2-5). Schema is provisional until the pre-pilot
content review; serialization is implemented and exercised by agent/smoke_test.py.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path


class Arm(StrEnum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"


class TerminationReason(StrEnum):
    SOLVED = "solved"
    SUBMITTED_WRONG = "submitted_wrong"   # one-shot submission spent on a candidate the oracle rejected
    MAX_STEPS = "max_steps"
    MAX_TOKENS = "max_tokens"
    AGENT_QUIT = "agent_quit"
    ERROR = "error"


@dataclass
class TokenAccounting:
    """Per-step token counts, split by kind.

    Two roll-ups:
      processed_tokens -- ALL four kinds. Descriptive/logging only (kept for trace
                          continuity and cost analysis); NOT a stop condition.
      budget_tokens    -- uncached_input + cache_write + output. THIS is the budget
                          basis (MAX_TOKENS) and the MC3 check.

    Why cache_read is EXCLUDED from the budget (reversal of the earlier decision):
    with prompt caching the whole growing transcript is re-sent each step as
    cache_read, so cumulative cache_read grows ~quadratically in steps and dominates
    (~86% of processed tokens in the Jormugandr pilot). On `processed_tokens` the
    MAX_TOKENS cap therefore tripped at ~step 36 -- BEFORE max_steps=40 -- and tripped
    EARLIER for A2 than A0 (A2 carries more per-step context: retrieval + ledger), so
    the arms were not budget-matched and MC3 blew (80% token-exhaustion vs the <=15%
    threshold). budget_tokens counts only the per-step NEW work (input+write+output),
    which scales ~linearly, so max_steps binds and the arms are comparable. The earlier
    rationale ("the model still processes a cache_read token") is true but had the
    side effect of making the budget an integral of context length over steps.
    """

    uncached_input_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0

    @property
    def processed_tokens(self) -> int:
        """All token kinds. Descriptive/logging + cost analysis only -- NOT the budget."""
        return (
            self.uncached_input_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
            + self.output_tokens
        )

    @property
    def budget_tokens(self) -> int:
        """Budget basis (and MC3): per-step NEW work, cache_read EXCLUDED. See class docstring."""
        return self.uncached_input_tokens + self.cache_write_tokens + self.output_tokens

    def __add__(self, other: "TokenAccounting") -> "TokenAccounting":
        return TokenAccounting(
            self.uncached_input_tokens + other.uncached_input_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass
class ToolCall:
    step_idx: int
    tool: str
    args: dict


@dataclass
class ToolResult:
    step_idx: int
    tool: str
    exit_code: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    truncated: bool
    elapsed_ms: int
    verdict: str = ""          # run_binary only: accepted|rejected|inconclusive
    ran_candidate: str = ""    # run_binary / trace_binary: the exact candidate executed
    input_method: str = ""     # run_binary / trace_binary: stdin|argv
    tracer: str = ""           # trace_binary only: strace|ltrace
    trace_output: str = ""     # trace_binary only: the tracer's own output (separate from program stdout)
    trace_output_sha256: str = ""   # trace_binary only: SHA over the captured trace bytes
    trace_truncated: bool = False   # trace_binary only: the trace exceeded the cap
    trace_output_bytes_captured: int = 0   # trace_binary only: bytes of trace captured (<= cap)


@dataclass
class Card:
    """A Pattern-RAG card. Populated for A1/A2 only; the list is empty for A0."""

    card_id: str
    family: str
    title: str
    applicability_signal: str
    mechanism: str
    recommended_validation_actions: list[str] = field(default_factory=list)
    requires_differential: bool = False
    validation_note: str = ""
    retrieval_keywords: list[str] = field(default_factory=list)
    grounding: str = "well_grounded"
    # v2 (registered-library) advisory fields; empty for thin pilot-seed cards (backward-compatible)
    misleading_interpretation: str = ""
    better_interpretation: str = ""
    not_applicable_when: list[str] = field(default_factory=list)
    misfire_risks: list[str] = field(default_factory=list)
    minimum_evidence_before_use: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)


@dataclass
class Hypothesis:
    """Produced by the record_hypothesis tool (common substrate, all arms).

    This is how the agent thinks on the record: it resolves the contradiction
    between "tool-call only, no free text" and the need for a stated hypothesis
    (retrieval query) and card citations (card_citation_rate metric).
    """

    step_idx: int
    text: str
    cites_card_ids: list[str] = field(default_factory=list)


@dataclass
class Validation:
    """One evidence-ledger entry, produced by the record_validation tool.

    A0/A1: advisory -- drives the ledger_completeness_rate comparison.
    A2: the scaffold gates submit_candidate on a qualifying entry (scaffold.py).
    """

    step_idx: int
    action_type: str
    source_observation: str
    result: str
    candidate: str = ""               # the candidate this validation concerns
    source_step_idx: int = -1         # trace step whose tool_result is the evidence
    tool_name: str = ""               # tool that produced that evidence
    verdict: str = "inconclusive"     # accepted | rejected | inconclusive
    baseline_step_idx: int | None = None  # wrong-input baseline step (differential)
    qualifies: bool | None = None     # None until the whitelist predicate evaluates it


@dataclass
class Submission:
    step_idx: int
    value: str
    accepted: bool
    oracle_detail: str = ""
    audit: dict = field(default_factory=dict)  # A2 structured scaffold-gate audit


@dataclass
class BlockedSubmission:
    """A submission rejected by the A2 scaffold. Recorded but NOT counted as an attempt."""

    step_idx: int
    value: str
    reason: str
    audit: dict = field(default_factory=dict)  # A2 structured scaffold-gate audit


@dataclass
class RetrievalEvent:
    """The retrieval active when the agent acted THIS step (A1/A2 only). Set by the policy BEFORE
    dispatch, so the A2 scaffold can read state.active_retrieval even for a same-step submission."""

    hypothesis_step_idx: int = -1
    query: str = ""
    ranked_cards: list[dict] = field(default_factory=list)   # [{card_id, rank, score}] this step
    block_injected: bool = False                             # was the card block (re)injected this step
    active_card_ids: list[str] = field(default_factory=list)  # retrieved for the CURRENT hypothesis


@dataclass
class StepRecord:
    """One line of trace.jsonl. The unit of the trace schema."""

    step_idx: int
    tool_call: ToolCall
    tool_result: ToolResult | None = None
    hypotheses_added: list[Hypothesis] = field(default_factory=list)
    validations_added: list[Validation] = field(default_factory=list)
    submission: Submission | None = None
    blocked_submission: BlockedSubmission | None = None
    retrieved_cards: list[Card] = field(default_factory=list)  # A1/A2 only
    retrieval_event: "RetrievalEvent | None" = None            # A1/A2: query/rank/score/injected/active
    tokens: TokenAccounting = field(default_factory=TokenAccounting)

    def to_record_dict(self) -> dict:
        d = {"record_type": "step", **asdict(self)}
        d["tokens"]["processed_tokens"] = self.tokens.processed_tokens
        return d


@dataclass
class AgentState:
    """Full per-attempt state. One AgentState == one (task, arm, attempt) trace."""

    task_id: str
    attempt_id: str
    arm: Arm
    step_idx: int = 0
    steps: list[StepRecord] = field(default_factory=list)
    hypothesis_ledger: list[Hypothesis] = field(default_factory=list)
    validation_ledger: list[Validation] = field(default_factory=list)
    submissions: list[Submission] = field(default_factory=list)
    blocked_submissions: list[BlockedSubmission] = field(default_factory=list)
    tokens: TokenAccounting = field(default_factory=TokenAccounting)
    terminated: bool = False
    termination_reason: TerminationReason | None = None
    termination_detail: str = ""
    run_meta: dict = field(default_factory=dict)  # #13: frozen-config provenance (set by run_pilot)
    active_retrieval: "RetrievalEvent | None" = None  # set by the policy pre-dispatch (A1/A2)

    def record_step(self, step: StepRecord) -> None:
        """Append a completed step and roll up its token usage."""
        self.steps.append(step)
        self.tokens = self.tokens + step.tokens

    def latest_hypothesis(self) -> Hypothesis | None:
        return self.hypothesis_ledger[-1] if self.hypothesis_ledger else None

    def has_qualifying_validation(self) -> bool:
        """Used by the A2 scaffold seam (submit gating)."""
        return any(v.qualifies for v in self.validation_ledger)

    def meta_dict(self) -> dict:
        return {
            "record_type": "meta",
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "arm": self.arm,
            "n_steps": len(self.steps),
            "terminated": self.terminated,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "processed_tokens_total": self.tokens.processed_tokens,
            "budget_tokens_total": self.tokens.budget_tokens,
            "tokens_total": asdict(self.tokens),
            "n_submissions": len(self.submissions),
            "n_blocked_submissions": len(self.blocked_submissions),
            **self.run_meta,
        }

    def persist(self, trace_path: Path | str) -> Path:
        """Write trace.jsonl: one meta line, then one line per step."""
        trace_path = Path(trace_path)
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        with trace_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(self.meta_dict()) + "\n")
            for step in self.steps:
                f.write(json.dumps(step.to_record_dict()) + "\n")
        return trace_path
