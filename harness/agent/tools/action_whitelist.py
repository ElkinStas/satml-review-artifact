"""Validation-action whitelist + the record_validation tool.

record_validation appends an evidence-ledger entry (the agent's explicit commitment that a
candidate was tested). It is common substrate (all arms). It NO LONGER decides acceptance
from the agent's free text -- per review, qualification is structural only here, and the A2
scaffold derives real acceptance from the cited run_binary step's structured verdict.
"""
from __future__ import annotations

from enum import StrEnum

from agent.state import AgentState, Validation


class ValidationActionType(StrEnum):
    DYNAMIC_RUN_WITH_INPUT = "dynamic_run_with_input"
    GDB_BREAKPOINT_CHECK = "gdb_breakpoint_check"
    Z3_CONSTRAINT_SOLVE = "z3_constraint_solve"
    MANUAL_TRACE_THROUGH = "manual_trace_through"


def qualifies(v: Validation) -> bool:
    """Structural completeness only (no text heuristics): a known action type, a named
    candidate, and a cited source step. Whether the candidate is actually accepted is a
    matter for the binary's real verdict (checked by the A2 scaffold), not this flag."""
    return (v.action_type in set(ValidationActionType)
            and (v.candidate or "") != ""
            and v.source_step_idx is not None and v.source_step_idx >= 0)


def record_validation(
    state: AgentState,
    *,
    step_idx: int,
    action_type: str,
    source_observation: str,
    result: str,
    candidate: str = "",
    source_step_idx: int = -1,
    tool_name: str = "",
    verdict: str = "inconclusive",
    baseline_step_idx: int | None = None,
) -> Validation:
    v = Validation(
        step_idx=step_idx, action_type=action_type, source_observation=source_observation,
        result=result, candidate=candidate, source_step_idx=source_step_idx,
        tool_name=tool_name, verdict=verdict, baseline_step_idx=baseline_step_idx,
    )
    v.qualifies = qualifies(v)
    state.validation_ledger.append(v)
    return v
