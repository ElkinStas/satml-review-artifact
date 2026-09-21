"""record_hypothesis tool -- COMMON SUBSTRATE (all arms A0/A1/A2).

Resolves a design contradiction found in the prompt stubs: system_a0 said
"tool-call only, no free text outside tool args", yet the retrieval query needs
{current_hypothesis} and A1 needs the agent to cite card_ids for the
card_citation_rate / card_ignored_rate metrics. With no free text, those have
nowhere to live.

Fix: the agent expresses hypotheses and card citations through this STRUCTURED
tool. It is in the common tool set, so A0/A1/A2 have identical tool surfaces --
the only arm differences remain retrieval (A1) and scaffold (A2). Parity preserved.
"""

from __future__ import annotations

from agent.state import AgentState, Hypothesis


def record_hypothesis(
    state: AgentState,
    *,
    step_idx: int,
    text: str,
    cites_card_ids: list[str] | None = None,
) -> Hypothesis:
    """Append a hypothesis to the ledger and return it (also recorded on the step).

    cites_card_ids is meaningful only for A1/A2; for A0 it is always empty because
    A0 receives no cards. card_citation_rate / card_ignored_rate are computed from
    this field against the step's retrieved_cards.
    """
    h = Hypothesis(
        step_idx=step_idx,
        text=text,
        cites_card_ids=list(cites_card_ids or []),
    )
    state.hypothesis_ledger.append(h)
    return h
