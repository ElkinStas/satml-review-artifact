"""System-prompt assembly: common base + arm deltas.

The prompt stubs shipped as three monolithic files (system_a0/a1/a2.txt), each
described as "identical to the previous except ...". That structure is replaced
here by one common base plus two deltas:

    A0 = common
    A1 = common + delta_a1
    A2 = common + delta_a1 + delta_a2

Two reasons, and the first matters more than caching:

  1. Parity by construction. The prereg requires A0/A1/A2 to differ ONLY by the
     intended informational delta (cards for A1, scaffold notice for A2). Three
     hand-maintained files drift -- a typo fixed in A0 but not A1 becomes an
     uncontrolled between-arm difference. A shared base cannot drift.
  2. Prompt caching. The common base (plus the static tool specs) is a
     byte-identical prefix across all arms and all runs -- the ideal place for a
     cache_control breakpoint. See agent/prompts/README.md for breakpoint
     placement; processed_tokens is logged for cost analysis while stopping uses
     budget_tokens (cache_read excluded), so caching is cost-only (see TokenAccounting
     in state.py).
"""

from __future__ import annotations

from pathlib import Path

from agent.state import Arm

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def _read(name: str, prompts_dir: Path) -> str:
    return (prompts_dir / name).read_text(encoding="utf-8").rstrip() + "\n"


def scaffold_mode_note(strictness: int, differential_trigger: str) -> str:  # noqa: ARG001
    """A2-only note stating the ACTIVE submission-gate rules, so the model is never told one rule while
    the run enforces another. Neutral about mechanisms; enters the prompt hash.

    The parameters are retained for signature/compat and are recorded in the audit, but no longer
    select a rule: the acceptance and differential layers died with run_binary (nothing can be executed,
    so there is no accepting run and no rejected baseline to contrast against).
    """
    return (
        "[Submission gate -- active configuration for this run]\n"
        "Your submission passes through a fixed gate that reads your DERIVATION, not your prose. It "
        "accepts a candidate only when the value was RECONSTRUCTED from what the program computes, and "
        "your evidence ledger records, for the EXACT candidate you submit, the earlier analysis step "
        "that produced it. A string you found written somewhere never counts, however plausible.\n"
        "The gate does not know whether your answer is correct, and will not tell you.\n"
    )


def assemble_system_prompt(arm: Arm, prompts_dir: Path | str | None = None,
                           scaffold_strictness: int | None = None,
                           differential_trigger: str | None = None) -> str:
    """Return the full system prompt for `arm`, assembled from base + deltas.

    By construction the A0 prompt is a prefix of A1, and A1 a prefix of A2 --
    agent/smoke_test.py asserts exactly this as the parity check. The A2 scaffold-mode note is appended
    AFTER delta_a2, so the prefix property is preserved.
    """
    pd = Path(prompts_dir) if prompts_dir is not None else _PROMPTS_DIR
    text = _read("system_common.txt", pd)
    if arm in (Arm.A1, Arm.A2):
        text += "\n" + _read("delta_a1.txt", pd)
    if arm == Arm.A2:
        text += "\n" + _read("delta_a2.txt", pd)
        s = 2 if scaffold_strictness is None else scaffold_strictness   # registered default 2/cited
        t = "cited" if differential_trigger is None else differential_trigger
        text += "\n" + scaffold_mode_note(s, t)
    return text
