"""Tool-call API: the registry of tools the agent can invoke, plus dispatch.

Invariants: (1) the tool SURFACE is identical across A0/A1/A2 -- arm differences are
retrieval (A1) and the submit scaffold (A2), never an extra tool; (2) llm_tool_specs is
STATIC and belongs in the cached prompt prefix. run_binary is common substrate (all arms);
it is the audited execution path the A2 scaffold keys on.
"""
from __future__ import annotations

from agent.state import AgentState, StepRecord, Submission, ToolCall
from agent.submit import SubmissionController
from agent.tools.action_whitelist import ValidationActionType, record_validation
from agent.tools.note import record_hypothesis
from agent.tools.shell import SHELL_FAMILIES, ShellTool

_AGENT_TOOLS = ("record_hypothesis", "record_validation", "submit_candidate", "quit")


def llm_tool_specs() -> list[dict]:
    """Static tool schemas sent to the model. Cache these (see prompting.py)."""
    specs: list[dict] = [
        {
            "name": fam,
            "kind": "shell",
            "description": f"Run `{fam}` on the target binary (supplied by the harness; you pass no "
                           f"path). In r2/gdb cmd and python3 code, refer to the binary as {{TARGET}}.",
            "input": {"cmd": "str (r2/gdb only)", "code": "str (python3 only)"},
        }
        for fam in sorted(SHELL_FAMILIES)
    ]
    specs += [
        {
            "name": "record_hypothesis",
            "kind": "agent",
            "description": "Record your current hypothesis about the binary. "
                           "Optionally cite pattern-card ids you are acting on.",
            "input": {"text": "str", "cites_card_ids": "list[str] (optional)"},
        },
        {
            "name": "record_validation",
            "kind": "agent",
            "description": "Record an evidence-ledger entry: how you established this candidate. "
                           "Cite the analysis step that produced it.",
            "input": {
                "action_type": f"one of {[a.value for a in ValidationActionType]}",
                "candidate": "str (the exact candidate this validation concerns)",
                "source_step_idx": "int (the step whose OUTPUT is your evidence)",
                "tool_name": "str (tool that produced that output)",
                "source_observation": "str",
                "result": "str (the observed output / detail)",
                "verdict": "your reading of that evidence: accepted | rejected | inconclusive",
            },
        },
        {
            "name": "submit_candidate",
            "kind": "agent",
            "description": "Submit a candidate answer to the submission controller.",
            "input": {"value": "str"},
        },
        {"name": "quit", "kind": "agent", "description": "End the attempt.", "input": {}},
    ]
    return specs


class ToolRegistry:
    """Dispatches a ToolCall to its executor and folds the outcome into a StepRecord."""

    def __init__(self, shell: ShellTool, controller: SubmissionController, runner=None, tracer=None) -> None:
        self.shell = shell
        self.controller = controller
        self.runner = runner  # RunBinaryTool; required for run_binary calls
        self.tracer = tracer  # TraceBinaryTool; required for trace_binary calls

    def tool_names(self) -> list[str]:
        # run_binary / trace_binary are NOT offered: executing the target is what made the
        # oracle free. Static analysis remains fully available.
        return sorted(SHELL_FAMILIES) + list(_AGENT_TOOLS)

    def dispatch(self, call: ToolCall, state: AgentState, step: StepRecord) -> None:
        name, args, idx = call.tool, call.args, call.step_idx

        if name in SHELL_FAMILIES:
            step.tool_result = self.shell.run(name, step_idx=idx, **args)
            return

        if name == "record_hypothesis":
            step.hypotheses_added.append(record_hypothesis(state, step_idx=idx, **args))
            return

        if name == "record_validation":
            step.validations_added.append(record_validation(state, step_idx=idx, **args))
            return

        if name == "submit_candidate":
            outcome = self.controller.submit(state, value=args["value"], step_idx=idx)
            if isinstance(outcome, Submission):
                step.submission = outcome
                state.submissions.append(outcome)
            else:
                step.blocked_submission = outcome
                state.blocked_submissions.append(outcome)
            return

        if name == "quit":
            return

        raise ValueError(f"unknown tool: {name!r}")
