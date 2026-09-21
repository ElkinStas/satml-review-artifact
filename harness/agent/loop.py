"""Main agent loop -- orchestrates one attempt.

Per-attempt execution:
    1. Initialise AgentState (state.py).
    2. Step loop, until a stop condition:
         - budget hooks: stop on max_steps, or a high token SAFETY ceiling
           (budget_tokens; cache_read excluded). max_steps is the binding budget.
         - policy proposes the next tool call (policy.py).
         - registry dispatches it; ledgers and the StepRecord are populated.
         - stop on an accepted submission or an agent quit.
    3. Persist the trace to {runs_dir}/{task_id}/{arm}/{attempt}/trace.jsonl.

Arm wiring: A0 runs with retrieval disabled and scaffold=None. A1 attaches per-step
card retrieval; A2 additionally passes a LedgerScaffold into the SubmissionController.
The loop itself does not branch on arm -- the arm differences are injected as
constructor dependencies (run_pilot.py wires them).

Status: implemented and exercised end-to-end -- against a stub (agent/smoke_test.py)
and against ClaudePolicy + BinaryOracle on real binaries (run_pilot.py). Registered
upgrades remain future work: scaffold-threshold calibration (Weeks 8-10) and the
confirmatory integration runs on the synthetic substrate. (BM25 retrieval is now
implemented -- see retrieval.py; keyword-overlap is retained as an ablation backend.)
"""

from __future__ import annotations

import os
import time

from agent.config import RunConfig
from agent.policy import Policy
from agent.state import AgentState, StepRecord, TerminationReason
from agent.tools.registry import ToolRegistry


class AgentLoop:
    def __init__(self, config: RunConfig, policy: Policy, registry: ToolRegistry,
                 run_meta: dict | None = None) -> None:
        self.config = config
        self.policy = policy
        self.registry = registry
        self.run_meta = run_meta or {}  # #13: provenance merged into the trace meta

    def run(self) -> AgentState:
        cfg = self.config
        # #10/#12: fail closed AND race-safe. Reserve the trace path atomically with O_CREAT|O_EXCL so
        # two parallel runs can't both pass an exists() check and then overwrite each other. The empty
        # reservation is overwritten by persist() at the end; a leftover 0-byte file flags an
        # incomplete run rather than silently vanishing.
        tp = cfg.trace_path()
        tp.parent.mkdir(parents=True, exist_ok=True)
        if cfg.overwrite:
            try:
                tp.unlink()
            except FileNotFoundError:
                pass
        try:
            os.close(os.open(tp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))
        except FileExistsError:
            raise FileExistsError(
                f"trace already exists: {tp} -- pass overwrite=True (--overwrite) or use a new runs_dir")
        state = AgentState(
            task_id=cfg.task_id, attempt_id=cfg.attempt_id, arm=cfg.arm
        )
        state.run_meta = dict(self.run_meta)  # #13

        while True:
            # --- budget hooks (calibrated values come from cfg, not from code) ---
            if state.step_idx >= cfg.max_steps:
                self._terminate(state, TerminationReason.MAX_STEPS)
                break
            # Budget is measured on budget_tokens (uncached_input + cache_write + output);
            # cache_read is EXCLUDED -- it is the cheap transcript re-read that grows
            # ~quadratically and otherwise trips this cap before max_steps, unequally across
            # arms. max_total_tokens is now a high safety ceiling; max_steps is the real budget.
            if state.tokens.budget_tokens >= cfg.max_total_tokens:
                self._terminate(state, TerminationReason.MAX_TOKENS)
                break

            # --- one step: propose -> dispatch -> record ---
            # #14: an API/network error in propose_action (timeout/5xx/etc.) must become an ERROR
            # trace, not an uncaught exception that aborts the run and every later attempt/arm.
            try:
                call, tokens = self.policy.propose_action(state)
            except Exception as exc:  # noqa: BLE001 -- policy/API error (after in-policy retries) -> ERROR trace
                self._terminate(state, TerminationReason.ERROR, detail=f"policy error: {exc!r}")
                break
            step = StepRecord(step_idx=state.step_idx, tool_call=call, tokens=tokens)
            step.retrieved_cards = list(getattr(self.policy, "last_retrieved", []) or [])
            step.retrieval_event = state.active_retrieval  # set by the policy pre-dispatch (A1/A2)
            try:
                self.registry.dispatch(call, state, step)
            except Exception as exc:  # noqa: BLE001 -- a bad tool call ends the attempt cleanly
                step.tokens = tokens
                state.record_step(step)
                self._terminate(state, TerminationReason.ERROR, detail=repr(exc))
                break
            state.record_step(step)

            # --- stop conditions evaluated after the step ---
            if step.submission is not None:
                # Submission is ONE-SHOT and terminal, right or wrong. If a wrong answer merely cost a
                # step and came back labelled "not accepted", submit_candidate would itself be a free,
                # retryable oracle -- the very affordance whose removal this design rests on. The agent
                # is never told whether it was right; scoring happens here, in the harness.
                self._terminate(state, TerminationReason.SOLVED if step.submission.accepted
                                else TerminationReason.SUBMITTED_WRONG)
                break
            if call.tool == "quit":
                self._terminate(state, TerminationReason.AGENT_QUIT)
                break

            state.step_idx += 1

        state.persist(cfg.trace_path())
        return state

    @staticmethod
    def _terminate(state: AgentState, reason: TerminationReason, detail: str = "") -> None:
        state.terminated = True
        state.termination_reason = reason
        state.termination_detail = detail  # exception repr for ERROR; surfaced in the trace meta
