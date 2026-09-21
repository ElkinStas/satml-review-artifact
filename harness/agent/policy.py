"""Action policy: how the agent chooses its next tool call.

The Policy abstraction is the seam between a deterministic scripted policy and the real
agent. StubPolicy (scripted, no LLM) exercises the loop, tools, budget hooks and trace
end-to-end in smoke tests; ClaudePolicy is the real model loop (implemented below). It:
  * assemble the system prompt via prompting.assemble_system_prompt(arm)
  * place cache_control breakpoints on [system + tool specs] and on the growing
    message history (see prompts/README.md)
  * parse the model's tool_use blocks into ToolCall objects
  * fill TokenAccounting from the API usage block (input / cache_read / cache_write
    / output). processed_tokens is logged for cost analysis; stopping uses budget_tokens
    (cache_read excluded).
"""

from __future__ import annotations

import time

from abc import ABC, abstractmethod

from agent.state import AgentState, ToolCall, TokenAccounting


class Policy(ABC):
    @abstractmethod
    def propose_action(self, state: AgentState) -> tuple[ToolCall, TokenAccounting]:
        """Return the next tool call and the token cost of producing it."""


# A default deterministic script: inspect, hypothesise, validate, submit.
def _default_script(accept_value: str) -> list[tuple[str, dict]]:
    return [
        ("file", {"target": "{binary}"}),
        ("strings", {"target": "{binary}"}),
        ("record_hypothesis", {"text": "candidate string seen in .rodata",
                               "cites_card_ids": []}),
        ("record_validation", {"action_type": "dynamic_run_with_input",
                               "source_observation": "ran binary with candidate",
                               "result": "binary accepted the input"}),
        ("submit_candidate", {"value": accept_value}),
    ]


class StubPolicy(Policy):
    """Deterministic scripted policy -- NO LLM. Drives the skeleton end-to-end.

    Each scripted step also reports a synthetic TokenAccounting so the MAX_TOKENS
    budget hook is genuinely exercised. `{binary}` placeholders are filled with the
    real binary path at construction time.
    """

    def __init__(
        self,
        binary_path: str,
        accept_value: str = "stub-flag",
        script: list[tuple[str, dict]] | None = None,
        tokens_per_step: int = 1_500,
    ) -> None:
        raw = script if script is not None else _default_script(accept_value)
        self._script = [
            (tool, {k: (v.replace("{binary}", binary_path) if isinstance(v, str) else v)
                    for k, v in args.items()})
            for tool, args in raw
        ]
        self._tokens_per_step = tokens_per_step
        self._cursor = 0

    def propose_action(self, state: AgentState) -> tuple[ToolCall, TokenAccounting]:
        if self._cursor < len(self._script):
            tool, args = self._script[self._cursor]
        else:
            tool, args = "quit", {}  # script exhausted -> end the attempt
        self._cursor += 1

        call = ToolCall(step_idx=state.step_idx, tool=tool, args=dict(args))
        # Synthetic accounting: first step writes cache, later steps read it --
        # mirrors how a real cached run bills, and exercises processed_tokens.
        if state.step_idx == 0:
            tokens = TokenAccounting(uncached_input_tokens=self._tokens_per_step,
                                     cache_write_tokens=600, output_tokens=120)
        else:
            tokens = TokenAccounting(uncached_input_tokens=300,
                                     cache_read_tokens=self._tokens_per_step,
                                     output_tokens=120)
        return call, tokens


# ============================================================================
# ClaudePolicy -- the real model loop. Drives the agent via the
# Anthropic Messages API. One tool call per step (disable_parallel_tool_use);
# conversation state held internally; previous dispatched result is read back
# from `state` and fed as a tool_result. A1/A2 get an advisory pattern-cards block.
# ============================================================================
from agent.prompting import assemble_system_prompt  # noqa: E402
from agent.tools.registry import llm_tool_specs  # noqa: E402
from agent.tools.action_whitelist import ValidationActionType  # noqa: E402


def _anthropic_tools(specs: list[dict]) -> list[dict]:
    """Translate registry llm_tool_specs() -> Anthropic tools JSON-schema."""
    tools = []
    for s in specs:
        name = s["name"]
        if s.get("kind") == "shell":
            props = {
                "cmd": {"type": "string", "description": "command string (r2/gdb only)"},
                "code": {"type": "string", "description": "python source (python3 only); refer to the "
                                                          "binary as {TARGET}"},
            }
            if name in ("r2", "gdb"):
                required = ["cmd"]                # target is injected by the harness (never model-supplied)
            elif name == "python3":
                required = ["code"]
            else:
                required = []                     # file/strings/readelf/objdump/nm take no arguments
        elif name == "trace_binary":
            props = {
                "tracer": {"type": "string", "enum": ["strace", "ltrace"]},
                "candidate": {"type": "string", "description": "the exact input to feed the binary"},
                "input_method": {"type": "string", "enum": ["stdin", "argv"],
                                 "description": "optional; task default if omitted"},
            }
            required = ["tracer", "candidate"]
        elif name == "record_hypothesis":
            props = {"text": {"type": "string"},
                     "cites_card_ids": {"type": "array", "items": {"type": "string"}}}
            required = ["text"]
        elif name == "record_validation":
            props = {
                "action_type": {"type": "string", "enum": [a.value for a in ValidationActionType]},
                "candidate": {"type": "string", "description": "the exact candidate this validation concerns"},
                "source_step_idx": {"type": "integer", "description": "step whose tool output is your evidence (see [step N] tags)"},
                "tool_name": {"type": "string", "description": "tool that produced that output"},
                "source_observation": {"type": "string"},
                "result": {"type": "string", "description": "the observed output / detail"},
                "verdict": {"type": "string", "enum": ["accepted", "rejected", "inconclusive"],
                            "description": "YOUR reading of what the run showed -- the harness does not tell you"},
            }
            required = ["action_type", "candidate", "source_step_idx", "source_observation", "result", "verdict"]
        elif name == "run_binary":
            props = {
                "candidate": {"type": "string", "description": "the exact input to feed the binary"},
                "input_method": {"type": "string", "enum": ["stdin", "argv"],
                                 "description": "optional; task default if omitted"},
            }
            required = ["candidate"]
        elif name == "submit_candidate":
            props = {"value": {"type": "string"}}
            required = ["value"]
        else:  # quit
            props, required = {}, []
        tools.append({
            "name": name, "description": s.get("description", ""),
            "input_schema": {"type": "object", "properties": props, "required": required,
                             "additionalProperties": False},
        })
    return tools


def _format_step_result(step) -> str:
    """Render a dispatched step's outcome as tool_result text for the model."""
    if step.tool_result is not None:
        r = step.tool_result
        head = f"[step {step.step_idx}] tool={r.tool} exit_code={r.exit_code}"
        body = f"{head}\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}"
        return body + ("\n[output truncated]" if r.truncated else "")
    if step.submission is not None:
        s = step.submission
        return f"submission {'ACCEPTED' if s.accepted else 'REJECTED'} ({s.oracle_detail})"
    if step.blocked_submission is not None:
        return f"submission BLOCKED by scaffold: {step.blocked_submission.reason}"
    if step.validations_added:
        return f"validation recorded (qualifies={step.validations_added[-1].qualifies})."
    if step.hypotheses_added:
        return "hypothesis recorded."
    return "ok."


class ClaudePolicy(Policy):
    def __init__(self, *, arm, binary_path, model, client=None, cards=None,
                 max_tokens=4096, prompts_dir=None, k=3, retry_count=2, retry_backoff_s=1.0,
                 scaffold_strictness=None, differential_trigger=None):
        self.arm = arm
        self.binary_path = binary_path
        self.model = model
        self.max_tokens = max_tokens
        if client is None:
            import anthropic
            client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        self.client = client
        self.system_text = assemble_system_prompt(arm, prompts_dir,
                                                  scaffold_strictness=scaffold_strictness,
                                                  differential_trigger=differential_trigger)
        self.tools = _anthropic_tools(llm_tool_specs())
        self.cards = list(cards or [])
        self.k = k
        self.retry_count = retry_count
        self.retry_backoff_s = retry_backoff_s
        self.last_retrieved: list = []
        self._last_injected_ids: list | None = None  # #8: inject card block only when top IDs change
        self._last_event = None  # last RetrievalEvent (for the loop to attach to the step)
        self.messages: list[dict] = []
        self._pending_id = None
        self._started = False

    def _task_text(self) -> str:
        return (f"The target binary is at: {self.binary_path}\n"
                "Analyse it and find an input it accepts. Emit exactly one tool call now.")

    def _retrieve_for_step(self, state):
        """Per-step retrieval (A1/A2). Returns (cards_block_text, RetrievalEvent).

        Records self.last_retrieved (per-step trace attribution) and a structured RetrievalEvent
        (query/rank/score/injected/active) so the A2 scaffold's `retrieved` differential trigger can
        read what was retrieved for the CURRENT hypothesis, not guess it from history.
        """
        from agent.state import Arm, RetrievalEvent
        from agent.retrieval import format_cards_block, retrieve_scored
        h = state.hypothesis_ledger[-1] if state.hypothesis_ledger else None
        query = h.text if h else ""
        if self.arm not in (Arm.A1, Arm.A2) or not self.cards:
            self.last_retrieved = []
            return "", RetrievalEvent(hypothesis_step_idx=(h.step_idx if h else -1), query=query)
        scored = retrieve_scored(self.cards, query, k=self.k)
        self.last_retrieved = [c for c, _, _ in scored]
        ids = [c.card_id for c in self.last_retrieved]
        ranked = [{"card_id": c.card_id, "rank": rank, "score": round(score, 6)} for c, score, rank in scored]
        # #8: re-inject the (identical) card block only when the top IDs change -- avoids re-sending an
        # identical ~500-word block as fresh input every step. The event is still recorded every step.
        # #8 reinject only when the top IDs change; but update the marker on EVERY retrieval (including
        # an all-miss []), so X -> [] -> X reinjects the block for the re-relevant phase (an intervening
        # miss no longer sticks the marker on the old IDs).
        changed = ids != self._last_injected_ids
        self._last_injected_ids = ids
        injected = bool(ids) and changed
        block = format_cards_block(self.last_retrieved) if injected else ""
        event = RetrievalEvent(hypothesis_step_idx=(h.step_idx if h else -1), query=query,
                               ranked_cards=ranked, block_injected=injected, active_card_ids=ids)
        return block, event

    def _mark_cache_breakpoint(self, messages) -> None:
        """#9: walking cache breakpoint on the growing message history.

        Anthropic caches the prefix up to a cache_control marker. Keep exactly ONE breakpoint on the
        last content block of the most recent message (the system prompt carries its own), so the whole
        transcript up to the latest turn is a cache read on the next request. Clear earlier message-level
        markers first to stay under the 4-breakpoint API limit.
        """
        for m in messages:
            c = m.get("content")
            if isinstance(c, list):
                for b in c:
                    if isinstance(b, dict):
                        b.pop("cache_control", None)
        if not messages:
            return
        last = messages[-1]
        c = last["content"]
        if isinstance(c, str):
            last["content"] = [{"type": "text", "text": c, "cache_control": {"type": "ephemeral"}}]
        elif isinstance(c, list) and c and isinstance(c[-1], dict):
            c[-1]["cache_control"] = {"type": "ephemeral"}

    def _create_with_retry(self, messages):
        """#3: retry the API call transactionally on the SAME request. self.messages is committed only
        after success, so a transient failure never corrupts history (no IndexError at step 0, no
        duplicated tool_result on later steps)."""
        last_exc = None
        for attempt in range(self.retry_count + 1):
            try:
                return self.client.messages.create(
                    model=self.model, max_tokens=self.max_tokens,
                    system=[{"type": "text", "text": self.system_text,
                             "cache_control": {"type": "ephemeral"}}],
                    tools=self.tools,
                    tool_choice={"type": "any", "disable_parallel_tool_use": True},
                    messages=messages,
                )
            except Exception as exc:  # noqa: BLE001 -- retry transient API/network errors
                last_exc = exc
                if attempt < self.retry_count:
                    time.sleep(min(self.retry_backoff_s * (2 ** attempt), 8.0))
                    continue
                raise
        raise last_exc  # unreachable

    def propose_action(self, state):
        cards_block, retrieval_event = self._retrieve_for_step(state)
        state.active_retrieval = retrieval_event  # pre-dispatch: the A2 scaffold reads THIS step's retrieval
        self._last_event = retrieval_event
        # Build the next user message WITHOUT mutating self.messages/_started yet (transactional).
        if not self._started:
            content = self._task_text() + (("\n\n" + cards_block) if cards_block else "")
            user_msg = {"role": "user", "content": content}
        else:
            blocks = [{"type": "tool_result", "tool_use_id": self._pending_id,
                       "content": _format_step_result(state.steps[-1])}]
            if cards_block:
                blocks.append({"type": "text", "text": cards_block})
            user_msg = {"role": "user", "content": blocks}

        req = self.messages + [user_msg]        # committed history + tentative turn
        self._mark_cache_breakpoint(req)         # walking breakpoint on the request (last block)
        resp = self._create_with_retry(req)

        # success -> commit the turn atomically
        self.messages.append(user_msg)
        self._started = True
        self.messages.append({"role": "assistant", "content": resp.content})

        tu = next((b for b in resp.content if getattr(b, "type", None) == "tool_use"), None)
        if tu is None:
            self._pending_id = None
            call = ToolCall(step_idx=state.step_idx, tool="quit", args={})
        else:
            self._pending_id = tu.id
            call = ToolCall(step_idx=state.step_idx, tool=tu.name, args=dict(tu.input))

        u = resp.usage
        tokens = TokenAccounting(
            uncached_input_tokens=getattr(u, "input_tokens", 0) or 0,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            output_tokens=getattr(u, "output_tokens", 0) or 0,
        )
        return call, tokens
