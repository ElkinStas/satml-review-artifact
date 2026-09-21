"""OpenAI-compatible policy -- a second model family behind the same agent loop.

WHY A SEPARATE FILE
-------------------
`agent/policy.py` is load-bearing: `ClaudePolicy` produced every measurement in the study, and its
hash is one of the preflight anchors. Editing it to add a second provider would invalidate those
anchors and put the existing A0/A1/A2 numbers in question for no reason. This module adds a parallel
implementation and touches nothing that already ran.

WHAT IS HELD IDENTICAL TO THE CLAUDE ARM
----------------------------------------
The point of the second model is to vary the MODEL and nothing else, so the comparison means
something. Reused verbatim from `agent.policy`:

  * the prompt files (`system_common.txt`, per-arm deltas) -- read through the same loader
  * `llm_tool_specs()` -- the same tool surface, only re-shaped into OpenAI's schema
  * `_format_step_result` -- identical rendering of a dispatched step back to the model
  * the retrieval path (`_retrieve_for_step`) -- same cards, same BM25, same k
  * the task text, the step budget, the sandbox, the pool, the scorer

Only four things differ, and all four are forced by the API rather than chosen:

  1. tool schema  {name, description, input_schema}  ->  {type:"function", function:{...parameters}}
  2. system prompt  a top-level `system=` argument   ->  a first message with role="system"
  3. tool result    a user block {type:"tool_result"} ->  a message with role="tool"
  4. cache control  explicit ephemeral breakpoints    ->  automatic prefix caching, nothing to mark

ONE ACTION PER STEP, ENFORCED THE SAME WAY IN BOTH ARMS
Anthropic uses `disable_parallel_tool_use`; Chat Completions has `parallel_tool_calls=False`. Both
guarantee exactly one tool call per turn, so the arms share the constraint rather than approximating
it. An earlier draft of this adapter claimed no equivalent existed and took the first call while
dropping the rest -- which would have left a real defect in the transcript: the assistant message
recorded every returned tool_call, but only the first ever received a matching tool result, so the
history sent back on the next turn was malformed. `n_parallel_dropped` remains as a tripwire and
should stay at zero; if it ever moves, the endpoint ignored the flag and the run is not comparable.

USAGE
    export OPENAI_API_KEY=...
    PILOT_MODEL=gpt-5.6-sol python3 run_pilot.py --task <id> --arm A0 --attempts 5 --policy openai

The model comes from PILOT_MODEL; there is no --model flag.

For a local OpenAI-compatible server (vLLM, SGLang), pass --base-url.
"""
from __future__ import annotations

import json
import time

from agent.policy import ClaudePolicy, _anthropic_tools, _format_step_result
from agent.state import ToolCall, TokenAccounting
from agent.tools.registry import llm_tool_specs


def _openai_tools(specs: list[dict]) -> list[dict]:
    """Re-shape the SAME tool schemas Claude receives into OpenAI's function format.

    This delegates to `_anthropic_tools`, which is where the real schemas live. The first version
    read `spec["input_schema"]` straight off the registry entry -- a key that does not exist there.
    `llm_tool_specs()` returns {name, kind, description, input}, with `input` a human-readable hint
    ({"cmd": "str (r2/gdb only)"}), not a JSON schema. The lookup silently produced empty
    `properties` for all twelve tools, so the OpenAI arm ran with tools that declared NO parameters
    at all and the model had to guess argument names.

    It guessed, and the guesses crashed runs mid-way:
        TypeError: ShellTool.run() got an unexpected keyword argument 'disassemble'
        TypeError: ShellTool.run() got an unexpected keyword argument ''

    Deriving from `_anthropic_tools` also removes the drift risk: both arms now describe the tool
    surface from one source, so a change to a tool cannot reach one family and not the other.
    """
    out = []
    for t in _anthropic_tools(specs):
        schema = dict(t["input_schema"])
        out.append({"type": "function",
                    "function": {"name": t["name"],
                                 "description": t.get("description", ""),
                                 "parameters": schema}})
    return out


class OpenAIPolicy(ClaudePolicy):
    """Same agent loop, same prompts, same tools -- different model family.

    Subclasses ClaudePolicy so retrieval, prompt assembly and task text come from one place. Only
    the transport is overridden.
    """

    def __init__(self, *, arm, binary_path, model, client=None, cards=None,
                 max_tokens=4096, prompts_dir=None, k=3, retry_count=2, retry_backoff_s=1.0,
                 base_url=None, reasoning_effort=None, **kw):
        super().__init__(arm=arm, binary_path=binary_path, model=model,
                         client=_NullClient(), cards=cards, max_tokens=max_tokens,
                         prompts_dir=prompts_dir, k=k, retry_count=retry_count,
                         retry_backoff_s=retry_backoff_s, **kw)
        if client is None:
            from openai import OpenAI
            client = OpenAI(base_url=base_url) if base_url else OpenAI()
        self.client = client
        self.tools = _openai_tools(llm_tool_specs())
        self.reasoning_effort = reasoning_effort
        self.n_parallel_dropped = 0   # tripwire: must stay 0 with parallel_tool_calls=False
        self.n_bad_args = 0           # tool-call arguments the tool does not declare

    # --- transport ------------------------------------------------------------------------
    def _mark_cache_breakpoint(self, messages) -> None:
        """No-op: OpenAI caches long prompt prefixes automatically, with nothing to annotate."""
        return

    def _create_with_retry(self, messages):
        """Retry on the SAME request, exactly as the Claude arm does.

        History is committed by the caller only after this returns, so a transient failure can never
        leave a half-written turn behind.
        """
        req = [{"role": "system", "content": self.system_text}] + messages
        last = None
        for attempt in range(self.retry_count + 1):
            try:
                # max_completion_tokens, not max_tokens: the latter is deprecated in Chat
                # Completions and is not accepted by reasoning-enabled models.
                kw = dict(model=self.model, max_completion_tokens=self.max_tokens,
                          messages=req, tools=self.tools, tool_choice="required",
                          parallel_tool_calls=False)
                if self.reasoning_effort:
                    # Pinned explicitly: GPT-5.6 defaults to medium, and an unstated default is a
                    # confound waiting to appear between two series of the same experiment.
                    kw["reasoning_effort"] = self.reasoning_effort
                return self.client.chat.completions.create(**kw)
            except Exception as exc:  # noqa: BLE001 -- retry transient API/network errors
                last = exc
                if attempt < self.retry_count:
                    time.sleep(min(self.retry_backoff_s * (2 ** attempt), 8.0))
                    continue
                raise
        raise last  # unreachable

    # --- the turn -------------------------------------------------------------------------
    def propose_action(self, state):
        cards_block, retrieval_event = self._retrieve_for_step(state)
        state.active_retrieval = retrieval_event
        self._last_event = retrieval_event

        # Build the turn WITHOUT mutating history: it is committed only after a successful call.
        if not self._started:
            content = self._task_text() + (("\n\n" + cards_block) if cards_block else "")
            pending = [{"role": "user", "content": content}]
        else:
            # OpenAI carries a tool result in its own message, keyed by the call id.
            pending = [{"role": "tool", "tool_call_id": self._pending_id,
                        "content": _format_step_result(state.steps[-1])}]
            if cards_block:
                pending.append({"role": "user", "content": cards_block})

        resp = self._create_with_retry(self.messages + pending)
        msg = resp.choices[0].message

        self.messages.extend(pending)
        self._started = True
        self.messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name,
                                         "arguments": tc.function.arguments}}
                           for tc in (msg.tool_calls or [])],
        })

        calls = msg.tool_calls or []
        if not calls:
            # No call despite tool_choice="required" -- treat as the agent stopping, same as Claude.
            self._pending_id = None
            call = ToolCall(step_idx=state.step_idx, tool="quit", args={})
        else:
            if len(calls) > 1:
                # Should be unreachable with parallel_tool_calls=False. If it fires, the endpoint
                # ignored the flag; count it so the run's provenance shows the arms diverged.
                self.n_parallel_dropped += len(calls) - 1
            tc = calls[0]
            self._pending_id = tc.id
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                # A malformed argument blob is a model error, not a harness error. Surface it as a
                # quit rather than crashing the run, so the trace records what happened.
                self._pending_id = None
                return (ToolCall(step_idx=state.step_idx, tool="quit", args={}),
                        _usage(resp))
            # Drop arguments the tool does not declare.
            #
            # Anthropic validates a tool call against `input_schema` before returning it, so a call
            # with a stray key never reaches the harness. The OpenAI API makes no such guarantee:
            # `parameters` is a hint, and the model may return valid JSON carrying keys the tool has
            # never heard of. Those went straight into ShellTool.run() and killed the run mid-way:
            #     TypeError: ShellTool.run() got an unexpected keyword argument 'disassemble'
            #     TypeError: ShellTool.run() got an unexpected keyword argument ''
            # -- the second one an empty key, i.e. {"": ...}. A run lost at step 7 or 11 to a
            # harness crash is not a measurement of anything, and it is the adapter's job to absorb
            # a provider difference rather than let it corrupt the batch.
            #
            # Dropped keys are counted, not silently discarded: how often a model misses its own
            # tool schema is itself a difference between the two families and belongs in the trace.
            if not isinstance(args, dict):
                self.n_bad_args += 1
                args = {}
            spec = next((t for t in self.tools
                         if t["function"]["name"] == tc.function.name), None)
            if spec:
                allowed = set((spec["function"].get("parameters") or {}).get("properties") or {})
                stray = [k for k in args if k not in allowed]
                if stray:
                    self.n_bad_args += len(stray)
                    args = {k: v for k, v in args.items() if k in allowed}
            call = ToolCall(step_idx=state.step_idx, tool=tc.function.name, args=args)

        return call, _usage(resp)


def _usage(resp) -> TokenAccounting:
    """Map OpenAI usage onto the study's accounting.

    `prompt_tokens` already INCLUDES cached tokens, so uncached is the difference -- reporting
    prompt_tokens as uncached would inflate the budget meter and stop runs early relative to the
    Claude arm. OpenAI has no cache-write counter (priming is not billed separately), so that field
    is 0 by construction rather than by omission.
    """
    u = getattr(resp, "usage", None)
    if u is None:
        return TokenAccounting(0, 0, 0, 0)
    prompt = getattr(u, "prompt_tokens", 0) or 0
    details = getattr(u, "prompt_tokens_details", None)
    cached = (getattr(details, "cached_tokens", 0) or 0) if details else 0
    return TokenAccounting(
        uncached_input_tokens=max(0, prompt - cached),
        cache_read_tokens=cached,
        cache_write_tokens=0,
        output_tokens=getattr(u, "completion_tokens", 0) or 0,
    )


class _NullClient:
    """Placeholder passed to the base constructor so it does not build an Anthropic client."""
