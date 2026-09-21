# agent/prompts/

System prompts, assembled as **common base + arm deltas** by
`agent/prompting.py`.

```
A0 = system_common.txt
A1 = system_common.txt + delta_a1.txt
A2 = system_common.txt + delta_a1.txt + delta_a2.txt
```

## Why base + delta (not three files)

1. **Parity by construction.** The prereg requires A0/A1/A2 to differ *only* by
   the intended informational delta. Three hand-maintained monoliths drift; a
   shared base cannot. `smoke_test.py` asserts A0 is a prefix of A1 is a prefix
   of A2.
2. **Prompt caching.** The common base + the static tool specs form a
   byte-identical prefix across every arm and every run.

## A0 contains no validation-discipline language

`system_common.txt` (= the A0 prompt) describes the tools `record_hypothesis`
and `record_validation` **neutrally**, as available tools — never as advice to
verify before submitting. Any "verify the candidate" effect must come from the
A1 cards or the A2 scaffold, not the baseline prompt. Keep it that way: editing
discipline language into the common base contaminates A0.

## cache_control placement (for the future ClaudePolicy, Weeks 3–5)

The Anthropic API call should mark cache breakpoints so the stable prefix is not
re-billed every step:

- **Breakpoint 1** — end of `[system prompt + tool specs]`. Static per arm
  (and the `system_common` portion is shared across arms). Re-read every step.
- **Breakpoint 2** — a walking breakpoint at the tail of the message history,
  so each step caches all prior turns.

Retrieved cards (A1/A2) are injected into the **user message stream**, never the
system prompt — they are append-only history, so forward caching still holds.

The token **budget** (`max_total_tokens`, MC3) is measured on *processed*
tokens, so enabling caching changes cost but not when the budget trips. See
`TokenAccounting` in `agent/state.py`.

## Status

`TODO(Week 1)`: finalize prompt prose at the pre-pilot content review.
