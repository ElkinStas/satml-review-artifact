# agent/prompts/

System prompts, assembled as **common base + arm deltas** by
`agent/prompting.py`.

```text
A0 = system_common.txt
A1 = system_common.txt + delta_a1.txt
A2 = system_common.txt + delta_a1.txt + delta_a2.txt
```

## Why base + delta

1. **Parity by construction.** A0/A1/A2 share the same common prompt surface; the arm-specific files add only the intended intervention text.
2. **Prompt caching.** The common base and static tool specifications form a stable prefix that can be reused across steps.

## A0 contains no validation-discipline language

`system_common.txt` (= the A0 prompt) describes `record_hypothesis` and
`record_validation` neutrally as available tools. Validation guidance is introduced by the A1 retrieval cards and the A2 arm-specific prompt/scaffold rather than by the baseline prompt.

## Cache and token accounting

The Anthropic policy uses explicit cache breakpoints for the stable prompt/tool prefix and the accumulated message history. Retrieved cards for A1/A2 are injected into the message stream rather than rewriting the common system prompt.

`TokenAccounting` records uncached input, cache-read, cache-write, and output tokens. `processed_tokens` includes all four categories for descriptive logging. The stopping budget uses `budget_tokens`, which excludes cache-read tokens and counts uncached input + cache-write + output tokens. See `agent/state.py` and `agent/loop.py` for the authoritative implementation.
