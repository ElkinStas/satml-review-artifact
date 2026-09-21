#!/usr/bin/env python3
"""Prompt-surface hygiene (no LLM).

The A0 prompt surface = the assembled system prompt AND the tool schemas (both are sent to the model).
Validation-discipline language must not appear anywhere in it, or the baseline is pre-treated against
W2. This scans BOTH surfaces (the earlier fix touched only system_common.txt; the same phrase also
lived in the run_binary tool schema in registry.py). It also checks the discipline DOES survive in the
A2 delta, so we know it wasn't over-removed.

Run from repo root:  python agent/test_prompt_hygiene.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.prompting import assemble_system_prompt
from agent.policy import ClaudePolicy
from agent.state import Arm

# Discipline phrases that must not reach the A0 baseline (case-insensitive).
FORBIDDEN = [
    "never infer", "test whether", "infer acceptance", "must validate", "validate before",
    "do not trust static", "don't trust static", "never accept", "always run_binary",
    "acceptance from static", "not enough",
]

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


def _policy(arm):
    # client=object() so __init__ doesn't build a real Anthropic client (client unused until a call)
    return ClaudePolicy(arm=arm, binary_path="./target", model="m", client=object(), cards=[])


def _surface(arm) -> str:
    pol = _policy(arm)
    # scan the ACTUAL schema the model receives (policy.tools = _anthropic_tools(llm_tool_specs())),
    # not the raw internal spec -- a change in _anthropic_tools() must not slip past this.
    return (pol.system_text + "\n" + json.dumps(pol.tools, default=str)).lower()


def main() -> int:
    schemas = json.dumps(_policy(Arm.A0).tools, default=str).lower()
    tools = {t["name"]: t["input_schema"] for t in _policy(Arm.A0).tools}
    a0 = _surface(Arm.A0)

    # 1. tool schemas alone (shared across arms) must be clean
    for p in FORBIDDEN:
        expect(f"tool schemas free of {p!r}", p not in schemas)

    # 2. full A0 surface (system prompt + schemas) must be clean
    for p in FORBIDDEN:
        expect(f"A0 surface free of {p!r}", p not in a0)

    # 3. execution is GONE from the agent surface. Removing run_binary alone would have been cosmetic
    #    (python3/gdb/r2 could still exec the target); the target is additionally exposed non-executable.
    #    These assertions guard the tool CONTRACT half of that cut.
    expect("run_binary is not offered to the agent", "run_binary" not in tools)
    expect("trace_binary is not offered to the agent", "trace_binary" not in tools)
    expect("no schema promises a semantic verdict",
           "observable verdict" not in schemas and "accepted | rejected" not in schemas)
    expect("static analysis survives intact",
           {"strings", "objdump", "nm", "readelf", "r2", "gdb", "python3"} <= set(tools))
    expect("submission is still available (it is the only terminal action)",
           "submit_candidate" in tools)
    expect("schemas do NOT teach acceptance discipline",
           "test whether" not in schemas and "never infer" not in schemas)

    # 4. discipline SURVIVES in the A2 delta (not over-removed): A2 surface carries the differential rule
    a2 = _surface(Arm.A2)
    expect("A2 surface carries the differential/validation intervention",
           "RECONSTRUCTED" in a2 or "derivation" in a2)
    expect("A2 surface differs from A0 surface (delta is applied)", a2 != a0)

    # #6 + final schema: shell tools take no target; args are required where meaningful; trace_binary added
    def req(n): return set(tools[n]["required"])
    def props(n): return set(tools[n]["properties"])
    expect("#6 r2 requires cmd only (no target)", req("r2") == {"cmd"})
    expect("#6 gdb requires cmd only (no target)", req("gdb") == {"cmd"})
    expect("#6 python3 requires code", req("python3") == {"code"})
    expect("#6 file/strings/nm take no arguments", req("nm") == set() and req("strings") == set() and req("file") == set())
    expect("no shell tool exposes a model-supplied target", all("target" not in props(f) for f in ("nm", "r2", "gdb", "python3", "strings")))
    expect("trace_binary absent from the final surface", "trace_binary" not in tools)
    expect("every schema forbids additional properties",
           all(s.get("additionalProperties") is False for s in tools.values()))
    expect("strace/ltrace are NOT standalone tools (only via trace_binary)",
           "strace" not in tools and "ltrace" not in tools)

    # #8: the A2 prompt states the ACTIVE gate mode (not a fixed 'cited' description)
    from agent.prompting import assemble_system_prompt
    a2_retr = assemble_system_prompt(Arm.A2, None, scaffold_strictness=2, differential_trigger="retrieved").lower()
    a2_s3 = assemble_system_prompt(Arm.A2, None, scaffold_strictness=3, differential_trigger="cited").lower()
    a1_txt = assemble_system_prompt(Arm.A1, None)
    a2_txt = assemble_system_prompt(Arm.A2, None, scaffold_strictness=2, differential_trigger="retrieved")
    # The differential/strictness modes died with run_binary (nothing is executable, so there is no
    # accepting run and no rejected baseline). What must hold now: the gate note is INVARIANT across
    # configurations -- the model is never told a rule the run does not enforce.
    expect("#8 gate note no longer varies with the dead strictness/trigger knobs", a2_retr == a2_s3)
    expect("#8 gate note states the derivation rule", "reconstructed" in a2_retr)
    expect("#8 gate note withholds correctness feedback",
           "does not know whether your answer is correct" in a2_retr)
    expect("#8 parity preserved: A1 prompt is a prefix of A2 (with mode note)", a2_txt.startswith(a1_txt))

    # phantom-tool + authoring-note hygiene: the prompt must not promise a tool absent from the schema,
    # nor leak DRAFT/arm-structure authoring notes. (strace/ltrace ARE named now -- legitimately, as the
    # trace_binary tracer options -- so they are not phantom.)
    sys_a0 = _policy(Arm.A0).system_text.lower()
    sys_a2 = _policy(Arm.A2).system_text.lower()
    tool_names = set(tools)
    for meta in ("draft", "verbatim", "[delta", "[system prompt", "token target", "finalized at the pre-pilot"):
        expect(f"prompt carries no authoring note '{meta}'", meta not in sys_a2)
    for named in ("record_hypothesis", "record_validation", "submit_candidate", "quit"):
        expect(f"prompt-named tool '{named}' exists in the schema", named in tool_names)
    for gone in ("run_binary", "trace_binary"):
        expect(f"prompt does NOT reference the removed tool '{gone}'", gone not in sys_a2)
    expect("prompt tells the agent the binary is referenced as {target}", "{target}" in sys_a0)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"PROMPT HYGIENE TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"PROMPT HYGIENE TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
