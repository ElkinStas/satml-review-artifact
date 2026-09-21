"""Tests for agent/derivation_check.py -- A2 levels 1 (terminality) and 2 (reachability).

All disassembly here is FABRICATED for the test. No symbol, address, marker or value is taken from
the task pool or from any run; the shapes are generic (a helper that compares, a branch under a
conditional). Keep it that way.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dataclasses import dataclass, field  # noqa: E402

from agent.derivation_check import (  # noqa: E402
    build_view, check_consumer_observed, check_reachability, check_terminality)
from agent.scaffold import LedgerScaffold  # noqa: E402


# Lightweight fakes, matching the style of agent/test_scaffold.py: the layers read only
# step_idx / tool_result.{tool,stdout} and the ledger entry's text fields.
@dataclass
class FakeResult:
    tool: str
    stdout: str = ""
    stderr: str = ""


@dataclass
class FakeStep:
    step_idx: int
    tool_result: FakeResult


@dataclass
class FakeState:
    steps: list = field(default_factory=list)
    validation_ledger: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)


@dataclass
class FakeValidation:
    step_idx: int
    source_step_idx: int
    source_observation: str = ""
    result: str = ""
    candidate: str = "CAND-0001"
    action_type: str = "manual_trace_through"
    tool_name: str = "objdump"
    verdict: str = "accepted"
    qualifies: bool = True

checks: list[tuple[str, bool]] = []


def expect(label, ok):
    checks.append((label, bool(ok)))


# --- fabricated observations -------------------------------------------------------------------
# A helper that performs a real comparison, and a caller frame that ignores its result.
DISASM_NO_CALLER = """
0000000000401100 <helper_cmp>:
  401100:\t55                   \tpush   %rbp
  401104:\te8 00 00 00 00       \tcall   401030 <strcmp@plt>
  401109:\t85 c0                \ttest   %eax,%eax
  40110b:\t74 05                \tje     401112
  401112:\tc3                   \tret

0000000000401200 <main>:
  401200:\t55                   \tpush   %rbp
  401204:\te8 00 00 00 00       \tcall   401300 <other_gate>
  401209:\tc3                   \tret

0000000000401300 <other_gate>:
  401300:\t31 c0                \txor    %eax,%eax
  401302:\tc3                   \tret
"""

DISASM_WITH_CALLER = DISASM_NO_CALLER.replace(
    "  401204:\te8 00 00 00 00       \tcall   401300 <other_gate>",
    "  401204:\te8 00 00 00 00       \tcall   401100 <helper_cmp>")

# A block that would accept, sitting under a conditional the agent may or may not account for.
DISASM_GUARDED = """
0000000000402000 <check_input>:
  402000:\t48 83 ec 08          \tsub    $0x8,%rsp
  402008:\t83 f8 07             \tcmp    $0x7,%eax
  40200c:\t75 20                \tjne    402040
  402010:\te8 00 00 00 00       \tcall   401030 <strcmp@plt>
  402015:\t85 c0                \ttest   %eax,%eax
  402040:\tc3                   \tret
"""


def state_with(disasm: str, tool: str = "objdump") -> FakeState:
    return FakeState(steps=[FakeStep(0, FakeResult(tool, stdout=disasm))])

# --- r2 fixtures ------------------------------------------------------------------------------
# The gutter glyphs, column positions, address format ("0x004010b0", no colon), the packed byte
# column and its truncation dot are copied EXACTLY from r2 output observed in the Week-9 traces.
# Every symbol name, string and constant is invented for this test: no task content belongs in a
# committed fixture. The parser is being tested on FORMAT, which is where it previously failed --
# it was written against objdump while the agent reaches for r2 in almost every run.
R2_PDF_NO_CALLER = """\u250c 33: sym.leaf_compare (const char *s1);
\u2502           ; arg const char *s1 @ rdi
\u2502           0x00401240      f30f1efa       endbr64
\u2502           0x00401244      4889fe         mov rsi, rdi
\u2502           0x0040124f      e83cfeffff     call sym.imp.strcmp         ; int strcmp(con
\u2502       \u250c\u2500< 0x00401254      85c0           test eax, eax
\u2502       \u2502   0x00401256      7405           je 0x40125d
\u2514           0x0040125d      c3             ret

\u250c 145: int sym.frame_entry (signed int argc, char **s1);
\u2502           0x004010b0      f30f1efa       endbr64
\u2502           0x004010c8      e8c3ffffff     call sym.other_path         ; int other(con
\u2514           0x004010d0      c3             ret
"""

R2_PDF_WITH_CALLER = R2_PDF_NO_CALLER.replace("call sym.other_path", "call sym.leaf_compare")

# A block that would accept, sitting under a conditional that skips it.
R2_PDF_GUARDED = """\u250c 96: sym.gate_path (const char *s1);
\u2502           0x00402000      4883ec08       sub rsp, 8
\u2502           0x00402008      83f807         cmp eax, 7
\u2502       \u250c\u2500< 0x0040200c      7532           jne 0x402040
\u2502       \u2502   0x00402010      e8cbffffff     call sym.imp.strcmp
\u2502       \u2502   0x00402015      85c0           test eax, eax
\u2514       \u2514\u2500> 0x00402040      c3             ret
"""

# r2 afl: a function inventory with no disassembly at all.
R2_AFL = """0x00401140    1 38           entry0
0x00401070    1 10           sym.imp.puts
0x00401240    1 33           sym.leaf_compare
0x00401220    5 118  -> 55   entry.init0
"""


def test_r2_formats():
    v = build_view(state_with(R2_PDF_NO_CALLER, tool="r2"))
    expect("r2: function names recovered from pdf headers",
           {"sym.leaf_compare", "sym.frame_entry"} <= set(v.func_at.values()))
    expect("r2: call targets recovered through the gutter",
           "sym.other_path" in v.call_targets and "sym.imp.strcmp" in v.call_targets)
    expect("r2: conditional jumps recovered with their targets",
           any(m == "je" and t == 0x40125d for _, m, t in v.cond_jumps))
    expect("r2: truncated byte column does not break the line",
           0x004010b0 in v.seen_addrs)

    va = build_view(state_with(R2_AFL, tool="r2"))
    expect("r2: afl inventory alone yields functions",
           {"entry0", "sym.leaf_compare"} <= set(va.func_at.values()))

    t = check_consumer_observed(state_with(R2_PDF_NO_CALLER, tool="r2"),
                                val(result="sym.leaf_compare compares the input against the stored value"))
    expect("r2/L1: a routine with no observed caller is blocked",
           (not t.ok) and t.code == "no_consumer_observed")
    t2 = check_consumer_observed(state_with(R2_PDF_WITH_CALLER, tool="r2"),
                                 val(result="sym.leaf_compare does the comparison"))
    expect("r2/L1: an observed call site satisfies the layer",
           t2.ok and t2.code == "consumer_observed")

    g = state_with(R2_PDF_GUARDED, tool="r2")
    r = check_reachability(g, val(result="at 0x402010 the input is compared and the block accepts"))
    expect("r2/L2: a site under an unmentioned skipping branch is blocked",
           (not r.ok) and r.code == "guard_not_accounted_for")
    r2ok = check_reachability(
        g, val(result="the jne at 0x40200c skips the block unless the length check passes, then 0x402010 runs"))
    expect("r2/L2: naming the controlling conditional satisfies the layer",
           r2ok.ok and r2ok.code == "guards_accounted_for")


def test_bounded_control_dependence():
    """A conditional that lands BEFORE the site does not skip it, so it is not its guard."""
    v = build_view(state_with(R2_PDF_GUARDED, tool="r2"))
    site = 0x402015
    guards = v.guards_of(site)
    expect("L2: a jcc whose target is past the site counts as a guard",
           any(a == 0x40200c for a, _, _ in guards))
    backward = build_view(state_with(R2_PDF_GUARDED.replace("7532           jne 0x402040",
                                                            "7532           jne 0x402000"), tool="r2"))
    expect("L2: a jcc that lands before the site is NOT counted as its guard",
           not any(a == 0x40200c for a, _, _ in backward.guards_of(site)))


def test_no_retroactive_repair():
    """A hypothesis written AFTER the ledger entry cannot justify it."""
    st = state_with(R2_PDF_GUARDED, tool="r2")
    v = val(step_idx=5, source_step_idx=0,
            result="at 0x402010 the input is compared and the block accepts")
    late = type("H", (), {"step_idx": 9, "text": "the jne at 0x40200c is never taken"})()
    st.hypotheses.append(late)
    r = check_reachability(st, v)
    expect("L2: a later hypothesis does not retroactively repair an earlier validation",
           (not r.ok) and r.code == "guard_not_accounted_for")
    early = type("H", (), {"step_idx": 3, "text": "the jne at 0x40200c is never taken"})()
    st.hypotheses.append(early)
    r2_ = check_reachability(st, v)
    expect("L2: reasoning recorded before the validation does support it",
           r2_.ok and r2_.code == "guards_accounted_for")



def val(step_idx=5, source_step_idx=0, observation="", result="", candidate="CAND-0001"):
    return FakeValidation(step_idx=step_idx, source_step_idx=source_step_idx,
                          source_observation=observation, result=result, candidate=candidate)


# --- W10f regression: the four defects the two-task A2 pilot exposed -------------------------
# Gutter glyphs, column layout and the XREF annotation are copied from real r2 output; every
# symbol, address and constant below is invented for the test.

R2_STRIPPED_MAIN = """            ; DATA XREF from entry0 @ 0x4011a8
\u250c 217: fcn.00401500 (int64_t arg1, int64_t arg2);
\u2502           0x00401500      f30f1efa       endbr64
\u2502           0x00401508      83ff01         cmp edi, 1
\u2502       \u250c\u2500< 0x0040150b      0f8eaf000000   jle 0x4015c0
\u2502       \u2502   0x00401520      4839d0         cmp rax, rdx
\u2502      \u250c\u2500\u2500< 0x00401524      7213           jb 0x401540
\u2502      \u2502\u2502   0x00401530      e87fffffff     call sym.imp.strcmp
\u2502     \u250c\u2500\u2500\u2500< 0x00401538      744d           je 0x401590
\u2502     \u2502\u2514\u2500\u2500> 0x00401540      83fd18         cmp ebp, 0x18
\u2502     \u2502\u250c\u2500\u2500< 0x00401544      7530           jne 0x401580
\u2502     \u2502\u2502\u2502   0x00401548      31c0           xor eax, eax
"""


def test_symbol_prefix_normalisation():
    """DEFECT 1: r2 stores `sym.foo`; the agent writes `foo`. Raw comparison never matched, so the
    terminality layer fell through to fail-open on every r2 run -- i.e. it was inert."""
    pdf = "\u250c 33: sym.leaf_check (const char *s1);\n\u2502  0x00401240  f30f1efa  endbr64\n"
    st = state_with(pdf, tool="r2")
    t = check_consumer_observed(st, val(result="the leaf_check function compares the input"))
    expect("D1: bare name matches the sym.-prefixed symbol (layer is no longer inert)",
           t.code != "no_named_site")


def test_stripped_entry_frame():
    """DEFECT 2: on a stripped binary the main frame is `fcn.XXXX`, reached from entry0 via the
    loader, so it has no observed `call` -- requiring a consumer would block every stripped task."""
    st = state_with(R2_STRIPPED_MAIN, tool="r2")
    v = build_view(st)
    expect("D2: the loader-reached frame is recognised from the XREF annotation",
           "fcn.00401500" in v.entry_frames)
    t = check_consumer_observed(st, val(result="the loop in fcn.00401500 validates the input"), v)
    expect("D2: evidence in a stripped entry frame passes",
           t.ok and t.code == "evidence_in_entry_frame")


def test_cmp_address_accepted_for_guard():
    """DEFECT 3: the agent cites the comparison that sets the flags, not the jump that reads them."""
    st = state_with(R2_STRIPPED_MAIN, tool="r2")
    v = build_view(st)
    # names 0x401540 (the cmp) rather than 0x401544 (the jne)
    # Every guard is named by its COMPARISON address (0x401508 argc, 0x401540 length), never by the
    # jcc that follows it -- which is exactly how the agent wrote it in the pilot.
    r = check_reachability(st, val(result="cmp edi,1 at 0x401508 passes; jb at 0x401524 is taken; "
                                          "cmp ebp,0x18 at 0x401540 gates the loop at 0x401548"), v)
    expect("D3: naming the cmp counts as accounting for its jcc", r.ok)
    # and a guard nobody mentioned at all is still required
    r2_ = check_reachability(st, val(result="jb at 0x401524 is taken; cmp ebp,0x18 at 0x401540 gates "
                                            "the loop at 0x401548"), v)
    expect("D3: an entirely unmentioned guard is still demanded", not r2_.ok)


def test_skipped_arm_not_required():
    """DEFECT 4a: a guard inside an arm the agent showed is jumped over must not be required..."""
    st = state_with(R2_STRIPPED_MAIN, tool="r2")
    v = build_view(st)
    claimed = {0x401508, 0x401524, 0x401544, 0x401548}
    skipped = v.skipped_between(claimed, 0x401548)
    expect("D4a: the arm skipped by the taken forward jump is excused",
           0x401538 in skipped)


def test_skip_direction_is_not_inverted():
    """DEFECT 4b: ...but a forward jump does NOT excuse guards when the SITE lies inside the region
    it jumps over -- reaching the site there means the jump was not taken. The first draft had this
    backwards and silently excused almost every guard."""
    st = state_with(R2_STRIPPED_MAIN, tool="r2")
    v = build_view(st)
    # 0x40150b jumps to 0x4015c0; the site 0x401548 is INSIDE that region
    skipped = v.skipped_between({0x401508}, 0x401548)
    expect("D4b: a jump the site sits inside of excuses nothing",
           0x401524 not in skipped and 0x401538 not in skipped)
    # and an agent naming nothing is still blocked
    r = check_reachability(st, val(result="the block at 0x401548 compares the input"), v)
    expect("D4b: negative control -- naming no guard is still blocked",
           (not r.ok) and r.code == "guard_not_accounted_for")


def test_block_budget():
    """DEFECT 5: a gate that repeats the same objection the agent cannot satisfy is a dead end.
    In the pilot one run was blocked 7x on one code and died at the step limit with no submission."""
    st = state_with(R2_STRIPPED_MAIN, tool="r2")
    st.validation_ledger.append(val(step_idx=5, source_step_idx=0,
                                    result="the block at 0x401548 compares the input"))
    gate = LedgerScaffold(artifact=None, require_derivation=False, require_reachability=True,
                          max_blocks_per_reason=3)
    d = gate.validate(st, "CAND-0001")
    expect("D5: first proposal is blocked", not d.allowed)
    # simulate the prior blocks the loop would have recorded
    class B:
        def __init__(s_, v_, c): s_.value, s_.audit = v_, {"reason_code": c}
    st.blocked_submissions = [B("CAND-0001", "guard_not_accounted_for") for _ in range(3)]
    d2 = gate.validate(st, "CAND-0001")
    # v5: budget exhaustion ABSTAINS instead of failing open. Admitting a proposal whose objection
    # is still unmet produced, in the recorded battery, exactly the error the gate exists to prevent.
    expect("D5: once the budget is spent the gate ABSTAINS (never fails open)",
           (not d2.allowed) and d2.audit["reason_code"] == "abstained_on_block_budget")
    expect("D5: the audit records that it was allowed on budget, not on merit",
           d2.audit["levels"]["budget_exhausted"]["prior_blocks"] == 3)
    expect("D5: a DIFFERENT candidate does not inherit the spent budget",
           gate.validate(st, "CAND-0002").audit["reason_code"] != "abstained_on_block_budget")



def main() -> int:
    # --- view construction ---
    view = build_view(state_with(DISASM_NO_CALLER))
    expect("view: function labels recovered", set(view.func_at.values()) ==
           {"helper_cmp", "main", "other_gate"})
    expect("view: call targets recovered", "other_gate" in view.call_targets)
    expect("view: conditional jumps recorded", any(m == "je" for _, m, _ in view.cond_jumps))
    expect("view: unconditional jmp is NOT a guard", all(m != "jmp" for _, m, _ in view.cond_jumps))

    # --- LEVEL 1: terminality ---
    st = state_with(DISASM_NO_CALLER)
    v = val(result="helper_cmp compares the input against the stored value and returns 1 on a match")
    t = check_consumer_observed(st, v)
    expect("L1: routine with no observed consumer is blocked", (not t.ok) and t.code == "no_consumer_observed")

    st2 = state_with(DISASM_WITH_CALLER)
    t2 = check_consumer_observed(st2, val(result="helper_cmp compares the input and its result is what the caller consumes"))
    expect("L1: an observed call site satisfies the layer", t2.ok and t2.code == "consumer_observed")

    t3 = check_consumer_observed(state_with(DISASM_NO_CALLER),
                           val(result="the comparison in main decides the outcome"))
    expect("L1: evidence in the entry frame passes (nothing calls main)",
           t3.ok and t3.code == "evidence_in_entry_frame")

    t4 = check_consumer_observed(state_with(DISASM_NO_CALLER), val(result="the value is compared somewhere"))
    expect("L1: fail-open when the evidence names no routine",
           t4.ok and t4.code == "no_named_site")

    # --- LEVEL 2: reachability ---
    stg = state_with(DISASM_GUARDED)
    r = check_reachability(stg, val(result="at 0x402010 the input is compared and the block accepts"))
    expect("L2: a guarded site with an unmentioned guard is blocked",
           (not r.ok) and r.code == "guard_not_accounted_for")
    expect("L2: the block names the controlling conditional it wants argued",
           any(g["addr"] == "0x40200c" for u in r.detail["unaccounted"] for g in u["guards"]))

    r2 = check_reachability(
        stg, val(result="the jne at 0x40200c is taken unless the length check passes; then 0x402010 runs"))
    expect("L2: referencing the controlling conditional satisfies the layer",
           r2.ok and r2.code == "guards_accounted_for")

    r3 = check_reachability(state_with(DISASM_NO_CALLER), val(result="helper_cmp does the comparison"))
    expect("L2: fail-open when the evidence locates no address",
           r3.ok and r3.code == "no_located_site")

    # --- wiring into the gate ---
    st3 = state_with(DISASM_NO_CALLER)
    ledger_v = val(step_idx=5, source_step_idx=0,
                   result="helper_cmp compares the input against the stored value")
    st3.validation_ledger.append(ledger_v)

    off = LedgerScaffold(artifact=None, require_derivation=False)
    d_off = off.validate(st3, "CAND-0001")
    expect("gate: levels are OFF by default (submission allowed)", d_off.allowed)
    expect("gate: level verdicts are recorded in shadow anyway",
           d_off.audit["levels"]["terminality"]["code"] == "no_consumer_observed")
    expect("gate: shadow verdict is marked unenforced",
           d_off.audit["levels"]["terminality"]["enforced"] is False)

    on = LedgerScaffold(artifact=None, require_derivation=False, require_terminality=True)
    d_on = on.validate(st3, "CAND-0001")
    expect("gate: level 1 blocks when switched on", not d_on.allowed)
    expect("gate: level 1 block carries the terminality reason", "consumer" in d_on.reason)
    expect("gate: audit marks the layer enforced",
           d_on.audit["levels"]["terminality"]["enforced"] is True)

    st4 = state_with(DISASM_GUARDED)
    st4.validation_ledger.append(val(step_idx=5, source_step_idx=0,
                                     result="at 0x402010 the input is compared and the block accepts"))
    on2 = LedgerScaffold(artifact=None, require_derivation=False, require_reachability=True)
    d2 = on2.validate(st4, "CAND-0001")
    expect("gate: level 2 blocks an unargued guarded site when switched on", not d2.allowed)
    expect("gate: level 2 block carries the reachability reason", "conditional" in d2.reason)

    expect("gate: version bumped for the new layers",
           d2.audit["gate_version"] == "derivation-v5")

    test_r2_formats()
    test_bounded_control_dependence()
    test_no_retroactive_repair()




    test_symbol_prefix_normalisation()
    test_stripped_entry_frame()
    test_cmp_address_accepted_for_guard()
    test_skipped_arm_not_required()
    test_skip_direction_is_not_inverted()
    test_block_budget()

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    print(f"DERIVATION-CHECK TEST: {'PASSED' if not fails else 'FAILED'} "
          f"({len(checks)} checks, {len(fails)} failed)")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
