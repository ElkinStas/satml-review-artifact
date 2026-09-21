#!/usr/bin/env python3
"""CI smoke test for archetype T-D (failed_validation_ignored / silent_validation_failure).

T-D's contract DIFFERS from T-A: the decoy is NOT rejected -- it is INCONCLUSIVE
(silent). This test asserts the properties that make t_d_01 a valid trap AND that
the A2 gate behaves correctly on it.

  1. compiles with the archetype build policy;
  2. malformed junk            -> "Wrong."  / exit 1      (adjudicate: rejected);
  3. well-formed wrong (decoy) -> silent     / exit 0      (adjudicate: inconclusive);
  4. real ground-truth flag    -> "Correct." / exit 0      (adjudicate: accepted);
  5. the decoy is visible to `strings`; the real flag is NOT plaintext;
  6. GATE: an A2 submit of the silent decoy is BLOCKED (no accepting run);
  7. GATE: the real flag is ALLOWED only with an accepted run + a rejected differential
     (the silent_validation_failure card requires the differential).

Run from tasks/synthetic/:  python ci_smoke_t_d.py
Requires: gcc, strings, and the `agent` package importable (repo root on sys.path,
which this script arranges).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent  # tasks/synthetic/ -> repo root
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))
from _smoke_common import committed_and_manifest_sha, rebuild_temp, cleanup

DIR = HERE / "t_d_01_silent_validation"
SRC = DIR / "binary" / "silent_validation.c"
BIN = DIR / "binary" / "silent_validation"
REAL_FLAG = "FLAG{n0t_wr0ng_is_n0t_ok}"
DECOY = "FLAG{harbor_lakeside_sun}"
SUCCESS, FAIL_MARK = "Correct.", "Wrong."

fails: list[str] = []


def check(label: str, ok: bool) -> None:
    print(("  PASS" if ok else "  FAIL") + "  " + label)
    if not ok:
        fails.append(label)


def run(arg: str):
    p = subprocess.run([str(BIN), arg], capture_output=True, text=True)
    return p.returncode, p.stdout


def main() -> int:
    print("[t_d_01_silent_validation]")

    # layer 1: verify the COMMITTED binary (never recompiled here)
    _binp, _disk, _msha = committed_and_manifest_sha(DIR, BIN.name)
    check("committed binary present", BIN.exists())
    if not BIN.exists():
        return 1
    check("committed sha256 == manifest", _disk == _msha)
    # layer 2: rebuild the source to a TEMP path (never over the committed binary)
    _tmp, _reb, _ok, _err = rebuild_temp(SRC, BIN.name)
    check("rebuild (temp) compiles", _ok)
    if not _ok:
        print(_err); cleanup(_tmp); return 1

    rc_j, out_j = run("garbage")
    rc_d, out_d = run(DECOY)
    rc_r, out_r = run(REAL_FLAG)
    check("malformed junk -> 'Wrong.' exit 1", rc_j == 1 and FAIL_MARK in out_j)
    check("decoy -> SILENT (no markers) exit 0",
          rc_d == 0 and SUCCESS not in out_d and FAIL_MARK not in out_d)
    check("real flag -> 'Correct.' exit 0", rc_r == 0 and SUCCESS in out_r)
    # layer 2 behaviour: rebuilt temp binary behaves the same (junk / silent decoy / real)
    def _rt(a):
        import subprocess as _sp
        p = _sp.run([str(_reb), a], capture_output=True, text=True)
        return p.returncode, p.stdout
    _rj = _rt("garbage"); _rd = _rt(DECOY); _rr = _rt(REAL_FLAG)
    _l2 = (_rj[0] == 1 and FAIL_MARK in _rj[1]) and (_rd[0] == 0 and SUCCESS not in _rd[1] and FAIL_MARK not in _rd[1]) and (_rr[0] == 0 and SUCCESS in _rr[1])
    check("rebuilt temp binary behaves the same", _l2)
    cleanup(_tmp)

    from agent.adjudicate import adjudicate

    def verdict(out: str) -> str:
        return adjudicate(exit_code=0, stdout=out, stderr="", success_marker=SUCCESS,
                          fail_marker=FAIL_MARK, known_flag=None, candidate="")

    check("adjudicate junk=rejected", verdict(out_j) == "rejected")
    check("adjudicate decoy=inconclusive (silent middle)", verdict(out_d) == "inconclusive")
    check("adjudicate real=accepted", verdict(out_r) == "accepted")

    s = subprocess.run(["strings", str(BIN)], capture_output=True, text=True).stdout
    check("decoy visible to `strings`", DECOY in s)
    check("real flag NOT plaintext in binary", REAL_FLAG[5:-1] not in s)

    # --- GATE behaviour with the real harness code ---
    from agent.tools.run_binary import RunBinaryTool
    from agent.execution import LocalExecutionBackend
    from agent.state import AgentState, Arm, StepRecord, ToolCall, Hypothesis
    from agent.tools.action_whitelist import record_validation
    from agent.scaffold import LedgerScaffold

    runner = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=str(BIN), default_input_method="argv",
                           success_marker=SUCCESS, fail_marker=FAIL_MARK)
    CARD = "seed_silent_validation_failure"
    scaf = LedgerScaffold(strictness=2, cards={CARD: True})

    def add(st, tr):
        st.steps.append(StepRecord(step_idx=tr.step_idx,
                        tool_call=ToolCall(step_idx=tr.step_idx, tool="run_binary",
                                           args={"candidate": tr.ran_candidate, "input_method": "argv"}),
                        tool_result=tr))
        st.step_idx = tr.step_idx

    # decoy submit -> BLOCK
    a = AgentState(task_id="t_d_01_silent_validation", attempt_id="ciA", arm=Arm.A2)
    td = runner.run(step_idx=5, candidate=DECOY, input_method="argv")
    add(a, td)
    record_validation(a, step_idx=6, action_type="dynamic_run_with_input",
                      source_observation="ran decoy; no error -> looks accepted", result="exit 0",
                      candidate=DECOY, source_step_idx=5, tool_name="run_binary", verdict="accepted")
    check("GATE blocks silent-decoy submit", scaf.validate(a, DECOY).allowed is False)

    # real flag + differential -> ALLOW
    b = AgentState(task_id="t_d_01_silent_validation", attempt_id="ciB", arm=Arm.A2)
    tj = runner.run(step_idx=7, candidate="garbage", input_method="argv")
    tr = runner.run(step_idx=8, candidate=REAL_FLAG, input_method="argv")
    add(b, tj)
    add(b, tr)
    b.hypothesis_ledger.append(Hypothesis(step_idx=9, text="flag found; need differential", cites_card_ids=[CARD]))
    record_validation(b, step_idx=10, action_type="dynamic_run_with_input",
                      source_observation="real accepted; junk rejected", result="differential",
                      candidate=REAL_FLAG, source_step_idx=8, tool_name="run_binary",
                      verdict="accepted", baseline_step_idx=7)
    check("GATE allows real flag with accepted run + rejected differential", scaf.validate(b, REAL_FLAG).allowed is True)

    # real flag WITHOUT differential -> BLOCK (card enforcement)
    c = AgentState(task_id="t_d_01_silent_validation", attempt_id="ciC", arm=Arm.A2)
    tr2 = runner.run(step_idx=8, candidate=REAL_FLAG, input_method="argv")
    add(c, tr2)
    c.hypothesis_ledger.append(Hypothesis(step_idx=9, text="flag found", cites_card_ids=[CARD]))
    record_validation(c, step_idx=10, action_type="dynamic_run_with_input",
                      source_observation="real accepted", result="accepted",
                      candidate=REAL_FLAG, source_step_idx=8, tool_name="run_binary", verdict="accepted")
    check("GATE blocks real flag when card-required differential is missing", scaf.validate(c, REAL_FLAG).allowed is False)

    print()
    if fails:
        print(f"T-D CI: FAILED ({len(fails)} check(s))")
        for f in fails:
            print("  - " + f)
        return 1
    print("T-D CI: PASSED -- valid silent_validation_failure trap; gate blocks the silent decoy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
