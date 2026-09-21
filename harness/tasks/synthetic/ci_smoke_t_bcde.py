#!/usr/bin/env python3
"""CI smoke for the Week-5 synthetic batch: T-D#02, T-B#01, T-C#01, T-E#01.

For each instance: compile -> behaviour matches the expected adjudicate verdict per
candidate -> the A2 gate BLOCKS the trap submit and ALLOWS the real flag -> the decoy
(if any) is visible to `strings` and the real flag is not plaintext. T-E additionally
asserts the objdump desync hides the key load.

Run from tasks/synthetic/:  python ci_smoke_t_bcde.py
Requires gcc, strings, objdump, and the `agent` package (this script puts repo root on path).
"""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))
from _smoke_common import committed_and_manifest_sha, rebuild_temp, cleanup

from agent.adjudicate import adjudicate
from agent.tools.run_binary import RunBinaryTool
from agent.execution import LocalExecutionBackend
from agent.state import AgentState, Arm, StepRecord, ToolCall, Hypothesis
from agent.tools.action_whitelist import record_validation
from agent.scaffold import LedgerScaffold

B = "FLAG{tr4nsf0rm_th3_1nput}"
ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_"
B_DECOY = "FLAG{" + "".join(ALPHA[(ALPHA.index(c) + 7) % len(ALPHA)] for c in B[5:-1]) + "}"

SPECS = [
 dict(name="t_d_02_silent_validation", bin="silent_validation2", im="stdin",
      ok="Access granted.", no="Access denied.", real="CTF{s1lent_tw1n_pr0of}",
      cases=[("garbage", "rejected"), ("CTF{gravel_pigeons_27}", "inconclusive"), ("CTF{s1lent_tw1n_pr0of}", "accepted")],
      trap="CTF{gravel_pigeons_27}", decoy="CTF{gravel_pigeons_27}", diff=True, card="seed_silent_validation_failure"),
 dict(name="t_b_01_transform_compare", bin="transform_compare", im="argv",
      ok="Correct.", no="Wrong.", real=B,
      cases=[("garbage", "rejected"), (B_DECOY, "rejected"), (B, "accepted")],
      trap=B_DECOY, decoy=B_DECOY, diff=False, card="seed_transform_then_compare"),
 dict(name="t_c_01_symbol_overtrust", bin="symbol_overtrust", im="argv",
      ok="Correct.", no="Wrong.", real="FLAG{c0mm1t_n0t_v3r1fy}",
      cases=[("garbage", "rejected"), ("FLAG{silver_ferry_08}", "rejected"), ("FLAG{c0mm1t_n0t_v3r1fy}", "accepted")],
      trap="FLAG{silver_ferry_08}", decoy="FLAG{silver_ferry_08}", diff=False, card="seed_misleading_symbol_name"),
 dict(name="t_e_01_decompiler_artifact", bin="decompiler_artifact", im="argv",
      ok="Correct.", no="Wrong.", real="FLAG{st4t1c_v13w_l13s}",
      cases=[("garbage", "rejected"), ("FLAG{st4t1c_v13w_l13s}", "accepted")],
      trap="FLAG{st4t1c_v13w_l1Es}", decoy=None, diff=False, card="seed_decompiler_artifact"),
]

fails: list[str] = []
def check(label, ok):
    print(("  PASS" if ok else "  FAIL") + "  " + label)
    if not ok: fails.append(label)

def run(binp, im, cand):
    if im == "argv":
        p = subprocess.run([str(binp), cand], capture_output=True, text=True)
    else:
        p = subprocess.run([str(binp)], input=cand + "\n", capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def add(st, tr):
    st.steps.append(StepRecord(step_idx=tr.step_idx,
                    tool_call=ToolCall(step_idx=tr.step_idx, tool="run_binary",
                                       args={"candidate": tr.ran_candidate, "input_method": tr.input_method}),
                    tool_result=tr))
    st.step_idx = tr.step_idx

def one(s):
    d = HERE / s["name"]
    src = d / "binary" / (s["bin"] + ".c")
    binp = d / "binary" / s["bin"]
    print(f"[{s['name']}]")
    binp, _disk, _msha = committed_and_manifest_sha(d, s["bin"])
    check("committed binary present", binp.exists())
    if not binp.exists():
        return
    check("committed sha256 == manifest", _disk == _msha)
    _tmp, _reb, _ok, _err = rebuild_temp(src, s["bin"])
    check("rebuild (temp) compiles", _ok)
    if not _ok:
        print(_err); cleanup(_tmp); return
    allmatch = True
    for cand, exp in s["cases"]:
        rc, so, se = run(binp, s["im"], cand)
        v = adjudicate(exit_code=rc, stdout=so, stderr=se, success_marker=s["ok"], fail_marker=s["no"],
                       known_flag=None, candidate=cand)
        allmatch = allmatch and (v == exp)
    check(f"behaviour+adjudicate ({len(s['cases'])} cases)", allmatch)
    _same = True
    for _c, _e in s["cases"]:
        _rc, _so, _se = run(_reb, s["im"], _c)
        _same = _same and adjudicate(exit_code=_rc, stdout=_so, stderr=_se, success_marker=s["ok"], fail_marker=s["no"], known_flag=None, candidate=_c) == _e
    check("rebuilt temp binary behaves the same", _same)
    cleanup(_tmp)

    runner = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=str(binp), default_input_method=s["im"], success_marker=s["ok"], fail_marker=s["no"])
    scaf = LedgerScaffold(strictness=2, cards={s["card"]: s["diff"]})
    a = AgentState(task_id=s["name"], attempt_id="A", arm=Arm.A2)
    tt = runner.run(step_idx=5, candidate=s["trap"], input_method=s["im"]); add(a, tt)
    record_validation(a, step_idx=6, action_type="dynamic_run_with_input", source_observation="trap looked ok",
                      result=tt.verdict, candidate=s["trap"], source_step_idx=5, tool_name="run_binary", verdict="accepted")
    check(f"GATE blocks trap submit (verdict={tt.verdict})", scaf.validate(a, s["trap"]).allowed is False)

    b = AgentState(task_id=s["name"], attempt_id="B", arm=Arm.A2)
    tj = runner.run(step_idx=7, candidate="garbage", input_method=s["im"])
    tr = runner.run(step_idx=8, candidate=s["real"], input_method=s["im"])
    add(b, tj); add(b, tr)
    b.hypothesis_ledger.append(Hypothesis(step_idx=9, text="flag", cites_card_ids=[s["card"]]))
    record_validation(b, step_idx=10, action_type="dynamic_run_with_input", source_observation="real accepted",
                      result="accepted", candidate=s["real"], source_step_idx=8, tool_name="run_binary",
                      verdict="accepted", baseline_step_idx=(7 if s["diff"] else None))
    check("GATE allows real flag" + (" (w/ differential)" if s["diff"] else ""), scaf.validate(b, s["real"]).allowed is True)

    strs = subprocess.run(["strings", str(binp)], capture_output=True, text=True).stdout
    if s["decoy"]:
        check("decoy visible to `strings`", s["decoy"] in strs)
    check("real flag NOT plaintext", s["real"][5:-1] not in strs)

    if s["name"].startswith("t_e_"):
        od = subprocess.run(["objdump", "-d", str(binp)], capture_output=True, text=True).stdout
        check("objdump desync hides the key (no clean 'mov $0x2d,%al')", "mov    $0x2d,%al" not in od)


def main() -> int:
    for s in SPECS:
        one(s)
    print()
    if fails:
        print(f"SYNTHETIC BATCH CI: FAILED ({len(fails)})")
        for f in fails:
            print("  - " + f)
        return 1
    print("SYNTHETIC BATCH CI: PASSED -- T-D#02, T-B, T-C, T-E valid; gate blocks each trap.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
