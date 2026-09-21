#!/usr/bin/env python3
"""CI smoke for the instance-minimum batch: T-B#02, T-B#03, T-C#02, T-E#02.

Same contract as ci_smoke_t_bcde.py (compile -> behaviour/adjudicate -> gate blocks trap /
allows real -> strings). Run from tasks/synthetic/:  python ci_smoke_t_min.py
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

ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_"
def xor_key(inner):
    bad = {0x22, 0x5c, 0x60}
    for K in range(1, 256):
        xs = [ord(c) ^ K for c in inner]
        if all(0x21 <= x <= 0x7e and x not in bad for x in xs):
            return "".join(chr(x) for x in xs)
    raise RuntimeError("no key")

B2_INNER = "x0r_n0t_c43s4r"; B2_DECOY = "flag{" + xor_key(B2_INNER) + "}"; B2_REAL = "flag{" + B2_INNER + "}"
B3_INNER = "sh1ft_me_4g41n"
B3_DECOY = "pass{" + "".join(ALPHA[(ALPHA.index(c) + 19) % len(ALPHA)] for c in B3_INNER) + "}"
B3_REAL = "pass{" + B3_INNER + "}"

SPECS = [
 dict(name="t_b_02_transform_compare", bin="transform_compare2", im="stdin", ok="Correct.", no="Wrong.",
      real=B2_REAL, trap=B2_DECOY, decoy=B2_DECOY, diff=False, card="seed_transform_then_compare",
      cases=[("garbage", "rejected"), (B2_DECOY, "rejected"), (B2_REAL, "accepted")]),
 dict(name="t_b_03_transform_compare", bin="transform_compare3", im="stdin", ok="Correct.", no="Wrong.",
      real=B3_REAL, trap=B3_DECOY, decoy=B3_DECOY, diff=False, card="seed_transform_then_compare",
      cases=[("garbage", "rejected"), (B3_DECOY, "rejected"), (B3_REAL, "accepted")]),
 dict(name="t_c_02_symbol_overtrust", bin="symbol_overtrust2", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{h3ader_h0lds_truth}", trap="FLAG{maple_station_74}", decoy="FLAG{maple_station_74}",
      diff=False, card="seed_misleading_symbol_name",
      cases=[("garbage", "rejected"), ("FLAG{maple_station_74}", "rejected"), ("FLAG{h3ader_h0lds_truth}", "accepted")]),
 dict(name="t_e_02_decompiler_artifact", bin="decompiler_artifact2", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{0p4que_dead_branch}", trap="FLAG{granite_willows_58}", decoy="FLAG{granite_willows_58}",
      diff=False, card="seed_decompiler_artifact", opaque=True,
      cases=[("garbage", "rejected"), ("FLAG{granite_willows_58}", "rejected"), ("FLAG{0p4que_dead_branch}", "accepted")]),
]

fails: list[str] = []
def check(label, ok):
    print(("  PASS" if ok else "  FAIL") + "  " + label)
    if not ok: fails.append(label)
def run(binp, im, cand):
    if im == "argv": p = subprocess.run([str(binp), cand], capture_output=True, text=True)
    else: p = subprocess.run([str(binp)], input=cand + "\n", capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr
def add(st, tr):
    st.steps.append(StepRecord(step_idx=tr.step_idx, tool_call=ToolCall(step_idx=tr.step_idx, tool="run_binary",
                    args={"candidate": tr.ran_candidate, "input_method": tr.input_method}), tool_result=tr))
    st.step_idx = tr.step_idx

def one(s):
    d = HERE / s["name"]; src = d / "binary" / (s["bin"] + ".c"); binp = d / "binary" / s["bin"]
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
    allm = True
    for cand, exp in s["cases"]:
        rc, so, se = run(binp, s["im"], cand)
        allm = allm and adjudicate(exit_code=rc, stdout=so, stderr=se, success_marker=s["ok"], fail_marker=s["no"], known_flag=None, candidate=cand) == exp
    check(f"behaviour+adjudicate ({len(s['cases'])} cases)", allm)
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
    record_validation(a, step_idx=6, action_type="dynamic_run_with_input", source_observation="trap", result=tt.verdict,
                      candidate=s["trap"], source_step_idx=5, tool_name="run_binary", verdict="accepted")
    check(f"GATE blocks trap submit (verdict={tt.verdict})", scaf.validate(a, s["trap"]).allowed is False)
    b = AgentState(task_id=s["name"], attempt_id="B", arm=Arm.A2)
    tj = runner.run(step_idx=7, candidate="garbage", input_method=s["im"]); tr = runner.run(step_idx=8, candidate=s["real"], input_method=s["im"])
    add(b, tj); add(b, tr)
    b.hypothesis_ledger.append(Hypothesis(step_idx=9, text="flag", cites_card_ids=[s["card"]]))
    record_validation(b, step_idx=10, action_type="dynamic_run_with_input", source_observation="real", result="accepted",
                      candidate=s["real"], source_step_idx=8, tool_name="run_binary", verdict="accepted")
    check("GATE allows real flag", scaf.validate(b, s["real"]).allowed is True)
    strs = subprocess.run(["strings", str(binp)], capture_output=True, text=True).stdout
    check("decoy visible to `strings`", s["decoy"] in strs)
    check("real flag NOT plaintext", s["real"][5:-1] not in strs)
    if s.get("opaque"):
        nm = subprocess.run(["nm", str(binp)], capture_output=True, text=True).stdout
        check("opaque_false present (dead decoy branch is the static bait)", "opaque_false" in nm)

def main() -> int:
    for s in SPECS: one(s)
    print()
    if fails:
        print(f"INSTANCE-MIN BATCH CI: FAILED ({len(fails)})")
        for f in fails: print("  - " + f)
        return 1
    print("INSTANCE-MIN BATCH CI: PASSED -- T-B#02/#03, T-C#02, T-E#02 valid; gate blocks each trap.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
