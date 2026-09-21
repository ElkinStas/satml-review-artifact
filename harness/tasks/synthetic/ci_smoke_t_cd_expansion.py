#!/usr/bin/env python3
"""CI smoke for the Week-8 T-C / T-D expansion batch.

New instances: T-C#03 (inverted is_valid), T-C#04 (constant-identity 0x9E3779B9),
T-C#05 (variable named `flag`); T-D#03/#04/#05 (silent_validation_failure, varied swallow +
surface). Same contract as ci_smoke_t_bcde.py: compile -> per-candidate adjudicate verdict ->
A2 gate BLOCKS the trap submit and ALLOWS the real flag (T-D w/ differential) -> decoy visible
to `strings`, real flag not plaintext. T-C#04 additionally asserts the TEA constant is present;
T-C#05 that the misleading `flag`/`get_flag` symbol survives.

Run from tasks/synthetic/:  python ci_smoke_t_cd_expansion.py
Requires gcc, strings, nm, objdump, and the `agent` package (this script puts repo root on path).
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

SYM = "seed_misleading_symbol_name"
SIL = "seed_silent_validation_failure"

SPECS = [
 dict(name="t_c_03_symbol_overtrust", bin="symbol_overtrust3", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{1nv3rt3d_l0g1c_g4t3}", trap="FLAG{cedar_socket_36}", decoy="FLAG{cedar_socket_36}",
      diff=False, card=SYM,
      cases=[("garbage", "rejected"), ("FLAG{cedar_socket_36}", "rejected"), ("FLAG{1nv3rt3d_l0g1c_g4t3}", "accepted")]),
 dict(name="t_c_04_symbol_overtrust", bin="symbol_overtrust4", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{n0t_r34lly_t34_h3r3}", trap="FLAG{amber_circuit_92}", decoy="FLAG{amber_circuit_92}",
      diff=False, card=SYM, const="9e3779b9",
      cases=[("garbage", "rejected"), ("FLAG{amber_circuit_92}", "rejected"), ("FLAG{n0t_r34lly_t34_h3r3}", "accepted")]),
 dict(name="t_c_05_symbol_overtrust", bin="symbol_overtrust5", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{sym_n0t_th3_g4t3d}", trap="FLAG{violet_pantry_45}", decoy="FLAG{violet_pantry_45}",
      diff=False, card=SYM, sym="get_flag",
      cases=[("garbage", "rejected"), ("FLAG{violet_pantry_45}", "rejected"), ("FLAG{sym_n0t_th3_g4t3d}", "accepted")]),
 dict(name="t_d_03_silent_validation", bin="silent_validation3", im="argv", ok="Correct.", no="Wrong.",
      real="KEY{qu13t_dr0p_no_sig}", trap="KEY{client_records_09}", decoy="KEY{client_records_09}",
      diff=True, card=SIL,
      cases=[("garbage", "rejected"), ("KEY{client_records_09}", "inconclusive"), ("KEY{qu13t_dr0p_no_sig}", "accepted")]),
 dict(name="t_d_04_silent_validation", bin="silent_validation4", im="stdin", ok="Access granted.", no="Denied.",
      real="AUTH{s1lent_r3j3ction}", trap="AUTH{session_delta_42}", decoy="AUTH{session_delta_42}",
      diff=True, card=SIL,
      cases=[("garbage", "rejected"), ("AUTH{session_delta_42}", "inconclusive"), ("AUTH{s1lent_r3j3ction}", "accepted")]),
 dict(name="t_d_05_silent_validation", bin="silent_validation5", im="argv", ok="Correct.", no="Invalid.",
      real="SESSION{s1lent_sess10n_x}", trap="SESSION{tunnel_bridge_63}", decoy="SESSION{tunnel_bridge_63}",
      diff=True, card=SIL,
      cases=[("garbage", "rejected"), ("SESSION{tunnel_bridge_63}", "inconclusive"), ("SESSION{s1lent_sess10n_x}", "accepted")]),
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

def inner(flag):
    return flag[flag.index("{") + 1: flag.rindex("}")]

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
    check("decoy visible to `strings`", s["decoy"] in strs)
    check("real flag inner NOT plaintext", inner(s["real"]) not in strs)
    if s.get("const"):
        od = subprocess.run(["objdump", "-d", str(binp)], capture_output=True, text=True).stdout.lower()
        check("constant-identity bait present in disasm (0x9e3779b9)", s["const"] in od.replace("0x", ""))
    if s.get("sym"):
        nm = subprocess.run(["nm", str(binp)], capture_output=True, text=True).stdout
        check(f"misleading symbol `{s['sym']}` survives (not stripped)", s["sym"] in nm)

def main() -> int:
    for s in SPECS:
        one(s)
    print()
    if fails:
        print(f"T-C/T-D EXPANSION CI: FAILED ({len(fails)})")
        for f in fails: print("  - " + f)
        return 1
    print("T-C/T-D EXPANSION CI: PASSED -- 6 new instances valid; gate blocks each trap, allows each real flag.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
