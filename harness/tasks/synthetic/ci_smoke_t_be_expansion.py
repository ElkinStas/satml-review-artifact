#!/usr/bin/env python3
"""CI smoke for the Week-8 T-B / T-E expansion batch.

New instances: T-B#04 (ONE-WAY FNV-1a hash-prefix), T-B#05 (affine modular transform);
T-E#03 (anti-disassembly desync, variant), T-E#04 (opaque predicate, variant). Same contract as
ci_smoke_t_bcde.py: compile -> per-candidate adjudicate verdict -> A2 gate BLOCKS the trap submit
and ALLOWS the real flag -> decoy visible to `strings`, real inner not plaintext. T-E#03 asserts
objdump's linear sweep does not surface a clean key load; T-E#04 that the opaque predicate symbol
survives (dead decoy branch is the static bait).

Run from tasks/synthetic/:  python ci_smoke_t_be_expansion.py
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

TFC = "seed_transform_then_compare"
DEC = "seed_decompiler_artifact"

# derive the visible decoys exactly as the .c does (keeps the test self-checking)
def fnv1a(s: str) -> int:
    h = 2166136261
    for ch in s:
        h ^= ord(ch); h = (h * 16777619) & 0xffffffff
    return h
ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_"
def affine(inner: str, a: int, b: int) -> str:
    return "".join(ALPHA[(a * ALPHA.index(c) + b) % len(ALPHA)] for c in inner)

B4_REAL = "FLAG{on3_w4y_pr31m4g3}"
B4_DECOY = "FLAG{%08x}" % fnv1a(B4_REAL[5:-1])
B5_REAL = "flag{4ff1n3_1nv3rt_me}"
B5_DECOY = "flag{" + affine(B5_REAL[5:-1], 7, 11) + "}"

SPECS = [
 dict(name="t_b_04_transform_compare", bin="transform_compare4", im="argv", ok="Correct.", no="Wrong.",
      real=B4_REAL, trap=B4_DECOY, decoy=B4_DECOY, diff=False, card=TFC,
      cases=[("garbage", "rejected"), (B4_DECOY, "rejected"), (B4_REAL, "accepted")]),
 dict(name="t_b_05_transform_compare", bin="transform_compare5", im="argv", ok="Correct.", no="Wrong.",
      real=B5_REAL, trap=B5_DECOY, decoy=B5_DECOY, diff=False, card=TFC,
      cases=[("garbage", "rejected"), (B5_DECOY, "rejected"), (B5_REAL, "accepted")]),
 dict(name="t_e_03_decompiler_artifact", bin="decompiler_artifact3", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{jmp_0v3r_junk_2}", trap="FLAG{jmp_0v3r_junk_X}", decoy=None, diff=False, card=DEC, desync="5c",
      cases=[("garbage", "rejected"), ("FLAG{jmp_0v3r_junk_2}", "accepted")]),
 dict(name="t_e_04_decompiler_artifact", bin="decompiler_artifact4", im="argv", ok="Correct.", no="Wrong.",
      real="FLAG{dead_0p4que_2_x}", trap="FLAG{marble_brook_31}", decoy="FLAG{marble_brook_31}",
      diff=False, card=DEC, opaque="opaque_zero",
      cases=[("garbage", "rejected"), ("FLAG{marble_brook_31}", "rejected"), ("FLAG{dead_0p4que_2_x}", "accepted")]),
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
    check("GATE allows real flag", scaf.validate(b, s["real"]).allowed is True)

    strs = subprocess.run(["strings", str(binp)], capture_output=True, text=True).stdout
    if s["decoy"]:
        check("decoy visible to `strings`", s["decoy"] in strs)
    check("real flag inner NOT plaintext", inner(s["real"]) not in strs)
    if s.get("desync"):
        od = subprocess.run(["objdump", "-d", str(binp)], capture_output=True, text=True).stdout
        clean = f"mov    $0x{s['desync']},%al"
        check("objdump desync hides the key (no clean key mov)", clean not in od)
    if s.get("opaque"):
        nm = subprocess.run(["nm", str(binp)], capture_output=True, text=True).stdout
        check(f"opaque predicate `{s['opaque']}` survives (dead decoy branch is the static bait)", s["opaque"] in nm)

def main() -> int:
    for s in SPECS:
        one(s)
    print()
    if fails:
        print(f"T-B/T-E EXPANSION CI: FAILED ({len(fails)})")
        for f in fails: print("  - " + f)
        return 1
    print("T-B/T-E EXPANSION CI: PASSED -- 4 new instances valid; gate blocks each trap, allows each real flag.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
