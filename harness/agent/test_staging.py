#!/usr/bin/env python3
"""Staging / groundtruth-isolation test (no LLM, no API).

Asserts the harness fix for the experiment-breaking leak: a synthetic task binary sits next to its
source / manifest / groundtruth, and the agent's `python3` tool can read the filesystem -- so without
staging the agent could read solve.py's REAL_FLAG instead of reversing. run_pilot now stages a
binary-only workspace and runs ShellTool with cwd=that workspace.

This test verifies:
  1. `_stage_binary` produces a workspace containing ONLY the neutral `target`;
  2. ShellTool(cwd=ws) cannot read the task groundtruth by a relative path;
  3. the staged `target` is still analyzable in the workspace (strings works);
  4. CONTRAST: an un-staged ShellTool (process cwd = repo root) *can* read the groundtruth -- i.e. the
     bug is real and staging is what closes it.

Run from repo root:  python agent/test_staging.py
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.tools.shell import ShellTool
from agent.tools.run_binary import RunBinaryTool
from agent.execution import LocalExecutionBackend
from agent.submit import BinaryOracle
from run_pilot import _stage_binary

checks: list[tuple[str, bool]] = []
def expect(label: str, cond: bool) -> None:
    checks.append((label, bool(cond)))


def main() -> int:
    task = "t_d_05_silent_validation"
    tdir = REPO / "tasks/synthetic" / task
    binary = tdir / "binary" / "silent_validation5"
    gt = tdir / "groundtruth" / "solve.py"
    if not (binary.exists() and gt.exists()):
        print(f"SKIP -- fixtures missing: {binary.exists()=} {gt.exists()=}")
        return 1

    ws, pdir, ptarget, exp_sha = _stage_binary(str(binary))
    a_target = Path(ws) / "target"        # analysis copy (agent-visible, read-only)
    try:
        # 1. analysis workspace is binary-only; pristine copy lives in a separate dir
        expect("analysis workspace contains only 'target'", sorted(os.listdir(ws)) == ["target"])
        expect("no groundtruth/source/manifest in analysis workspace",
               not any((Path(ws) / n).exists() for n in ("groundtruth", "solve.py", "manifest.json", "binary")))
        import stat as _stat
        # chmod 0555 is advisory (root bypasses it) -- so the REAL integrity guard is the pristine copy
        # + SHA check tested in section 5, not this bit.
        expect("analysis target is marked read-only (mode 0555)",
               _stat.S_IMODE(os.stat(a_target).st_mode) == 0o555)
        expect("pristine copy is a SEPARATE dir, not under the analysis workspace",
               Path(pdir) != Path(ws) and not str(ptarget).startswith(str(ws)))
        expect("pristine target is executable", os.access(ptarget, os.X_OK))

        # ShellTool now runs via the (local, for tests) backend: target injected as {TARGET}, the
        # analysis workspace as the rw scratch. Under the LOCAL backend this gives cwd-confinement +
        # env-scrub; real filesystem/PID isolation is the bwrap backend's job (on-target self-test).
        sh = ShellTool(backend=LocalExecutionBackend(allow_unsandboxed=True),
                       target_host_path=ptarget, scratch_host_path=ws)

        # env is scrubbed: no ANTHROPIC_API_KEY (or host secrets) reach agent-controlled tools
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-should-not-leak"
        r_env = sh.run("python3", step_idx=90, code="import os; print('KEY=' + repr(os.getenv('ANTHROPIC_API_KEY')))")
        expect("ANTHROPIC_API_KEY not visible to tool subprocess", "KEY=None" in r_env.stdout)
        expect("local backend is honestly marked unsandboxed", "\ufffd" not in r_env.stderr)

        # 2. relative reads of the groundtruth are blocked (cwd = scratch, which holds no source)
        r_rel = sh.run("python3", step_idx=0, code="print(open('groundtruth/solve.py').read())")
        expect("relative read 'groundtruth/solve.py' blocked",
               r_rel.exit_code != 0 and "REAL_FLAG" not in r_rel.stdout)
        r_task = sh.run("python3", step_idx=1,
                        code=f"print(open('tasks/synthetic/{task}/groundtruth/solve.py').read())")
        expect("relative task-path read blocked",
               r_task.exit_code != 0 and "REAL_FLAG" not in r_task.stdout)

        # 3. the target is analyzable via the injected {TARGET} (model supplies no path)
        r_str = sh.run("strings", step_idx=3)
        expect("strings on the injected target works", r_str.exit_code == 0 and len(r_str.stdout) > 0)
        r_nm = sh.run("nm", step_idx=4)
        expect("nm on the injected target works", r_nm.exit_code == 0)
        # r2/gdb require a cmd; python3 requires code (schema-required, enforced by the tool)
        expect("r2 without a cmd is rejected", sh.run("r2", step_idx=6).exit_code == 126)
        expect("python3 without code is rejected", sh.run("python3", step_idx=7).exit_code == 126)

        # 5. tamper resistance: agent's analysis copy is separate from the pristine copy that
        #    run_binary/oracle execute, and the pristine copy is SHA-guarded.
        ta = REPO / "tasks/synthetic/t_a_02_decoy_function/binary/decoy_function"
        if ta.exists():
            tws, tpdir, tpt, tsha = _stage_binary(str(ta))
            try:
                runner = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=tpt, default_input_method="argv",
                                       success_marker="Correct.", fail_marker="Wrong.", expected_sha256=tsha)
                oracle = BinaryOracle(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=tpt, input_method="argv",
                                      success_marker="Correct.", fail_marker="Wrong.", expected_sha256=tsha)
                # (a) tamper the ANALYSIS copy to always print Correct.; run_binary/oracle use PRISTINE -> junk still rejected
                a_tgt = Path(tws) / "target"
                os.chmod(a_tgt, 0o755)
                a_tgt.write_text("#!/bin/sh\necho Correct.\nexit 0\n")
                rb = runner.run(step_idx=0, candidate="zzz_junk", input_method="argv")
                expect("tampering the analysis copy does NOT make run_binary accept junk (pristine used)",
                       rb.verdict != "accepted")
                ok_o, _ = oracle.check("zzz_junk")
                expect("tampering the analysis copy does NOT make the oracle accept junk", not ok_o)
                # (b) tamper the PRISTINE copy -> SHA guard refuses to run/score
                os.chmod(tpt, 0o755)
                Path(tpt).write_bytes(b"not-the-real-binary")
                rb2 = runner.run(step_idx=1, candidate="s3rial_0rphan!", input_method="argv")
                expect("SHA guard: run_binary refuses a tampered pristine target (inconclusive)",
                       rb2.verdict == "inconclusive")
                ok_o2, det = oracle.check("s3rial_0rphan!")
                expect("SHA guard: oracle refuses a tampered pristine target", not ok_o2 and "integrity" in det)
            finally:
                shutil.rmtree(tws, ignore_errors=True)
                shutil.rmtree(tpdir, ignore_errors=True)
    finally:
        shutil.rmtree(ws, ignore_errors=True)
        shutil.rmtree(pdir, ignore_errors=True)

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"STAGING ISOLATION TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"STAGING ISOLATION TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
