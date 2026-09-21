#!/usr/bin/env python3
"""trace_binary tests (no real strace/ltrace needed).

Verifies the wiring + safety properties: a trace result is tool "trace_binary" (never "run_binary", so
the A2 scaffold can't treat it as acceptance), an unavailable tracer is a structured non-fatal result
(not a crash), bad tracer/method are rejected, and the pristine SHA guard fires. The happy path (reading
the tracer's -o file) is proven at the backend level in test_execution.

Run from repo root:  python agent/test_trace_binary.py
"""
from __future__ import annotations

import hashlib
import stat
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.execution import LocalExecutionBackend
from agent.tools.trace_binary import TraceBinaryTool

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))


def main() -> int:
    be = LocalExecutionBackend(allow_unsandboxed=True)
    d = Path(tempfile.mkdtemp(prefix="rerag_tb_"))
    exe = d / "prog"
    exe.write_text("#!/bin/sh\necho hi\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    sha = hashlib.sha256(exe.read_bytes()).hexdigest()
    tb = TraceBinaryTool(backend=be, binary_path=str(exe), default_input_method="argv", expected_sha256=sha)

    # bad tracer / bad method -> structured error, tool stays 'trace_binary'
    r_bad = tb.run(step_idx=0, tracer="dtrace", candidate="x", input_method="argv")
    expect("unknown tracer rejected", r_bad.exit_code == -1 and "unknown tracer" in r_bad.stderr)
    expect("rejection is still tool=trace_binary", r_bad.tool == "trace_binary")
    r_m = tb.run(step_idx=0, tracer="strace", candidate="x", input_method="carrier-pigeon")
    expect("bad input_method rejected", "bad input_method" in r_m.stderr)

    # unavailable tracer (no strace in this env) -> structured NON-FATAL result, not an exception
    r = tb.run(step_idx=1, tracer="strace", candidate="x", input_method="argv")
    expect("unavailable tracer does not raise (returns a ToolResult)", r is not None)
    expect("unavailable tracer is nonzero/structured (not accepted)", r.exit_code != 0 or r.verdict != "accepted")
    expect("trace result carries tracer + candidate + method",
           r.tracer == "strace" and r.ran_candidate == "x" and r.input_method == "argv")
    expect("trace result exposes trace_output_bytes_captured", hasattr(r, "trace_output_bytes_captured"))

    # SAFETY: a trace is NEVER an acceptance signal -> tool must be 'trace_binary', verdict inconclusive
    expect("trace_binary result is tool=trace_binary (scaffold never counts it as run_binary)",
           r.tool == "trace_binary")
    expect("trace_binary verdict is inconclusive (not an acceptance)", r.verdict == "inconclusive")

    # pristine SHA guard fires on a tampered target
    tb_bad = TraceBinaryTool(backend=be, binary_path=str(exe), default_input_method="argv",
                             expected_sha256="0" * 64)
    rg = tb_bad.run(step_idx=2, tracer="strace", candidate="x", input_method="argv")
    expect("SHA mismatch is a structured trace error", "integrity" in rg.stderr and rg.tool == "trace_binary")

    try:
        exe.unlink(); d.rmdir()
    except OSError:
        pass

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"TRACE_BINARY TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"TRACE_BINARY TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
