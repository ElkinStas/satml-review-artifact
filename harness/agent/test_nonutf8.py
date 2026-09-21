#!/usr/bin/env python3
"""Non-UTF-8 output regression (bug #7).

RE/CTF binaries can print arbitrary bytes. RunBinaryTool and BinaryOracle used text=True with no
errors="replace", so a 0xff byte before the success marker raised UnicodeDecodeError -> the accept was
lost (verdict inconclusive / oracle rejected). Now output is captured as raw bytes, hashed over the raw
bytes, and decoded with errors="replace" for marker matching + trace.

Run from repo root:  python agent/test_nonutf8.py
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.tools.run_binary import RunBinaryTool
from agent.execution import LocalExecutionBackend
from agent.submit import BinaryOracle

checks: list[tuple[str, bool]] = []
def expect(label, cond): checks.append((label, bool(cond)))

# stdout = 0xff (invalid UTF-8) then the success marker on its own line, exit 0.
RAW_STDOUT = b"\xff\nCorrect.\n"
SCRIPT = "#!/bin/sh\nprintf '\\377\\nCorrect.\\n'\n"


def main() -> int:
    d = Path(tempfile.mkdtemp(prefix="rerag_nonutf8_"))
    exe = d / "target"
    exe.write_text(SCRIPT)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    sha = hashlib.sha256(exe.read_bytes()).hexdigest()

    runner = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=exe, default_input_method="argv",
                           success_marker="Correct.", fail_marker="Wrong.", expected_sha256=sha)
    r = runner.run(step_idx=0, candidate="anything", input_method="argv")
    expect("run_binary does not raise on non-UTF-8 output", r is not None)
    expect("run_binary reads the marker past a 0xff byte -> accepted", r.verdict == "accepted")
    expect("run_binary stdout_sha256 is over RAW bytes",
           r.stdout_sha256 == hashlib.sha256(RAW_STDOUT).hexdigest())
    expect("run_binary decoded stdout uses U+FFFD replacement (no crash)", "\ufffd" in r.stdout)

    oracle = BinaryOracle(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=exe, input_method="argv",
                          success_marker="Correct.", fail_marker="Wrong.", expected_sha256=sha)
    ok, detail = oracle.check("anything")
    expect("oracle accepts despite non-UTF-8 output", ok)

    # stdin framing: stdin_append_newline controls whether a trailing '\n' is piped. Use a byte-count
    # binary that accepts iff stdin is exactly 2 bytes ('ok'); 'ok\n' is 3 bytes -> rejected.
    d2 = Path(tempfile.mkdtemp(prefix="rerag_framing_"))
    echo = d2 / "target"
    echo.write_text('#!/bin/sh\nn=$(wc -c)\nif [ "$n" -eq 2 ]; then echo Correct.; else echo Wrong.; fi\n')
    echo.chmod(echo.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    esha = hashlib.sha256(echo.read_bytes()).hexdigest()
    r_nl = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=echo, default_input_method="stdin", success_marker="Correct.",
                         fail_marker="Wrong.", expected_sha256=esha, stdin_append_newline=True
                         ).run(step_idx=0, candidate="ok", input_method="stdin")
    r_no = RunBinaryTool(backend=LocalExecutionBackend(allow_unsandboxed=True), binary_path=echo, default_input_method="stdin", success_marker="Correct.",
                         fail_marker="Wrong.", expected_sha256=esha, stdin_append_newline=False
                         ).run(step_idx=0, candidate="ok", input_method="stdin")
    expect("stdin_append_newline=True pipes 'ok\\n' (3 bytes) -> not accepted", r_nl.verdict != "accepted")
    expect("stdin_append_newline=False pipes bare 'ok' (2 bytes) -> accepted", r_no.verdict == "accepted")
    try:
        echo.unlink(); d2.rmdir()
    except OSError:
        pass

    # cleanup
    try:
        exe.unlink(); d.rmdir()
    except OSError:
        pass

    fails = [c for c in checks if not c[1]]
    for label, ok_ in checks:
        print(f"  {'PASS' if ok_ else 'FAIL'}  {label}")
    print()
    if fails:
        print(f"NON-UTF8 TEST: FAILED ({len(fails)}/{len(checks)})")
        return 1
    print(f"NON-UTF8 TEST: PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
