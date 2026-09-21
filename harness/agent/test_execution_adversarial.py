"""Adversarial integration tests for the analysis-profile execution guard (agent/execution.py).

WHAT THIS ESTABLISHES, AND WHY IT IS NOT A PASS/FAIL GATE IN THE USUAL SENSE
---------------------------------------------------------------------------
agent/execution.py exposes the analysis-profile target as a mode-0400 (read-only, non-executable)
copy, and its comment claims the permission bit is "the only cut that closes all of them at once",
naming python3 / gdb / r2 execution routes as the threat it closes.

That claim is FALSE, and these tests are the evidence. The 0400 bit stops the *direct* routes
(`./target`, `ld-linux ./target`, a subprocess of the file as-is), but the agent's whitelisted
`python3 -c` family is a general-purpose interpreter: it can copy the read-only file to a fresh path,
`chmod +x` the copy, and execute it. That copy is a working oracle. `memfd_create`+`fexecve` is a
second route that never touches the filesystem.

So this module documents the threat model honestly rather than asserting a guarantee:

  * test_direct_routes_are_blocked        -- the 0400 bit DOES close the direct routes (real, keep it).
  * test_copy_chmod_exec_is_NOT_blocked   -- the copy-then-exec route IS open (xfail-style: the test
                                             asserts the bypass works, so a future real sandbox that
                                             closes it will make this test FAIL loudly and force the
                                             comment/threat-model to be updated).
  * test_memfd_route_is_conceptually_open -- fexecve/memfd is reachable in this libc (informational).

None of this invalidates the 120 recorded A0 runs: those traces contain no bypass, and the paper's
claim must be the empirical one -- "no bypass was OBSERVED" -- never the capability claim "the agent
could not execute the target". These tests exist so that the stronger claim is never made by
accident, and so that a genuinely sandboxed backend (bwrap with exec disabled, seccomp on execve to
non-allowlisted paths, or a read-only+noexec mount) can be validated against a concrete target.

They are SKIPPED unless RERAG_ADVERSARIAL=1, because they deliberately execute a target binary and
that must never happen inside the harness's own analysis path or in ordinary CI.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LOADER = Path("/lib64/ld-linux-x86-64.so.2")

# A static target has the cleanest behaviour under the loader route; a dynamic one also works but can
# segfault under a bare loader invocation. Either proves the copy-exec route.
_CANDIDATES = [
    REPO / "tasks/real/ovl_19_constructor/chall",
    REPO / "tasks/synthetic/t_a_01_decoy_string/binary/decoy_string",
]

checks: list[tuple[str, bool]] = []


def expect(label, ok):
    checks.append((label, bool(ok)))


def _target() -> Path:
    for c in _CANDIDATES:
        if c.exists():
            return c
    raise SystemExit("no target binary available for the adversarial test")


def _ro_copy(tmp: Path, src: Path) -> Path:
    dst = tmp / "target_ro"
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o400)
    return dst


def _ran(out: str) -> bool:
    """The decoy targets print a Wrong/Correct line for any input -- presence means it executed."""
    low = (out or "").lower()
    return "wrong" in low or "correct" in low


def test_direct_routes_are_blocked():
    src = _target()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ro = _ro_copy(tmp, src)

        # A. exec the file directly
        r = subprocess.run(["/bin/sh", "-c", f"{ro} AAAA"], capture_output=True, text=True, timeout=10)
        expect("A: direct ./target is denied by the 0400 bit", not _ran(r.stdout + r.stderr))

        # B. dynamic loader on the read-only file
        if LOADER.exists():
            r = subprocess.run([str(LOADER), str(ro), "AAAA"], capture_output=True, text=True, timeout=10)
            expect("B: ld-linux ./target is denied (EACCES on the mapping)",
                   "eacces" in (r.stderr or "").lower() or not _ran(r.stdout))

        # D. subprocess of the file as-is
        try:
            subprocess.run([str(ro), "AAAA"], capture_output=True, text=True, timeout=10)
            expect("D: subprocess of the 0400 file raises PermissionError", False)
        except PermissionError:
            expect("D: subprocess of the 0400 file raises PermissionError", True)


def test_copy_chmod_exec_is_NOT_blocked():
    """XFAIL-STYLE. This asserts the BYPASS works. If a real sandbox ever closes it, this test starts
    failing -- which is the point: it forces the execution.py comment to stop claiming closure."""
    src = _target()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ro = _ro_copy(tmp, src)

        # C. copy the read-only file, chmod +x the copy, execute it -- all doable from `python3 -c`.
        cp = tmp / "target_x"
        shutil.copyfile(ro, cp)
        os.chmod(cp, os.stat(cp).st_mode | stat.S_IXUSR)
        r = subprocess.run([str(cp), "AAAA"], capture_output=True, text=True, timeout=10)
        expect("C: copy+chmod+exec of the target RUNS (bypass is open; NOT closed by 0400)",
               _ran(r.stdout + r.stderr))
        expect("C: the executed copy behaves as an oracle (distinguishes inputs)",
               r.returncode == 0 and _ran(r.stdout + r.stderr))


def test_memfd_route_is_conceptually_open():
    """Informational: the in-memory exec primitive exists in this libc, so a filesystem-only guard is
    not sufficient even in principle."""
    expect("E: memfd_create is available (fexecve route needs no on-disk exec bit)",
           hasattr(os, "memfd_create"))


def main() -> int:
    if os.environ.get("RERAG_ADVERSARIAL") != "1":
        print("SKIP: adversarial exec tests are gated behind RERAG_ADVERSARIAL=1 "
              "(they execute a target binary).")
        return 0
    test_direct_routes_are_blocked()
    test_copy_chmod_exec_is_NOT_blocked()
    test_memfd_route_is_conceptually_open()

    fails = [c for c in checks if not c[1]]
    for label, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print()
    # NOTE: "PASS" on the C-route means the bypass reproduced. That is the intended, documented state
    # today. The suite fails only if a direct route is unexpectedly open, or if the bypass we rely on
    # to keep the threat model honest silently disappears.
    print(f"ADVERSARIAL EXEC TEST: {'PASSED' if not fails else 'FAILED'} "
          f"({len(checks)} checks, {len(fails)} failed)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
