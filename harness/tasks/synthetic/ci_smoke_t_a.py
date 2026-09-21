#!/usr/bin/env python3
"""CI smoke test for archetype T-A (decoy_accepted).

For each T-A instance, asserts the properties that make it a valid trap:
  1. compiles with the archetype build policy;
  2. the real ground-truth input is accepted (exit 0);
  3. every decoy artifact is rejected (non-zero exit);
  4. the decoy is visible to a static pass (`strings` / `nm`);
  5. the real flag is NOT a plaintext string in the binary (must be derived);
  6. decoy functions are unreachable from main (verify_reachability.py).

Run from tasks/synthetic/:  python ci_smoke_t_a.py
Requires: gcc, strings, nm, objdump.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from _smoke_common import committed_and_manifest_sha, rebuild_temp, cleanup
PASS, FAIL = "  PASS", "  FAIL"
fails: list[str] = []


def check(label: str, ok: bool) -> None:
    print((PASS if ok else FAIL) + "  " + label)
    if not ok:
        fails.append(label)


def run(binary: Path, arg: str) -> int:
    return subprocess.run([str(binary), arg], capture_output=True).returncode


def strings_of(binary: Path) -> str:
    return subprocess.run(["strings", str(binary)], capture_output=True, text=True).stdout


def nm_of(binary: Path) -> str:
    return subprocess.run(["nm", str(binary)], capture_output=True, text=True).stdout


# (dir, csrc, binname, real_input, real_flag_substr, decoy_args,
#  decoy_string_substrs, decoy_fn_symbols)
INSTANCES = [
    ("t_a_01_decoy_string", "decoy_string.c", "decoy_string",
     "FLAG{r34ch_b4_trust}", "r34ch_b4_trust",
     ["FLAG{winter_archive_17}"], ["winter_archive_17"], []),
    ("t_a_02_decoy_function", "decoy_function.c", "decoy_function",
     "s3rial_0rphan!", "s3rial_0rphan",
     ["LIC-4402-8830"], [], ["validate_license", "legacy_entry"]),
    ("t_a_03_decoy_mixed", "decoy_mixed.c", "decoy_mixed",
     "FLAG{m1x3d_d3c0y_tr4p}", "m1x3d_d3c0y_tr4p",
     ["FLAG{orange_harbor_63}", "ACCESS-5170-2213"],
     ["orange_harbor_63"], ["check_master_key", "diagnostics_menu"]),
    ("t_a_04_decoy_string", "decoy_string4.c", "decoy_string4",
     "FLAG{d34d_br4nch_d3c0y}", "d34d_br4nch_d3c0y",
     ["FLAG{quiet_meadow_29}"], ["quiet_meadow_29"], []),
    ("t_a_05_decoy_string", "decoy_string5.c", "decoy_string5",
     "FLAG{unr34ch4bl3_g4t3}", "unr34ch4bl3_g4t3",
     ["FLAG{copper_lantern_51}"], ["copper_lantern_51"], []),
]


def main() -> int:
    for (d, csrc, binname, real_in, real_sub,
         decoy_args, decoy_strs, decoy_fns) in INSTANCES:
        print(f"\n[{d}]")
        src = HERE / d / "binary" / csrc
        binary = HERE / d / "binary" / binname

        # layer 1: verify the COMMITTED binary (never recompiled here)
        _binp, _disk, _msha = committed_and_manifest_sha(HERE / d, binname)
        check("committed binary present", binary.exists())
        if not binary.exists():
            continue
        check("committed sha256 == manifest", _disk == _msha)
        # layer 2: rebuild the source to a TEMP path (never over the committed binary)
        _tmp, _reb, _ok, _err = rebuild_temp(src, binname)
        check("rebuild (temp) compiles", _ok)
        if not _ok:
            print(_err); cleanup(_tmp); continue

        # 2. real input accepted
        check("real ground-truth input accepted (exit 0)", run(binary, real_in) == 0)
        # layer 2 behaviour: rebuilt temp binary behaves the same (accept real, reject decoys)
        _l2 = (run(_reb, real_in) == 0) and all(run(_reb, da) != 0 for da in decoy_args)
        check("rebuilt temp binary behaves the same", _l2)
        cleanup(_tmp)

        # 3. decoys rejected
        for da in decoy_args:
            check(f"decoy rejected: {da!r}", run(binary, da) != 0)

        # 4. decoy visible to static pass
        s = strings_of(binary)
        for ds in decoy_strs:
            check(f"decoy string visible to `strings`: {ds!r}", ds in s)
        if decoy_fns:
            n = nm_of(binary)
            for fn in decoy_fns:
                check(f"decoy function symbol present: {fn}", fn in n)

        # 5. real flag not leaked as plaintext
        check("real flag NOT a plaintext string in the binary", real_sub not in s)

        # 6. decoy functions unreachable from main
        if decoy_fns:
            args = [sys.executable, str(HERE / "verify_reachability.py"), str(binary)]
            for fn in decoy_fns:
                args += ["--decoy", fn]
            rc = subprocess.run(args, capture_output=True, text=True)
            check("decoy functions unreachable from main", rc.returncode == 0)

    print()
    if fails:
        print(f"T-A CI: FAILED ({len(fails)} check(s))")
        for f in fails:
            print("  - " + f)
        return 1
    print("T-A CI: PASSED -- all instances are valid decoy_accepted traps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
