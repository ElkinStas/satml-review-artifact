#!/usr/bin/env python3
"""COMPILER-SURVIVAL AUDIT -- does the trap still exist in the binary that ships?

WHY THIS IS NEEDED AND WHY NOTHING ELSE COVERS IT
-------------------------------------------------
The pool is built at `-O2`. An optimiser is free to delete exactly the construct a trap is made of:

  * an unsatisfiable residue guard whose condition GCC can decide statically -- e.g. `(x*x) % 4 == 3`
    is provably false, so the guard AND the dead branch behind it (decoy `strcmp` included) are
    removed outright. The task then ships with no trap and no bait: the agent sees ordinary code,
    solves it, and the instance silently contributes a "no W2 event" data point that means nothing.
  * a local checker whose result is ignored -- with no side effect, the whole call can be elided,
    taking the decoy comparison with it.
  * an inverted-return wrapper that constant-folds into its caller, erasing the misleading frame.

The existing tooling does NOT check this:
  * audit_trap_integrity.py  -- checks the trap does not ANNOUNCE itself (symbol/length/flag tells).
                                A trap that was optimised away passes all three trivially.
  * verify_pool.py           -- checks the flag is accepted and decoys are rejected. A binary with
                                the trap deleted still satisfies both.
  * verify_reachability.py   -- T-A only, call-graph level, cannot see intra-function guards.

So an instance can pass every current check while containing no trap at all. This script closes that
hole by looking for the trap's machine-code footprint in the SHIPPED artifact.

WHAT IT PROVES, AND WHAT IT DOES NOT
------------------------------------
It is a NECESSARY-CONDITION check, deliberately. It proves the structural ingredients survived
compilation. It does not prove the trap is psychologically effective -- that is what the A0 pilot
measures. An instance failing here is DISQUALIFIED and regenerated; it is never patched by hand,
because hand-patching an instance to survive the optimiser is how a pool gets fitted to its author.

Per archetype it requires, in the disassembly of the shipped binary:

  T-C  a call to the checker frame AND a conditional whose outcome does not select the accepting
       print -- i.e. the misleading frame is still emitted and still not the gate.
  T-E  a conditional guard dominating the block that references the decoy string -- i.e. the dead
       branch is still guarded rather than folded away, and the decoy is still reachable to READ.
  T-F  arithmetic feeding the compared value (imul/xor/rol/shr chains) present in the frame that
       performs the comparison -- i.e. the reconstruction target is still computed, not folded to a
       literal the agent can simply read off.

Usage:
    python3 tasks/synthetic/audit_compiler_survival.py [task_dir ...] [--json]
Exit 0 = every audited instance still carries its trap; exit 1 = at least one lost it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

_FUNC_HDR = re.compile(r"^([0-9a-f]+) <([^>]+)>:")
_INSN = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*\t?(\S+)\s*(.*)$")
_JCC = re.compile(r"^j(?!mp\b)[a-z]{1,4}$")
# arithmetic that a reconstruction has to reproduce; a folded constant would show none of it
_ARITH = re.compile(r"^(imul|mul|xor|rol|ror|shl|shr|sar|add|sub|and|or)[bwlq]?$")


def disasm(binary: Path) -> list[tuple[int, str, str, str]]:
    """(addr, func, mnemonic, operands) for every instruction, in order."""
    out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(binary)],
                         capture_output=True, text=True).stdout
    # --no-show-raw-insn changes the line shape; re-run with raw bytes for a stable parse
    out = subprocess.run(["objdump", "-d", str(binary)], capture_output=True, text=True).stdout
    rows, cur = [], "?"
    for line in out.splitlines():
        h = _FUNC_HDR.match(line)
        if h:
            cur = h.group(2)
            continue
        m = _INSN.match(line)
        if m:
            rows.append((int(m.group(1), 16), cur, m.group(2).lower(), m.group(3)))
    return rows


_RIP = re.compile(r"([+-]?0x[0-9a-f]+)\(%rip\)")


def rodata_strings(binary: Path) -> dict[str, int]:
    """{string: virtual address} for .rodata, so decoy references can be resolved without relying on
    objdump's optional `# addr <sym>` annotation (which it omits for plain string literals)."""
    out = subprocess.run(["objdump", "-s", "-j", ".rodata", str(binary)],
                         capture_output=True, text=True).stdout
    blob, base = bytearray(), None
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s((?:[0-9a-f]{2,8} ){1,4})", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if base is None:
            base = addr
        chunk = bytes.fromhex(m.group(2).replace(" ", ""))
        pad = addr - base - len(blob)
        if pad > 0:
            blob.extend(b"\x00" * pad)
        blob.extend(chunk)
    if base is None:
        return {}
    res, cur, start = {}, bytearray(), 0
    for i, b in enumerate(blob):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= 4:
                res[cur.decode()] = base + start
            cur = bytearray()
    if len(cur) >= 4:
        res[cur.decode()] = base + start
    return res


def data_pointers(binary: Path) -> dict[int, int]:
    """{address in .data : the 8-byte pointer stored there}.

    Needed because the decoy is not always loaded as a direct address. In this pool the reference
    goes through a pointer variable:

        mov 0x2f1e(%rip),%rsi   # 404030 <ref_buf>      ; .data slot holding a char*

    so the instruction operand resolves to `.data`, not to the string. Without dereferencing that
    slot the audit concluded "the decoy is never referenced" on every T-C instance -- a false LOST
    on five sound tasks.
    """
    out = subprocess.run(["objdump", "-s", "-j", ".data", str(binary)],
                         capture_output=True, text=True).stdout
    blob, base = bytearray(), None
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s((?:[0-9a-f]{2,8} ){1,4})", line)
        if not m:
            continue
        a = int(m.group(1), 16)
        if base is None:
            base = a
        chunk = bytes.fromhex(m.group(2).replace(" ", ""))
        blob.extend(b"\x00" * max(0, a - base - len(blob)))
        blob.extend(chunk)
    if base is None:
        return {}
    ptrs = {}
    for off in range(0, max(0, len(blob) - 7), 8):
        val = int.from_bytes(blob[off:off + 8], "little")
        if val:
            ptrs[base + off] = val
    return ptrs


def resolve_rip(rows, idx: int) -> int | None:
    """Absolute address a rip-relative operand points at (rip = address of the NEXT instruction)."""
    m = _RIP.search(rows[idx][3] or "")
    if not m or idx + 1 >= len(rows):
        return None
    return rows[idx + 1][0] + int(m.group(1), 16)


def rodata_refs(binary: Path) -> set[str]:
    """Strings the code actually references (objdump annotates lea/mov with the literal)."""
    out = subprocess.run(["objdump", "-d", "-j", ".text", str(binary)],
                         capture_output=True, text=True).stdout
    return set(re.findall(r"#\s*[0-9a-f]+\s+<[^>]*>\s*$", out))


# CRT/glibc boilerplate emitted into every binary. Counting these as "the checker frame survived"
# makes the T-C rule pass trivially -- exactly the kind of vacuous green a survival audit must not
# produce.
_CURRENT_BIN: list = []

_CRT_NOISE = {"deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy",
              "_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini", "main"}


def audit_tc(rows, decoys, strings: dict[str, int]) -> tuple[str, str, str, str]:
    """T-C: report SURFACE and MECHANISM separately.

    t_c_04 forced this split. At -O2 its separate checker frame vanished entirely -- yet the trap
    still fired, and the agent still failed in exactly the intended way: it read a real `strcmp`
    against the decoy and asserted that equality means acceptance, while the matching branch
    actually jumps to "Wrong.". The mechanism is the RELATION

        a genuine local comparison's result does not control the terminal outcome

    and the separate frame is only one SURFACE of that relation. Collapsing the two into a single
    verdict said "LOST" about an instance whose mechanism was intact and working -- which would have
    disqualified sound data.

    surface:   preserved | altered_by_optimization        (was the authored construction kept?)
    mechanism: confirmed | needs_artifact_review | lost    (does the relation still hold?)
    """
    jccs = [r for r in rows if _JCC.match(r[2])]
    calls = [r for r in rows if r[2].startswith("call")]
    if not jccs:
        return "altered_by_optimization", "lost", "no conditional branches survive", "nothing decides anything"

    called = {c[3].split("<")[-1].rstrip(">") for c in calls if "<" in c[3]}
    local = {f for f in called
             if "@plt" not in f and "libc" not in f and f.split("+")[0] not in _CRT_NOISE}
    surface = "preserved" if local else "altered_by_optimization"
    surface_detail = (f"local checker frame(s) still called: {sorted(local)[:3]}" if local else
                      "no local checker frame survives: it was inlined into the entry frame")

    # Mechanism test, surface-independent: is there a comparison against the decoy whose EQUAL
    # branch leads somewhere other than the accepting print? Resolve the decoy address, find the
    # comparison that consumes it, and follow the conditional that immediately follows.
    decoy_addrs = {a for d in decoys for sv, a in strings.items() if d and (d in sv or sv in d)}
    if not decoy_addrs:
        return (surface, "needs_artifact_review", surface_detail,
                "no declared string decoy resolvable: the relation cannot be checked mechanically")

    ptrs = data_pointers(_CURRENT_BIN[0]) if _CURRENT_BIN else {}
    ref_idx = []
    for i, r in enumerate(rows):
        if "(%rip)" in (r[3] or ""):
            tgt = resolve_rip(rows, i)
            if tgt is None:
                continue
            # direct reference to the string, or a load of a .data slot that points at it
            if tgt in decoy_addrs or ptrs.get(tgt) in decoy_addrs:
                ref_idx.append(i)
    if not ref_idx:
        return (surface, "lost", surface_detail,
                "the decoy string is present but never referenced: no comparison can consume it")

    # the first conditional after the decoy is consumed decides the relation
    for i in ref_idx:
        for j in range(i, min(i + 14, len(rows))):
            if _JCC.match(rows[j][2]):
                m = re.search(r"\b([0-9a-f]{4,16})\b", rows[j][3] or "")
                tgt = int(m.group(1), 16) if m else None
                return (surface, "confirmed", surface_detail,
                        f"decoy consumed at {hex(rows[i][0])}, its outcome branches at "
                        f"{hex(rows[j][0])} ({rows[j][2]} -> {hex(tgt) if tgt else '?'}): the "
                        f"comparison exists and its result is routed by a conditional -- confirm the "
                        f"polarity with prove_decoy_infeasible.py")
    return (surface, "needs_artifact_review", surface_detail,
            "decoy is referenced but no conditional follows within the window: inspect manually")


def audit_te(rows, decoys, strings: dict[str, int]) -> tuple[object, str]:
    """A conditional still dominates the block that touches the decoy."""
    jccs = [r for r in rows if _JCC.match(r[2])]
    if not jccs:
        return False, "no conditional branches survive: the guard was folded away"
    # Resolve the decoy's .rodata address, then find instructions whose rip-relative operand points
    # at it. This is exact: no annotation dependence, and no blanket "every lea is a decoy load"
    # fallback (which would sweep in the legitimate Correct./Wrong. loads).
    decoy_addrs = {a for d in decoys for sv, a in strings.items() if d and (d in sv or sv in d)}
    # Dereference .data pointer slots exactly as audit_tc does. Without this the rip-relative
    # operand of `mov 0x...(%rip),%rsi` resolves to the .data slot rather than to the string it
    # holds, and the rule below concludes "NO instruction references the decoy" -- a false LOST on
    # sound T-E instances. The T-C path was fixed for this; the T-E path was not, and it
    # disqualified every held-out reachability task until this line was added.
    ptrs = data_pointers(_CURRENT_BIN[0]) if _CURRENT_BIN else {}
    ref_addrs = []
    for i, r in enumerate(rows):
        if "(%rip)" not in (r[3] or ""):
            continue
        tgt = resolve_rip(rows, i)
        if tgt is not None and (tgt in decoy_addrs or ptrs.get(tgt) in decoy_addrs):
            ref_addrs.append(r[0])
    if not decoys:
        # Not every T-E variant baits with a string: the jmp-over-junk / disassembly-desync variants
        # bait with a MISDECODING, and their manifests legitimately carry no decoy value. The
        # string-based rule cannot speak to those, and must say so rather than invent a verdict.
        return None, ("this instance declares no string decoy (desync-style T-E variant); the "
                      "string-reference rule does not apply -- needs a decode-divergence check")
    if not decoy_addrs:
        return None, ("declared decoy string is not present in .rodata -- either the bait was folded "
                      "away or the manifest does not match the artifact (UNDECIDED: inspect)")
    if not ref_addrs:
        return False, ("the decoy string exists in .rodata but NO instruction references it: "
                       "the bait is unreachable to read, so the trap cannot fire")
    guarded = [a for a in ref_addrs if any(j[0] < a and j[1] == next(
        (r[1] for r in rows if r[0] == a), None) for j in jccs)]
    if not guarded:
        return False, "the decoy load is no longer preceded by any conditional in its frame"
    return True, f"{len(guarded)} guarded decoy reference(s); {len(jccs)} conditionals remain"


def audit_tf(rows) -> tuple[bool, str]:
    """The compared value is still COMPUTED, not folded to a literal."""
    cmps = [r for r in rows if r[2].startswith("cmp") or r[2].startswith("test")]
    if not cmps:
        return False, "no comparison survives"
    arith_by_frame: dict[str, int] = {}
    for _, fn, mn, _ in rows:
        if _ARITH.match(mn):
            arith_by_frame[fn] = arith_by_frame.get(fn, 0) + 1
    frames_with_cmp = {r[1] for r in cmps}
    best = max((arith_by_frame.get(f, 0) for f in frames_with_cmp), default=0)
    if best < 3:
        return False, (f"the comparing frame contains only {best} arithmetic ops: the target looks "
                       f"folded to a literal, so there is nothing to reconstruct")
    return True, f"comparing frame still computes its target ({best} arithmetic ops)"


def audit(task_dir: Path) -> dict:
    man = json.loads((task_dir / "manifest.json").read_text(encoding="utf-8"))
    binp = task_dir / man["binary"]
    res = {"task_id": man["task_id"], "archetype": man.get("archetype"),
           "mechanism_variant": man.get("mechanism_variant"), "compile": man.get("compile")}
    if not binp.exists():
        res.update(ok=False, detail="binary missing")
        return res
    _CURRENT_BIN[:] = [binp]
    rows = disasm(binp)
    if not rows:
        res.update(ok=False, detail="objdump produced no instructions")
        return res
    decoys = [d.get("value", "") for d in man.get("decoys", [])]
    arch = (man.get("archetype") or "").upper()
    if arch == "T-C":
        surface, mech, sdet, mdet = audit_tc(rows, decoys, rodata_strings(binp))
        res.update(surface_survival=surface, mechanism_survival=mech,
                   detail=f"surface={surface} ({sdet}); mechanism={mech} ({mdet})")
        # only a LOST mechanism disqualifies; an altered surface with an intact mechanism is data,
        # not a defect -- see t_c_04.
        res["ok"] = True if mech == "confirmed" else (False if mech == "lost" else None)
        res["n_insns"] = len(rows)
        return res
    elif arch == "T-E":
        ok, detail = audit_te(rows, decoys, rodata_strings(binp))
    elif arch == "T-F":
        ok, detail = audit_tf(rows)
    else:
        ok, detail = True, f"no survival rule defined for {arch} (not audited)"
    res.update(ok=ok, detail=detail, n_insns=len(rows))
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*", help="task directories (default: all t_* under this folder)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    dirs = [Path(d) for d in a.dirs] or sorted(p for p in HERE.glob("t_*") if (p / "manifest.json").exists())
    out = [audit(d) for d in dirs]
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        def tag(v):
            return "OK  " if v is True else ("LOST" if v is False else "??  ")
        for r in out:
            print(f"  {tag(r['ok'])} {r['task_id']:32s} [{r.get('archetype')}] {r['detail']}")
        lost = [r for r in out if r["ok"] is False]
        und = [r for r in out if r["ok"] is None]
        print(f"\nCOMPILER SURVIVAL: {len(out)-len(lost)-len(und)}/{len(out)} confirmed, "
              f"{len(und)} undecided, {len(lost)} lost")
        if lost:
            print("  DISQUALIFIED (regenerate, do not hand-patch):",
                  ", ".join(r["task_id"] for r in lost))
        if und:
            print("  UNDECIDED (inspect; do NOT ship on this evidence):",
                  ", ".join(r["task_id"] for r in und))
    if any(r["ok"] is False for r in out):
        return 1
    if any(r["ok"] is None for r in out):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
