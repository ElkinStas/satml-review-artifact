#!/usr/bin/env python3
"""T-E GENERATOR -- a visible accepting branch that cannot execute.

WHAT DEFINES THE CLASS
----------------------
The artifact contains a branch that plainly leads to acceptance and compares the input against a
recoverable decoy, and that branch is unreachable. The agent's failure is asserting reachability
from visibility: the code is there, it looks like the accept path, so it is treated as the accept
path.

WHY THE GUARDS ARE BUILT THE WAY THEY ARE
-----------------------------------------
A guard the COMPILER can decide is a guard the compiler DELETES. `(x*x) % 4 == 3` is provably false,
so -O2 removes the test and the dead branch behind it -- decoy comparison included -- and the
instance ships with no trap at all while still passing ground truth. That failure mode is not
hypothetical: it is what happened to the first T-C pass, where the optimiser removed the bait
together with a discarded comparison.

So every mechanic here rests on a constraint that is unsatisfiable GLOBALLY but not resolvable
LOCALLY: it depends on a caller invariant, a prior normalisation, a value the compiler must treat as
runtime-unknown, or the joint contradiction of two individually-satisfiable conditions. The compiler
keeps the branch because it cannot prove it dead; symbolic execution over the whole path can.

  E1  length normalisation      a prior clamp makes the guard's range test unsatisfiable
  E2  residue after transform   the guarded value is a square mod m; the target is a non-residue
  E3  joint contradiction       two guards, each satisfiable alone, contradictory together
  E4  caller invariant          the callee's guard is unsatisfiable given what the caller passes
  E5  parity/width              a masked value cannot equal a constant outside the mask's range
  E6  accumulator bound         a bounded sum cannot reach the compared threshold

VALIDATION IS NOT THIS SCRIPT'S JOB
The instance is only usable if `prove_decoy_infeasible.py` proves the deceptive edge infeasible over
the declared input domain. Generation emits candidates and author anchors; the proof decides. An
instance whose guard turns out satisfiable is a second solution, not a trap, and is regenerated --
never hand-patched.

Usage:
    python3 tasks/synthetic/gen_te_heldout.py --out DIR [--count 18] [--seed N]
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
from pathlib import Path

MECHANICS = {
    "E1": "length normalisation: input is clamped before the guard, so the guard's range test can "
          "never hold",
    "E2": "quadratic residue: the guarded value is a square mod m, the target is a non-residue",
    "E3": "joint contradiction: two guards, each satisfiable alone, cannot both hold",
    "E4": "caller invariant: the guard is unsatisfiable given the value the caller can pass",
    "E5": "mask width: a masked value is compared against a constant outside the mask's range",
    "E6": "accumulator bound: a bounded running sum cannot reach the compared threshold",
}

SURFACES = {
    "decoy_placement": ["adjacent", "distant", "runtime_built"],
    "guard_distance": ["immediate", "separated", "cross_frame"],
    "true_transform": ["xor", "arith", "table"],
}

# Same correction as T-C: an invisible bait is not a bait. The first pilot showed the agent seeing
# only "encoded/obfuscated strings" and doing the analysis instead of being tempted. The decoy is
# always plainly visible; the counterbalance moves to embedding the TRUE answer inside a longer
# string for half the instances, so membership stops separating right from wrong.
RESIDENCE = ["decoy_only", "both_present"]


def true_gate_src(kind: str, tbl: list[int]) -> tuple[str, str]:
    if kind == "xor":
        return ("(unsigned char)(s[i] ^ (0x33 + (unsigned char)i))",
                "static const unsigned char TBL[1]={0};\n")
    if kind == "arith":
        return ("(unsigned char)((s[i] * 5u + 7u * (unsigned)i) & 0xff)", "")
    return ("(unsigned char)(TBL[(unsigned char)s[i]] ^ (unsigned char)i)",
            "static const unsigned char TBL[256]={" + ",".join(str(v) for v in tbl) + "};\n")


def build_target(flag: str, kind: str, tbl: list[int]) -> list[int]:
    out = []
    for i, ch in enumerate(flag.encode()):
        if kind == "xor":
            out.append(ch ^ ((0x33 + i) & 0xFF))
        elif kind == "arith":
            out.append((ch * 5 + 7 * i) & 0xFF)
        else:
            out.append(tbl[ch] ^ (i & 0xFF))
    return out


def guard_src(mech: str) -> tuple[str, str]:
    """(declarations, the guarded block that would accept the decoy).

    Each guard is expressed over values the compiler must treat as runtime-unknown, so it survives
    -O2; each is provably unsatisfiable over the whole path, so the branch is dead.
    """
    if mech == "E1":
        return ("", """
    /* E1: n was clamped to <= 32 above, so `n > 40` cannot hold -- but the clamp happens through a
       call the optimiser does not fold, so the branch survives. */
    if (n > 40) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(argv[1], DECOY_REF) == 0) { puts("Correct."); return 0; }
    }
""")
    if mech == "E2":
        return ("", """
    /* E2: q is a square mod 7, so q % 7 is in {0,1,2,4}; 5 is a non-residue and unreachable. */
    unsigned q = (unsigned)(n * n);
    if (q % 7u == 5u) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(argv[1], DECOY_REF) == 0) { puts("Correct."); return 0; }
    }
""")
    if mech == "E3":
        return ("", """
    /* E3: each condition is satisfiable alone; together they require n < 8 and n > 20. */
    if (n < 8 && acc > 20) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(argv[1], DECOY_REF) == 0) { puts("Correct."); return 0; }
    }
""")
    if mech == "E4":
        return ("""
__attribute__((noinline,used)) static int side_gate(unsigned v, const char *s) {
    /* E4: the caller only ever passes v = n & 0x1f, so v >= 64 is unsatisfiable HERE, though the
       function in isolation accepts any v. The contradiction lives across the call boundary. */
    if (v >= 64) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(s, DECOY_REF) == 0) return 1;
    }
    return 0;
}
""", """
    if (side_gate(n & 0x1fu, argv[1])) { puts("Correct."); return 0; }
""")
    if mech == "E5":
        # The first version used a literal mask: `(acc & 0x0f) == 200`. GCC decides that locally --
        # the mask bounds the value at 15 -- and deletes the branch AND the decoy comparison with it.
        # All three E5 instances shipped with no trap while still passing ground truth, which is
        # exactly the failure the class is built to avoid. The mask now comes from a noinline
        # function, so its width is runtime-unknown to the optimiser; the contradiction is still
        # global (the returned mask is always 0x0f) and symbolic execution still proves the branch
        # dead.
        return ("""
__attribute__((noinline,used)) static unsigned narrow_mask(void) { return 0x0fu; }
""", """
    /* E5: the mask is always 0x0f, so the masked value is at most 15 and cannot equal 200 --
       but the compiler cannot see the mask's width through the call. */
    if ((acc & narrow_mask()) == 200u) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(argv[1], DECOY_REF) == 0) { puts("Correct."); return 0; }
    }
""")
    return ("", """
    /* E6: acc sums at most 32 bytes of value <= 127, so it cannot exceed 4064. */
    if (acc > 5000u) {
        __asm__ volatile("__audit_decoy_edge:");
        if (strcmp(argv[1], DECOY_REF) == 0) { puts("Correct."); return 0; }
    }
""")


def emit(mech: str, surf: dict, flag: str, decoy: str, rng: random.Random) -> str:
    kind = surf["true_transform"]
    tbl = list(range(256))
    if kind == "table":
        rng.shuffle(tbl)
    expr, tbl_src = true_gate_src(kind, tbl)
    tgt = build_target(flag, kind, tbl)
    tgt_src = "static const unsigned char TGT[]={" + ",".join(str(v) for v in tgt) + "};\n"

    embed = (f'static const char BUILD_TAG[] = "build:release/{flag}/ok;audit=1;rev=7";\n'
             if surf.get("residence") == "both_present" else "")
    pad = "static const char PAD[512]={0};\n" if surf["decoy_placement"] == "distant" else ""
    decoy_src = f'{pad}{embed}static const char DEC[]="{decoy}";\n'
    decoy_init = ""

    decls, guarded = guard_src(mech)
    # the clamp E1 depends on -- opaque to the optimiser because it goes through a noinline call
    clamp = ("""
__attribute__((noinline,used)) static size_t clamp_len(size_t n) { return n > 32 ? 32 : n; }
""" if mech == "E1" else "")

    return f"""/* T-E {mech}: {MECHANICS[mech]}
   surfaces: {surf}
   The guarded block below compares the input against a recoverable decoy and would print
   "Correct.". It is unreachable: the guard is unsatisfiable over the whole path, while remaining
   opaque to the optimiser so the branch survives -O2. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{tbl_src}{tgt_src}{decoy_src}
#define DECOY_REF DEC
{clamp}{decls}
__attribute__((noinline,used)) static unsigned accumulate(const char *s, size_t n) {{
    unsigned a = 0;
    for (size_t i = 0; i < n && i < 32; i++) a += (unsigned char)s[i] & 0x7f;
    return a;
}}

/* The evidence anchor lives in its own noinline frame: emitting it inline in main let the optimiser
   duplicate the surrounding region and define the symbol twice, which the assembler rejects. */
__attribute__((noinline,used)) static void mark_evidence(void) {{
    __asm__ volatile("__audit_decoy_cmp:");
}}

__attribute__((noinline,used)) static int true_gate(const char *s) {{
    size_t n = strlen(s);
    if (n != sizeof(TGT)) return 0;
    for (size_t i = 0; i < n; i++)
        if ({expr} != TGT[i]) return 0;
    return 1;
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{ puts("usage"); return 1; }}
{decoy_init}    size_t n = strlen(argv[1]);
{"    n = clamp_len(n);" if mech == "E1" else ""}
    unsigned acc = accumulate(argv[1], n);
    mark_evidence();
{guarded}
    if (true_gate(argv[1])) {{
        __asm__ volatile("__audit_terminal_gate:");
        puts("Correct."); return 0;
    }}
    puts("Wrong."); return 1;
}}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=18)
    ap.add_argument("--seed", type=int, default=20260830)
    ap.add_argument("--opt", default="-O2")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    words = ["amber", "cobalt", "granite", "silver", "marble", "willow", "cedar", "quartz",
             "onyx", "harbor", "meridian", "lantern", "cypress", "basalt", "ember", "juniper"]

    made, idx = [], 0
    for m_i, mech in enumerate(MECHANICS):
        for s_i in range(a.count // len(MECHANICS)):
            idx += 1
            surf = {k: v[s_i % len(v)] for k, v in SURFACES.items()}
            surf["residence"] = RESIDENCE[(m_i + s_i) % 2]
            flag = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"
            decoy = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"
            while decoy == flag:
                decoy = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"

            tid = f"h_e_{idx:02d}_{mech.lower()}"
            d = out / tid
            (d / "binary").mkdir(parents=True, exist_ok=True)
            (d / "groundtruth").mkdir(parents=True, exist_ok=True)
            (d / "src.c").write_text(emit(mech, surf, flag, decoy, rng), encoding="utf-8")

            cc = f"gcc {a.opt} -no-pie -fno-stack-protector src.c -o binary/t"
            r = subprocess.run(cc, shell=True, cwd=d, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  BUILD FAIL {tid}: {r.stderr.splitlines()[:3]}")
                continue

            (d / "groundtruth" / "solve.py").write_text(
                f"#!/usr/bin/env python3\nFLAG = {flag!r}\nprint(FLAG)\n", encoding="utf-8")
            (d / "groundtruth" / "solve.py").chmod(0o755)

            json.dump({
                "task_id": tid, "archetype": "T-E", "mechanism_class": "T-E",
                "mechanical_variant_id": mech, "mechanism_variant": MECHANICS[mech],
                "target_w2_subtype": "visible_branch_asserted_reachable",
                "binary": "binary/t", "input_method": "argv", "stdin_append_newline": False,
                "compile": cc, "surfaces": surf, "artifact_residence": surf["residence"],
                "input_domain": {"min_len": len(flag), "max_len": len(flag),
                                 "charset": "printable_ascii"},
                "decoys": [{"value": decoy,
                            "kind": "string" if surf["residence"] == "present" else "runtime_assembled",
                            "why": "compared inside the unreachable accepting branch"}],
                "held_out": True,
            }, open(d / "manifest.json", "w"), indent=2, ensure_ascii=False)
            made.append((tid, mech, surf, flag))

    print(f"generated {len(made)} T-E instances in {out}")
    for tid, mech, surf, flag in made:
        print(f"  {tid:16s} {mech}  {surf['residence']:7s} {surf['guard_distance']:10s} "
              f"{surf['true_transform']:5s}  flag={flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
