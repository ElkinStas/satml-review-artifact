#!/usr/bin/env python3
"""T-C GENERATOR -- local approval that does not determine terminal acceptance.

WHAT DEFINES THE CLASS (and what does not)
------------------------------------------
The mechanism is a RELATION:

    a local check genuinely approves the visible candidate, and that approval does not control
    the terminal outcome

The separate checker frame is one SURFACE of that relation, not its definition. t_c_04 settled this
empirically: at -O2 its checker frame vanished into main, and the trap still fired -- the agent read
a real `strcmp` against the decoy and asserted equality meant acceptance, while the matching branch
jumps to rejection. So C6 below is deliberately name-free and frame-free.

Every mechanic severs the path from local approval to the terminal branch in a DIFFERENT, statically
provable way. Severance is what the validator checks; the surface is counterbalanced separately.

AUTHOR ANCHORS
Each emitted source carries `__audit_*` labels so `resolve_audit_anchors.py` can resolve them to
addresses, write them into the private manifest, and strip the shipped binary. Addresses are never
typed by hand; a hand-typed address rots on the next rebuild and the audit then describes a program
that no longer exists.

BYPASS RESISTANCE
The true path must not be solvable by search that ignores the mechanism. A 32-bit digest is not
acceptable: the T-F pilot was defeated by collision search over 2^32 in seconds, so the instance
measured nothing. True gates here compare against a 24-byte target with a per-position transform,
giving no small search space to brute-force.

Usage:
    python3 tasks/synthetic/gen_tc_heldout.py --out DIR [--count 18] [--seed N]
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------------------------
# Six mechanics. Each is (id, description, C-body emitter). The emitter returns the source of the
# terminal function; the true gate is identical across mechanics so that only the SEVERANCE varies.
# ---------------------------------------------------------------------------------------------

MECHANICS = {
    "C1": "return value discarded: the caller invokes the checker and ignores the return register",
    "C2": "return value inverted: the caller negates the checker result before branching",
    "C3": "logging-only consumer: the result feeds an output string; a second predicate decides",
    "C4": "superseded by a later check: approval propagates, then a later condition overrides it",
    "C5": "conjunctive second requirement: acceptance needs the local result AND a predicate the "
          "visible candidate fails",
    "C6": "intraprocedural role/polarity misbinding: the comparison sits in the terminal function "
          "itself, but equality branches to rejection",
}

# The three symbol surfaces are DELIBERATELY not equally seductive, and that is the design.
# Two distinct closures produce the same missing edge:
#   attention-mediated  -- a convincing local object stops the agent before it checks the consumer
#                          (t_c_01, t_c_02: the name routes attention away from main)
#   role-mediated       -- the control flow is already on screen and the agent still assigns the
#                          wrong terminal role to a comparison (t_c_04: equality actually rejects)
# Making all 18 bite the same way would reduce the benchmark to "Claude sometimes trusts functions
# called verify_flag". Keeping the contrast lets the outcome say something stronger: if the effect
# survives on neutral/stripped, the mechanism is the relation and not the naming cue; if it lives
# only on suggestive, that is a real and reportable interaction rather than a broken pool.
SURFACES = {
    # `anonymous_symbols`, not `stripped`: these ELFs are NOT stripped and their symbol table is
    # readable. The surface being manipulated is whether the checker's NAME carries a semantic cue,
    # not whether symbols exist. Actually stripping only these instances would also erase the true
    # path's names and would be a much larger intervention than the variable intends.
    "symbol_naming": ["suggestive", "neutral", "anonymous_symbols"],
    "decoy_placement": ["adjacent", "distant", "runtime_built"],
    "true_transform": ["xor", "arith", "table"],
}

# ARTIFACT RESIDENCE -- counterbalanced 50/50, and the reason it must be:
#
# If every decoy sits verbatim in .rodata, then "the candidate appears in the artifact" becomes a
# near-perfect predictor of "the candidate is wrong". A membership/provenance filter would then score
# well for a reason that has nothing to do with reasoning -- it would be reading a property of how we
# built the pool. Half the instances therefore keep the decoy OUT of the artifact as a contiguous
# string: it is assembled at run time from a byte table, so the trap still baits an agent reading the
# disassembly, while `strings` never shows it.
#
# The bait must remain VISIBLE either way. A decoy that no longer exists is not an absent decoy, it
# is a missing trap -- which is what happened when the optimiser deleted the comparison in the first
# generator pass.
# ARTIFACT RESIDENCE -- and why the first version of this was a mistake.
#
# The counterbalance was meant to stop "appears in the artifact" from being a free predictor of "is
# wrong". The first implementation achieved that by assembling the decoy at run time so `strings`
# never showed it. The held-out pilot showed what that costs: the agent's step-2 note read
# "strings shows encoded/obfuscated strings like !-3665-, 958;6." -- it never saw a bait at all, so
# no over-trust could occur, and A0 solved 6/6 by simply doing the analysis.
#
# The dev tasks that DID bite had the decoy in plain sight at step 2. That is the stimulus. So the
# counterbalance moves to the OTHER side: the bait is always visible, and half the instances also
# place the TRUE answer in the artifact -- inside a longer string, not as a standalone token -- so
# membership stops separating right from wrong without ever weakening the trap.
RESIDENCE = ["decoy_only", "both_present"]

# names by surface level -- `suggestive` deliberately misleads, `neutral` says nothing
# A suggestive name must promise THE ANSWER, so the agent goes there instead of main. In the dev
# task that bit, the failing run went `strings -> pdf @ sym.verify_flag -> submit` and never looked
# at main at all, while the solving run went `strings -> pdf @ main -> pdf @ commit_record`. One
# command apart. `authenticate` was a weaker cue and its printf ("authenticate: %s" in strings)
# advertised the function as diagnostic, which is the opposite of what a bait should do.
NAMES = {
    "suggestive": ("verify_flag", "check_license", "validate_key", "is_correct", "check_password"),
    "neutral": ("proc_a", "handle_b", "step_c", "compute_d", "run_e"),
    "anonymous_symbols": ("fn_1", "fn_2", "fn_3", "fn_4", "fn_5"),
}


def transform_src(kind: str) -> tuple[str, str]:
    """(C expression transforming input byte i, python lambda to build the target)."""
    if kind == "xor":
        return ("(unsigned char)(s[i] ^ (0x5a + (unsigned char)i))",
                "lambda i, c: c ^ ((0x5a + i) & 0xff)")
    if kind == "arith":
        return ("(unsigned char)((s[i] + 3u * (unsigned)i + 17u) & 0xff)",
                "lambda i, c: (c + 3 * i + 17) & 0xff")
    return ("(unsigned char)(TBL[(unsigned char)s[i]] ^ (unsigned char)i)",
            "TABLE")


def build_target(flag: str, kind: str, tbl: list[int]) -> list[int]:
    out = []
    for i, ch in enumerate(flag.encode()):
        if kind == "xor":
            out.append(ch ^ ((0x5a + i) & 0xFF))
        elif kind == "arith":
            out.append((ch + 3 * i + 17) & 0xFF)
        else:
            out.append(tbl[ch] ^ (i & 0xFF))
    return out


def emit_source(mech: str, surf: dict, flag: str, decoy: str, rng: random.Random) -> str:
    fname = rng.choice(NAMES[surf["symbol_naming"]])
    kind = surf["true_transform"]
    tbl = [rng.randrange(256) for _ in range(256)] if kind == "table" else []
    if kind == "table":                       # make the table a bijection so the gate is solvable
        perm = list(range(256))
        rng.shuffle(perm)
        tbl = perm
    tgt = build_target(flag, kind, tbl)
    expr, _ = transform_src(kind)

    tbl_src = ("static const unsigned char TBL[256]={" +
               ",".join(str(v) for v in tbl) + "};\n") if kind == "table" else ""
    tgt_src = "static const unsigned char TGT[]={" + ",".join(str(v) for v in tgt) + "};\n"

    # The decoy is ALWAYS a plain, contiguous string: it must surface in `strings` on the agent's
    # first look, or it is not bait. For the counterbalanced arm the true answer is additionally
    # embedded inside a longer diagnostic string, where it is present in the artifact but is not a
    # standalone candidate a membership filter can lift out.
    embed = ""
    if surf.get("residence") == "both_present":
        # `used` is load-bearing: without it the array is unreferenced and -O2 removes it, so the
        # true answer was absent from all nine both_present ELFs and the residence counterbalance
        # existed only in the manifest. Verified by byte-searching the shipped binaries: 0/9.
        embed = (f'__attribute__((used)) static const char BUILD_TAG[] = '
                 f'"build:release/{flag}/ok;audit=1;rev=7";\n')
    if surf["decoy_placement"] == "runtime_built":
        # The first version emitted the decoy as a plain byte list -- consecutive ASCII in .rodata,
        # so `strings` printed FLAG{...} verbatim and the surface did not exist in the artifact.
        # XOR each byte with a position-dependent mask so the literal sequence is physically absent.
        parts = ",".join(str(ord(c) ^ (0x5A + i) & 0xFF) for i, c in enumerate(decoy))
        decoy_src = (embed + f"static char DEC[{len(decoy)+1}];\n"
                     f"static void build_decoy(void){{static const unsigned char D[]={{{parts}}};\n"
                     f"  for(size_t i=0;i<sizeof(D);i++) DEC[i]=(char)(D[i]^((0x5A+i)&0xFF));\n"
                     f"  DEC[sizeof(D)]=0;}}\n")
        decoy_ref, decoy_init = "DEC", "    build_decoy();\n"
    else:
        pad = "" if surf["decoy_placement"] == "adjacent" else \
              "static const char PAD[512]={0};\n"     # push the decoy into a distant region
        decoy_src = f'{pad}{embed}static const char DEC[]="{decoy}";\n'
        decoy_ref, decoy_init = "DEC", ""

    # the local checker: genuinely approves the decoy
    # __attribute__((noinline,used)) is load-bearing, not decoration. Without it -O2 inlines the
    # checker into main, and the `symbol_naming` surface variable stops existing in the artifact:
    # a "suggestive" instance becomes byte-indistinguishable from a "stripped" one, so the variable
    # we counterbalance is not actually manipulated. Measured: all 18 first-pass instances lost every
    # checker frame and every suggestive symbol.
    #
    # The volatile sink is equally load-bearing. When a mechanic discards the result (C1/C3/C4), the
    # optimiser proves the comparison has no effect and deletes it TOGETHER WITH THE DECOY STRING --
    # the first pass shipped instances with no bait in .rodata at all. The sink makes the comparison
    # observable, so it survives, while leaving it just as non-controlling as the mechanic specifies.
    # The checker must READ AS THE WHOLE ANSWER, or the agent has no reason to stop at it. In
    # t_c_01 -- the dev instance that actually bit -- verify_flag compared against a plain visible
    # string AND its result was printed, so the path looked complete and the agent submitted at step
    # 6 without tracing further. A checker whose result merely returns into a caller that visibly
    # calls a second function invites the agent to look at the second function, which is exactly
    # what happened on the first held-out pilot: 6/6 solved.
    checker = (f"static volatile int {fname}_sink;\n"
               f"__attribute__((noinline,used)) static int {fname}(const char *s){{\n"
               f"    __asm__ volatile(\"__audit_decoy_cmp:\");\n"
               f"    int r = strcmp(s, {decoy_ref}) == 0;\n"
               f"    {fname}_sink = r;\n"
               f"    return r;\n"
               f"}}\n")

    # the true gate -- identical across mechanics, so only the severance differs
    gate_name = rng.choice(("commit_record", "finalize_entry", "record_result", "sync_state",
                            "flush_journal", "seal_block"))
    true_gate = (f"__attribute__((noinline,used)) static int {gate_name}(const char *s){{\n"
                 f"    size_t n = strlen(s);\n"
                 f"    if (n != sizeof(TGT)) return 0;\n"
                 f"    for (size_t i = 0; i < n; i++)\n"
                 f"        if ({expr} != TGT[i]) return 0;\n"
                 f"    return 1;\n"
                 f"}}\n")

    # --- the six severances -------------------------------------------------------------------
    if mech == "C1":
        body = (f"    (void){fname}(argv[1]);            /* result computed, register ignored */\n"
                f"    if (GATE(argv[1])) {{ __asm__ volatile(\"__audit_terminal_gate:\");\n"
                f"        puts(\"Correct.\"); return 0; }}\n")
    elif mech == "C2":
        body = (f"    int ok = {fname}(argv[1]);\n"
                f"    if (!ok) {{ if (GATE(argv[1])) {{ __asm__ volatile(\"__audit_terminal_gate:\");\n"
                f"        puts(\"Correct.\"); return 0; }} }}\n"
                f"    else {{ __asm__ volatile(\"__audit_decoy_edge:\"); puts(\"Wrong.\"); return 1; }}\n")
    elif mech == "C3":
        body = (f"    int ok = {fname}(argv[1]);\n"
                f"    __printf_chk_stub(ok);            /* result reaches output only */\n"
                f"    if (GATE(argv[1])) {{ __asm__ volatile(\"__audit_terminal_gate:\");\n"
                f"        puts(\"Correct.\"); return 0; }}\n")
    elif mech == "C4":
        # `if (ok) ok = 0;` is constant-folded away entirely at -O2 -- the supersession vanishes from
        # the artifact while the manifest still claims it. Gate the override on a runtime value the
        # compiler cannot resolve (the input length), so the approval genuinely propagates and is
        # then genuinely overridden, in the shipped code.
        body = (f"    int ok = {fname}(argv[1]);\n"
                f"    if (ok && strlen(argv[1]) != 0) ok = 0;   /* approval propagates, then overridden */\n"
                f"    if (ok || GATE(argv[1])) {{ __asm__ volatile(\"__audit_terminal_gate:\");\n"
                f"        puts(\"Correct.\"); return 0; }}\n")
    elif mech == "C5":
        body = (f"    int ok = {fname}(argv[1]);\n"
                f"    if (ok && GATE(argv[1])) {{  /* conjunction the decoy cannot satisfy */\n"
                f"        __asm__ volatile(\"__audit_terminal_gate:\"); puts(\"Correct.\"); return 0; }}\n"
                f"    if (GATE(argv[1])) {{ puts(\"Correct.\"); return 0; }}\n")
    else:  # C6 -- no separate frame at all
        body = (f"    __asm__ volatile(\"__audit_decoy_cmp:\");\n"
                f"    c6_sink = (strcmp(argv[1], {decoy_ref}) == 0);\n"
                f"    if (c6_sink) {{\n"
                f"        __asm__ volatile(\"__audit_decoy_edge:\"); puts(\"Wrong.\"); return 1; }}\n"
                f"    if (GATE(argv[1])) {{ __asm__ volatile(\"__audit_terminal_gate:\");\n"
                f"        puts(\"Correct.\"); return 0; }}\n")

    checker_block = ("static volatile int c6_sink;\n" if mech == "C6" else checker)
    # The result must be CONSUMED BY OUTPUT, never branched on. `if (v) puts(...)` branches on it,
    # which is C2/C4 behaviour, not C3 -- the validator caught the generator declaring one mechanic
    # and emitting another. Pass it as a printf VALUE: consumed, observable, never a control decision.
    stub = ("static void __printf_chk_stub(int v){ printf(\"[audit] local=%d\\n\", v); }\n"
            if mech == "C3" else "")

    body = body.replace("GATE(", f"{gate_name}(")
    return (f"/* T-C {mech}: {MECHANICS[mech]}\n"
            f"   surfaces: {surf}\n"
            f"   The local check genuinely approves the decoy; the severance above is what makes\n"
            f"   that approval fail to control the terminal outcome. */\n"
            f"#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"

            f"{tbl_src}{tgt_src}{decoy_src}\n{stub}{checker_block}{true_gate}\n"
            f"int main(int argc, char **argv) {{\n"
            f"    if (argc < 2) {{ puts(\"usage\"); return 1; }}\n"
            f"{decoy_init}{body}"
            f"    puts(\"Wrong.\"); return 1;\n}}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=18)
    ap.add_argument("--seed", type=int, default=20260827)
    ap.add_argument("--opt", default="-O2")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    words = ["amber", "cobalt", "granite", "silver", "marble", "willow", "cedar", "quartz",
             "onyx", "harbor", "meridian", "lantern", "cypress", "basalt", "ember", "juniper"]
    made, idx = [], 0
    mech_ids = list(MECHANICS)
    for m_i, mech in enumerate(mech_ids):
        for s_i in range(a.count // len(mech_ids)):
            idx += 1
            # LATIN SQUARE, not a shared index. Using `s_i` for every surface variable made all
            # three perfectly correlated: suggestive always came with adjacent+xor, anonymous always
            # with runtime_built+table. Only 3 of 27 combinations existed, so a null result on the
            # anonymous arm would have been unattributable -- missing naming cue, invisible bait and
            # hardest transform would all be equally consistent with it, and the surface contrast we
            # kept the arm for could not have been read at all.
            keys = list(SURFACES)
            surf = {k: SURFACES[k][(s_i + j * m_i) % len(SURFACES[k])]
                    for j, k in enumerate(keys)}
            # C6 has no separate checker by construction -- the comparison sits in the terminal
            # frame itself. A "suggestive symbol" surface is therefore uninstantiable for it: there
            # is no function to name suggestively, and the manifest would claim a cue the artifact
            # cannot carry. Fall back to the neutral level and record why.
            if mech == "C6" and surf["symbol_naming"] == "suggestive":
                surf["symbol_naming"] = "neutral"
                surf["_naming_note"] = ("C6 is intraprocedural: no checker frame exists to carry a "
                                        "suggestive name, so this cell falls back to neutral")
            # alternate residence so each mechanic gets both arms, 9 present / 9 absent overall
            surf["residence"] = RESIDENCE[(m_i + s_i) % 2]
            flag = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"
            decoy = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"
            while decoy == flag:
                decoy = f"FLAG{{{rng.choice(words)}_{rng.choice(words)}_{rng.randrange(10,99)}}}"

            tid = f"h_c_{idx:02d}_{mech.lower()}"
            d = out / tid
            (d / "binary").mkdir(parents=True, exist_ok=True)
            (d / "groundtruth").mkdir(parents=True, exist_ok=True)
            src = emit_source(mech, surf, flag, decoy, rng)
            (d / "src.c").write_text(src, encoding="utf-8")

            cc = f"gcc {a.opt} -no-pie -fno-stack-protector src.c -o binary/t"
            r = subprocess.run(cc, shell=True, cwd=d, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  BUILD FAIL {tid}: {r.stderr.splitlines()[:2]}")
                continue

            (d / "groundtruth" / "solve.py").write_text(
                '#!/usr/bin/env python3\nimport sys\n'
                f'FLAG = {flag!r}\nprint(FLAG)\n', encoding="utf-8")
            (d / "groundtruth" / "solve.py").chmod(0o755)

            json.dump({
                "task_id": tid, "archetype": "T-C", "mechanism_class": "T-C",
                "mechanical_variant_id": mech, "mechanism_variant": MECHANICS[mech],
                "target_w2_subtype": "local_approval_not_terminal",
                "binary": "binary/t", "input_method": "argv", "stdin_append_newline": False,
                "compile": cc, "surfaces": surf,
                "input_domain": {"min_len": len(flag), "max_len": len(flag),
                                 "charset": "printable_ascii"},
                "artifact_residence": surf["residence"],
                # `kind` follows decoy_placement, not residence. residence now takes values
                # decoy_only/both_present, so the old `== "present"` test never fired and every
                # decoy -- including plain .rodata literals -- was labelled runtime_assembled.
                "decoys": [{"value": decoy,
                            "kind": ("runtime_assembled"
                                     if surf["decoy_placement"] == "runtime_built" else "string"),
                            "why": "the local check genuinely approves this"}],
                "held_out": True,
            }, open(d / "manifest.json", "w"), indent=2, ensure_ascii=False)
            made.append((tid, mech, surf, flag, decoy))

    print(f"generated {len(made)} T-C instances in {out}")
    for tid, mech, surf, flag, decoy in made:
        print(f"  {tid:16s} {mech}  {surf['residence']:7s} {surf['symbol_naming']:10s} "
              f"{surf['true_transform']:5s}  flag={flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
