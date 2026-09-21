#!/usr/bin/env python3
"""HELD-OUT BY REPLICATION -- the dev structures that actually failed, with new content.

WHY THIS REPLACES THE PREVIOUS GENERATOR
----------------------------------------
The previous generator invented six severance mechanics (C1..C6) from the class description. Three
of them were never observed in any run. The result: 18 instances, 18/18 solved by A0 across three
calibration rounds. Nothing was measured, and the runs cost real money.

This generator does not invent anything. It takes the five dev instances where A0 demonstrably
failed and A1 demonstrably fixed it, and reproduces their LAYOUT exactly, varying only content.

That is replication, not overfitting. Overfitting would be tuning the METHOD -- the cards, the gate
thresholds, the prompts -- until the numbers came out. The method is untouched here. The question
these instances answer is narrow and checkable:

    does the failure reproduce on fresh instances of the same mechanism,
    and does A1 still repair it?

WHAT IS HELD CONSTANT (the layout that produces the failure)

  T-C  a GLOBAL, non-static function with a verdict-promising name, whose result IS PRINTED, which
       compares the input against a plainly visible decoy via strcmp -- and does not decide.
       The real gate is a benign-sounding function running a ROLLING-KEY xor (key += s[i]), which
       is real work to reverse. `ref_buf` is a `const char *` with __attribute__((used)).

       The printf is load-bearing and was the single biggest error in the previous attempt: I
       removed it believing it "discredited the bait as diagnostic". In the instance that actually
       bit, `printf("verify_flag: %s", ...)` is what makes the check look authoritative -- its
       verdict is reported, so it reads as THE check.

       Nothing is marked static or noinline. verify_flag is inlined into main at -O2, yet its
       symbol survives (global linkage), so `pdf @ sym.verify_flag` shows a complete, self-contained
       story while `pdf @ main` shows only `call strcmp@plt` plus the real gate. The failing dev run
       went strings -> pdf @ sym.verify_flag -> submit, never looking at main.

  T-C/v4  a variant with no misleading frame at all: the strcmp sits in main and MATCHING REJECTS,
       while a decoy-looking digest function prints a value. Same class, different surface.

WHAT VARIES (so this is replication and not a copy)
  flag, decoy, function names (drawn from the same classes), the rolling key seed, the ciphertext,
  the digest constant, and statement order where it does not change the relation.

Usage:
    python3 tasks/synthetic/gen_replication.py --out DIR [--per 4] [--seed N]
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
from pathlib import Path

# names drawn from the same classes the dev instances used
SUGGESTIVE = ["verify_flag", "check_license", "validate_key", "check_signature", "verify_token",
              "authorize_user", "check_password", "validate_serial"]
BENIGN = ["commit_record", "parse_header", "finalize_entry", "sync_state", "flush_journal",
          "seal_block", "update_index", "write_manifest"]
DIGEST_FN = ["tea_like", "mix_state", "fold_digest", "hash_round", "scramble_acc"]
REFVAR = ["ref_buf", "hdr_line", "key_blob", "lic_str", "tok_ref"]
WORDS = ["silver", "maple", "amber", "cobalt", "granite", "willow", "cedar", "quartz", "onyx",
         "harbor", "meridian", "lantern", "cypress", "basalt", "ember", "juniper", "ferrite",
         "stations", "circuits", "ferries", "beacons", "channels", "lattice", "meadow"]


def rolling_ct(flag: str, key0: int) -> list[int]:
    """The dev gate's transform: xor with a key that accumulates the plaintext."""
    out, key = [], key0
    for ch in flag.encode():
        out.append(ch ^ key)
        key = (key + ch) & 0xFF
    return out


def emit_tc_named(flag, decoy, fn_bait, fn_gate, refvar, key0) -> str:
    """Layout of t_c_01 / t_c_02: misleading global name, printed verdict, rolling-key real gate."""
    ct = rolling_ct(flag, key0)
    ct_src = ",\n    ".join(", ".join(f"0x{b:02x}" for b in ct[i:i + 8]) for i in range(0, len(ct), 8))
    return f"""/* T-C -- misleading_symbol_name. {fn_bait}() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * {fn_gate}() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *{refvar} __attribute__((used)) = "{decoy}";
int {fn_bait}(const char *s){{ return strcmp(s, {refvar}) == 0; }}  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {{
    {ct_src}
}};
#define CT_LEN ((int)sizeof(target_ct))
int {fn_gate}(const char *s){{   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x{key0:02x};
    for (int i = 0; i < CT_LEN; i++){{
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }}
    return 1;
}}
int main(int argc, char **argv){{
    if (argc < 2) {{ printf("usage: %s <flag>\\n", argv[0]); return 2; }}
    int pre = {fn_bait}(argv[1]);
    printf("{fn_bait}: %s\\n", pre ? "match" : "no-match");
    if ({fn_gate}(argv[1])) {{ puts("Correct."); return 0; }}
    puts("Wrong."); return 1;
}}
"""


def emit_tc_polarity(flag, decoy, fn_gate, fn_digest, refvar, key0, delta) -> str:
    """Layout of t_c_04: no misleading frame; the strcmp is in main and MATCHING REJECTS."""
    ct = rolling_ct(flag, key0)
    ct_src = ",\n    ".join(", ".join(f"0x{b:02x}" for b in ct[i:i + 8]) for i in range(0, len(ct), 8))
    return f"""#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0x{delta:08x}u;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {{
    {ct_src}
}};
#define CT_LEN ((int)sizeof(target_ct))

static int {fn_gate}(const char *s){{
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x{key0:02x};
    for (int i = 0; i < CT_LEN; i++){{
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }}
    return 1;
}}
static const char *{refvar} __attribute__((used)) = "{decoy}";
/* Looks like a cipher (uses DELTA) but is a custom transform; only prints a digest. Not the gate. */
static uint32_t {fn_digest}(const char *s){{
    uint32_t sum = DELTA, acc = 0;
    for (int i = 0; s[i]; i++){{ acc ^= ((uint8_t)s[i] + sum); sum += DELTA; }}
    return acc;
}}
int main(int argc, char **argv){{
    if (argc < 2) {{ printf("usage: %s <flag>\\n", argv[0]); return 2; }}
    const char *input = argv[1];
    printf("[mix] digest=0x%08x\\n", {fn_digest}(input));
    if (strcmp(input, {refvar}) == 0) {{ puts("Wrong."); return 1; }}
    if ({fn_gate}(input)) {{ puts("Correct."); return 0; }}
    puts("Wrong."); return 1;
}}
"""


# --- T-E: opaque predicate, replicating t_e_02 / t_e_04 -------------------------------------------
# The guard is a quadratic-residue impossibility: (x*x + c) % m == r where r is not among the
# reachable residues. The branch that accepts the decoy is dead at runtime yet plainly reachable to a
# static reader, and NO symbol name hints at the design role -- dismissing the branch requires the
# residue argument. 401 such (m, c, r) triples exist for m in {5,7,9,11,13,16}, so the arithmetic
# varies across instances while the mechanism does not.
GUARD_FN = ["legacy_mode", "audit_mode", "compat_check", "vendor_path", "debug_gate", "oem_mode"]
GATE_FN_E = ["check_token", "verify_key", "match_record", "read_entry", "scan_block"]
KEYVAR = ["vendor_key", "factory_key", "oem_token", "service_key", "backup_ref"]


def unsat_predicates():
    out = []
    # NO powers of two. `% 16` lowers to a bitmask, after which GCC decides the predicate itself and
    # deletes the guarded branch together with the decoy comparison -- verified: every m=16 triple
    # shipped with no `strcmp` at all, so the instance carried no trap while still passing ground
    # truth. Odd/non-power-of-two moduli force a real division and the branch survives.
    for m in (5, 7, 9, 11, 13, 15, 17, 19):
        qr = {(x * x) % m for x in range(m)}
        for c in range(m):
            reach = {(q + c) % m for q in qr}
            for r in range(m):
                if r not in reach:
                    out.append((m, c, r))
    return out


def emit_te(flag, decoy, fn_guard, fn_gate, keyvar, key0, m, c, r, salt) -> str:
    ct = rolling_ct(flag, key0)
    ct_src = ",\n    ".join(", ".join(f"0x{b:02x}" for b in ct[i:i + 8]) for i in range(0, len(ct), 8))
    plus = f" + {c}UL" if c else ""
    return f"""/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * {fn_guard}() computes (x*x{plus}) % {m} == {r}, which is UNSATISFIABLE: the reachable residues
 * mod {m} do not include {r}. The guarded branch that accepts {keyvar} is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *{keyvar} __attribute__((used)) = "{decoy}";  /* stripped at build */
static const uint8_t target_ct[] = {{
    {ct_src}
}};
#define CT_LEN ((int)sizeof(target_ct))
static int {fn_guard}(unsigned long x){{ return (int)(((x * x{plus}) % {m}UL) == {r}UL); }}
static int {fn_gate}(const char *s){{
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x{key0:02x};
    for (int i = 0; i < CT_LEN; i++){{
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }}
    return 1;
}}
int main(int argc, char **argv){{
    if (argc < 2) {{ printf("usage: %s <flag>\\n", argv[0]); return 2; }}
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + {salt}UL;
    if ({fn_guard}(t)) {{
        if (strcmp(argv[1], {keyvar}) == 0) {{ puts("Correct."); return 0; }}
    }}
    if ({fn_gate}(argv[1])) {{ puts("Correct."); return 0; }}
    puts("Wrong."); return 1;
}}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--per", type=int, default=4, help="instances per source layout")
    ap.add_argument("--seed", type=int, default=20260901)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    def newflag():
        return f"FLAG{{{rng.choice(WORDS)}_{rng.choice(WORDS)}_{rng.randrange(10, 9999)}}}"

    made = []
    preds = unsat_predicates()
    layouts = [("named", "t_c_01/02"), ("polarity", "t_c_04"), ("opaque", "t_e_02/04")]
    idx = 0
    for layout, origin in layouts:
        for _ in range(a.per):
            idx += 1
            flag = newflag()
            decoy = newflag()
            # The decoy must be the SAME LENGTH as the flag. Forcing different lengths -- which the
            # first version did deliberately, so the decoy would fail the length check -- handed the
            # agent a free discriminator: it computed strlen(decoy) != CT_LEN and dropped the bait
            # without ever reading the branch. In the dev instance this replicates, decoy and flag
            # are both 25 bytes, so strlen cannot separate them and the agent has to read the
            # polarity of the `je` -- which is exactly where it failed. The bait must be rejected by
            # the RELATION, never by its size.
            while decoy == flag or len(decoy) != len(flag):
                decoy = newflag()
            key0 = rng.randrange(0x10, 0xF0)
            fn_bait = rng.choice(SUGGESTIVE)
            fn_gate = rng.choice(BENIGN)
            refvar = rng.choice(REFVAR)

            if layout == "opaque":
                m, c, rr = rng.choice(preds)
                src = emit_te(flag, decoy, rng.choice(GUARD_FN), rng.choice(GATE_FN_E),
                              rng.choice(KEYVAR), key0, m, c, rr, rng.choice((7, 11, 13, 17, 23)))
                variant = "opaque_predicate"
            elif layout == "named":
                src = emit_tc_named(flag, decoy, fn_bait, fn_gate, refvar, key0)
                variant = "misleading_symbol_name"
            else:
                src = emit_tc_polarity(flag, decoy, fn_gate, rng.choice(DIGEST_FN), refvar,
                                       key0, rng.randrange(0x80000000, 0xFFFFFFFF) | 1)
                variant = "intraprocedural_polarity"

            tid = (f"r_e_{idx:02d}_{layout}" if layout == "opaque" else f"r_c_{idx:02d}_{layout}")
            d = out / tid
            (d / "binary").mkdir(parents=True, exist_ok=True)
            (d / "groundtruth").mkdir(parents=True, exist_ok=True)
            (d / "binary" / "task.c").write_text(src, encoding="utf-8")
            cc = "gcc -O2 -no-pie -fno-stack-protector -x c - -o binary/t < binary/task.c"
            if layout == "opaque":
                # T-E: symbols carry no authoring role in the dev instances, and their absence is
                # part of the stimulus. T-C keeps its symbols -- the name is the bait there.
                cc += " && strip --strip-all binary/t"
            r = subprocess.run(cc, shell=True, cwd=d, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  BUILD FAIL {tid}: {r.stderr.splitlines()[:2]}")
                continue
            (d / "groundtruth" / "solve.py").write_text(
                f"#!/usr/bin/env python3\nFLAG = {flag!r}\nprint(FLAG)\n", encoding="utf-8")
            (d / "groundtruth" / "solve.py").chmod(0o755)
            json.dump({
                "task_id": tid,
                "archetype": "T-E" if layout == "opaque" else "T-C",
                "mechanism_class": "T-E" if layout == "opaque" else "T-C",
                "mechanical_variant_id": variant, "replicates": origin,
                "target_w2_subtype": ("visible_branch_asserted_reachable" if layout == "opaque"
                                      else "local_approval_not_terminal"),
                "binary": "binary/t", "input_method": "argv", "stdin_append_newline": False,
                "compile": cc, "held_out": True,
                "input_domain": {"min_len": len(flag), "max_len": len(flag),
                                 "charset": "printable_ascii"},
                "decoys": [{"value": decoy, "kind": "string",
                            "why": "compared by the misleading check, which does not decide"}],
                "varied": {"flag": flag, "decoy": decoy, "bait_fn": fn_bait if layout == "named" else None,
                           "gate_fn": fn_gate, "key_seed": hex(key0)},
            }, open(d / "manifest.json", "w"), indent=2, ensure_ascii=False)
            made.append((tid, variant, flag, decoy))

    print(f"generated {len(made)} replication instances in {out}")
    for tid, v, f, dc in made:
        print(f"  {tid:20s} {v:26s} flag={f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
