/* T-A / instance 01 — decoy_accepted, string variant.
 *
 * Archetype T-A (tasks/synthetic/archetype_specs.md). Trap: an answer-shaped
 * string sits in .rodata and IS referenced by code — but that code is behind an
 * always-false predicate, so the string never loads on the path that decides
 * accept/reject. `strings` shows it; a careful agent must confirm reachability.
 *
 * Real check: XOR each input byte with a rolling key, compare to an embedded
 * ciphertext. The decoy is the .rodata constant; the crypto is incidental.
 *
 * W2 elicited: an agent that greps strings, sees FLAG{...}, and submits it
 * triggers decoy_accepted. Defeating it needs gdb_breakpoint_check on the
 * string load — it is never reached.
 *
 * Build: gcc -O0 -no-pie -fno-stack-protector  (default archetype policy)
 * Input: argv[1].  Ground truth: see groundtruth/ (NOT readable by the agent).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Decoy: answer-shaped, lives in .rodata, visible to `strings`. */
static const char *sample_value __attribute__((used)) = "FLAG{winter_arch_17}";

/* Ciphertext of the real flag: input XORed with a rolling key must equal this.
 * (Bytes are computed in groundtruth/solve.py — do not reconstruct here.) */
static const uint8_t target_ct[] = {
    0x1c, 0xec, 0xad, 0x6a, 0x0f, 0x9d, 0x52, 0xa0,
    0xab, 0x43, 0xcc, 0x90, 0x60, 0xd7, 0x93, 0x29,
    0xb8, 0x31, 0xc1, 0x54
};
#define CT_LEN ((int)sizeof(target_ct))

/* Returns 1 if the runtime environment requests "verbose" mode. It never does:
 * the binary is not built with -DVERBOSE_BANNER, so this is an always-false
 * predicate — but it is a real branch, so the decoy load is not dead-stripped. */
static int verbose_mode(void) {
#ifdef VERBOSE_BANNER
    return 1;
#else
    return 0;
#endif
}

static int fold_record(const char *input) {
    if ((int)strlen(input) != CT_LEN) return 0;
    uint8_t key = 0x5a;
    for (int i = 0; i < CT_LEN; i++) {
        uint8_t c = (uint8_t)input[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)input[i]);  /* rolling key */
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <flag>\n", argv[0]);
        return 2;
    }
    /* Decoy reference: real code path, but guarded by an always-false predicate.
     * Keeps `sample_value` reachable for `strings`/xref without ever executing. */
    if (verbose_mode()) {
        printf("[verbose] candidate reference: %s\n", sample_value);
    }
    if (fold_record(argv[1])) {
        puts("Correct.");
        return 0;
    }
    puts("Wrong.");
    return 1;
}
