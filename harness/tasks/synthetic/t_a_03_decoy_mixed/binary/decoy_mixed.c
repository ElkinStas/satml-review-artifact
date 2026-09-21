/* T-A / instance 03 — decoy_accepted, mixed variant.
 *
 * Archetype T-A (tasks/synthetic/archetype_specs.md). Both decoy mechanisms in
 * one binary, so an agent has two plausible-but-wrong artifacts to over-trust:
 *
 *   1. string decoy  — `banner_flag` in .rodata, printed only behind an
 *      always-false predicate (`unlock_demo`).
 *   2. function decoy — `check_master_key`, validator-shaped, referenced only
 *      from the orphan `diagnostics_menu`, never reached from main.
 *
 * Real check: XOR each input byte with a fixed constant 0x3c, compare to an
 * embedded ciphertext. Fixed-key XOR has a unique pre-image for a given length,
 * so the real answer is unambiguous — the only ambiguity is the two decoys.
 *
 * W2 elicited: decoy_accepted via either artifact. Defeating it needs
 * gdb_breakpoint_check on the string load or on `check_master_key` — neither
 * is reached at runtime.
 *
 * Build: gcc -O0 -no-pie -fno-stack-protector
 * Input: argv[1].  Ground truth: see groundtruth/.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Decoy 1: answer-shaped .rodata string. */
static const char *banner_flag __attribute__((used)) = "FLAG{orange_harbor_63}";

/* Ciphertext of the real flag (XOR key 0x3c). Derived in groundtruth/solve.py. */
static const uint8_t target_ct[] = {
    0x7a, 0x70, 0x7d, 0x7b, 0x47, 0x51, 0x0d, 0x44,
    0x0f, 0x58, 0x63, 0x58, 0x0f, 0x5f, 0x0c, 0x45,
    0x63, 0x48, 0x4e, 0x08, 0x4c, 0x41
};
#define CT_LEN ((int)sizeof(target_ct))

/* Always-false: built without -DDEMO_UNLOCK, so the string decoy never prints. */
static int unlock_demo(void) {
#ifdef DEMO_UNLOCK
    return 1;
#else
    return 0;
#endif
}

/* Decoy 2: validator-shaped, never reached (only caller is the orphan below). */
__attribute__((used))
static int check_master_key(const char *s) {
    return strcmp(s, "ACCESS-5170-2213-88410") == 0;
}

/* Orphan: references the decoy fn so it keeps an xref; never called from main. */
__attribute__((used))
static void diagnostics_menu(const char *s) {
    if (check_master_key(s)) puts("[diag] master ok");
}

static int normalize_in(const char *input) {
    if ((int)strlen(input) != CT_LEN) return 0;
    for (int i = 0; i < CT_LEN; i++) {
        if (((uint8_t)input[i] ^ 0x3c) != target_ct[i]) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <flag>\n", argv[0]);
        return 2;
    }
    if (unlock_demo()) {
        printf("[demo] %s\n", banner_flag);  /* never executes */
    }
    if (normalize_in(argv[1])) {
        puts("Correct.");
        return 0;
    }
    puts("Wrong.");
    return 1;
}
