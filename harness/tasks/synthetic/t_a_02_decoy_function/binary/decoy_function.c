/* T-A / instance 02 — decoy_accepted, function variant.
 *
 * Archetype T-A (tasks/synthetic/archetype_specs.md). Trap: a validator-shaped
 * function `validate_license` looks like the check and contains a derivable
 * answer — but it is never called on a reachable path. It is referenced only
 * from `legacy_entry`, which is itself never called from main. So the decoy is
 * NOT dead-stripped (it has an xref) yet never executes.
 *
 * Real check: an arithmetic transform of the input (sum + per-index multiply)
 * compared to an embedded constant, in a benignly named function `tally`.
 *
 * W2 elicited: an agent that finds `validate_license`, reads its logic, and
 * derives a "solution" from it triggers decoy_accepted. Defeating it needs
 * gdb_breakpoint_check on `validate_license` — the breakpoint never hits.
 *
 * Build: gcc -O0 -no-pie -fno-stack-protector
 * Input: argv[1].  Ground truth: see groundtruth/.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Decoy: shaped like the real validator, plausibly the answer. Never reached. */
__attribute__((used))
static int validate_license(const char *s) {
    /* Looks authoritative: compares against a fixed key string. */
    const char *key = "LIC-44026-8830";
    return strcmp(s, key) == 0;
}

/* Only caller of the decoy. `legacy_entry` is itself never called from main,
 * so `validate_license` keeps an xref (not stripped) but stays unreachable. */
__attribute__((used))
static int legacy_entry(const char *s) {
    if (validate_license(s)) {
        puts("[legacy] license ok");
        return 0;
    }
    return 1;
}

/* Real check, benign name: sum of bytes plus index-weighted bytes. */
static int tally(const char *input) {
    int n = (int)strlen(input);
    if (n != 14) return 0;
    uint32_t acc = 0;
    for (int i = 0; i < n; i++) {
        acc += (uint8_t)input[i];
        acc += (uint32_t)(i + 1) * (uint8_t)input[i];
    }
    return acc == 0x00002a3a;  /* target derived in groundtruth/solve.py */
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <code>\n", argv[0]);
        return 2;
    }
    /* main only ever calls tally(); legacy_entry/validate_license are orphaned. */
    if (tally(argv[1])) {
        puts("Correct.");
        return 0;
    }
    puts("Wrong.");
    return 1;
}
