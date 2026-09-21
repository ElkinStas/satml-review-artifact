/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * legacy_mode() computes (x*x + 11UL) % 13 == 9, which is UNSATISFIABLE: the reachable residues
 * mod 13 do not include 9. The guarded branch that accepts oem_token is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *oem_token __attribute__((used)) = "FLAG{meridian_basalt_331}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0xe6, 0xaa, 0x73, 0x34, 0xc1, 0x53, 0xfe, 0x72,
    0x00, 0x8d, 0x28, 0xc1, 0x7a, 0xec, 0x8d, 0x3f,
    0xdd, 0x4e, 0xe2, 0x5d, 0x57, 0xa1, 0xff, 0xc7,
    0x4a
};
#define CT_LEN ((int)sizeof(target_ct))
static int legacy_mode(unsigned long x){ return (int)(((x * x + 11UL) % 13UL) == 9UL); }
static int match_record(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xa0;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 11UL;
    if (legacy_mode(t)) {
        if (strcmp(argv[1], oem_token) == 0) { puts("Correct."); return 0; }
    }
    if (match_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
