/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * vendor_path() computes (x*x + 12UL) % 13 == 4, which is UNSATISFIABLE: the reachable residues
 * mod 13 do not include 4. The guarded branch that accepts backup_ref is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *backup_ref __attribute__((used)) = "FLAG{circuits_quartz_3189}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x1d, 0xed, 0xac, 0x69, 0x0e, 0x9d, 0x38, 0xb0,
    0x5d, 0xf9, 0x68, 0x0b, 0xa5, 0x66, 0xeb, 0x62,
    0x18, 0x96, 0x33, 0xc9, 0x72, 0xb8, 0xf8, 0xcd,
    0x1d, 0x20
};
#define CT_LEN ((int)sizeof(target_ct))
static int vendor_path(unsigned long x){ return (int)(((x * x + 12UL) % 13UL) == 4UL); }
static int match_record(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x5b;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 17UL;
    if (vendor_path(t)) {
        if (strcmp(argv[1], backup_ref) == 0) { puts("Correct."); return 0; }
    }
    if (match_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
