/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * vendor_path() computes (x*x + 2UL) % 15 == 4, which is UNSATISFIABLE: the reachable residues
 * mod 15 do not include 4. The guarded branch that accepts backup_ref is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *backup_ref __attribute__((used)) = "FLAG{basalt_ferrite_7556}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x24, 0xe4, 0xb5, 0x72, 0x07, 0x86, 0x1d, 0xbc,
    0x4c, 0xc4, 0x5e, 0xc1, 0x9a, 0x16, 0xb7, 0x59,
    0xcc, 0x7a, 0xe7, 0xb8, 0x70, 0x48, 0x88, 0xdb,
    0x66
};
#define CT_LEN ((int)sizeof(target_ct))
static int vendor_path(unsigned long x){ return (int)(((x * x + 2UL) % 15UL) == 4UL); }
static int scan_block(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x62;
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
    if (scan_block(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
