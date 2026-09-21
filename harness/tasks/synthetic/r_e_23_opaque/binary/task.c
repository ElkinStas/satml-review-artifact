/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * vendor_path() computes (x*x) % 17 == 6, which is UNSATISFIABLE: the reachable residues
 * mod 17 do not include 6. The guarded branch that accepts oem_token is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *oem_token __attribute__((used)) = "FLAG{quartz_ferries_2765}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x60, 0x20, 0xf9, 0xbe, 0x3b, 0xd3, 0x42, 0xf6,
    0x94, 0x37, 0xb5, 0x66, 0xf4, 0x65, 0x11, 0xad,
    0x24, 0xd5, 0x7c, 0x21, 0xeb, 0x2b, 0x7b, 0x4b,
    0xd6
};
#define CT_LEN ((int)sizeof(target_ct))
static int vendor_path(unsigned long x){ return (int)(((x * x) % 17UL) == 6UL); }
static int scan_block(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x26;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 7UL;
    if (vendor_path(t)) {
        if (strcmp(argv[1], oem_token) == 0) { puts("Correct."); return 0; }
    }
    if (scan_block(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
