/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * debug_gate() computes (x*x + 6UL) % 15 == 11, which is UNSATISFIABLE: the reachable residues
 * mod 15 do not include 11. The guarded branch that accepts service_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *service_key __attribute__((used)) = "FLAG{harbor_maple_8642}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x6b, 0x3f, 0xfe, 0x47, 0x3c, 0xad, 0x5f, 0xe6,
    0x60, 0xcf, 0x88, 0x24, 0xa9, 0x47, 0xfe, 0x74,
    0x11, 0x86, 0x0f, 0x59, 0x93, 0xe3, 0x6e
};
#define CT_LEN ((int)sizeof(target_ct))
static int debug_gate(unsigned long x){ return (int)(((x * x + 6UL) % 15UL) == 11UL); }
static int scan_block(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x2d;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 23UL;
    if (debug_gate(t)) {
        if (strcmp(argv[1], service_key) == 0) { puts("Correct."); return 0; }
    }
    if (scan_block(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
