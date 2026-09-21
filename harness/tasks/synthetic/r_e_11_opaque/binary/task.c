/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * audit_mode() computes (x*x + 8UL) % 17 == 5, which is UNSATISFIABLE: the reachable residues
 * mod 17 do not include 5. The guarded branch that accepts factory_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *factory_key __attribute__((used)) = "FLAG{ferrite_ferries_9402}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x3d, 0x8d, 0x4c, 0x09, 0xee, 0x73, 0x0a, 0x9c,
    0x2e, 0xab, 0x40, 0xd5, 0x46, 0x1a, 0xbf, 0x5e,
    0xc3, 0x6c, 0x1c, 0x93, 0x0c, 0x86, 0xd5, 0x2d,
    0x74, 0xfb
};
#define CT_LEN ((int)sizeof(target_ct))
static int audit_mode(unsigned long x){ return (int)(((x * x + 8UL) % 17UL) == 5UL); }
static int check_token(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x7b;
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
    if (audit_mode(t)) {
        if (strcmp(argv[1], factory_key) == 0) { puts("Correct."); return 0; }
    }
    if (check_token(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
