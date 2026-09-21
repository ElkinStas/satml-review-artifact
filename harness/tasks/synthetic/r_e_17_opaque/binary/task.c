/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * compat_check() computes (x*x + 10UL) % 17 == 13, which is UNSATISFIABLE: the reachable residues
 * mod 17 do not include 13. The guarded branch that accepts factory_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *factory_key __attribute__((used)) = "FLAG{channels_juniper_7377}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x29, 0xf9, 0x40, 0x05, 0xf2, 0x67, 0x0e, 0xa2,
    0x21, 0xd0, 0x73, 0xf7, 0x84, 0x35, 0xba, 0x48,
    0xd1, 0x65, 0xec, 0x81, 0x33, 0xb8, 0x61, 0xab,
    0xe3, 0x37, 0x4a
};
#define CT_LEN ((int)sizeof(target_ct))
static int compat_check(unsigned long x){ return (int)(((x * x + 10UL) % 17UL) == 13UL); }
static int check_token(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x6f;
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
    if (compat_check(t)) {
        if (strcmp(argv[1], factory_key) == 0) { puts("Correct."); return 0; }
    }
    if (check_token(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
