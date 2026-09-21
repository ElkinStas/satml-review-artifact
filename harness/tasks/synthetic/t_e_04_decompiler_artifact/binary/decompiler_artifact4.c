/* T-E / instance 04 -- decompiler_artifact_trust (OPAQUE PREDICATE, residue variant of #02).
 * audit_mode() computes (x*x) % 3 == 2, which is UNSATISFIABLE: squares mod 3 are {0,1}, never 2.
 * The branch accepting factory_key is dead at runtime but reachable-looking statically. As in #02,
 * no symbol name reveals the design role; dismissing the branch requires the residue argument.
 * Distinct from #02 by modulus and by the shape of the impossibility. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *factory_key = "FLAG{marble_brook_31}";
static const uint8_t target_ct[] = {
    0x6b, 0x3f, 0xfe, 0x47, 0x3c, 0xa3, 0x4e, 0xf2,
    0x97, 0x25, 0x96, 0x59, 0xec, 0x6f, 0x1d, 0x95,
    0x2f, 0x90, 0x19, 0x52, 0xe1
};
#define CT_LEN ((int)sizeof(target_ct))
static int audit_mode(unsigned long x){ return (int)(((x * x) % 3UL) == 2UL); }
static int verify_key(const char *s){
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
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 11UL;
    if (audit_mode(t)) {
        if (strcmp(argv[1], factory_key) == 0) { puts("Correct."); return 0; }
    }
    if (verify_key(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
