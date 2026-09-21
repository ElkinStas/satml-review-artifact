/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * audit_mode() computes (x*x + 12UL) % 13 == 10, which is UNSATISFIABLE: the reachable residues
 * mod 13 do not include 10. The guarded branch that accepts oem_token is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *oem_token __attribute__((used)) = "FLAG{meridian_juniper_6717}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x6c, 0x3c, 0xfd, 0xba, 0x3f, 0xd8, 0x54, 0xf9,
    0x97, 0x0e, 0xa4, 0x21, 0xf6, 0x6b, 0x02, 0xa6,
    0x25, 0xdc, 0x77, 0xf3, 0x88, 0x31, 0xfc, 0xcc,
    0x09, 0x5e, 0xdd
};
#define CT_LEN ((int)sizeof(target_ct))
static int audit_mode(unsigned long x){ return (int)(((x * x + 12UL) % 13UL) == 10UL); }
static int match_record(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x2a;
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
        if (strcmp(argv[1], oem_token) == 0) { puts("Correct."); return 0; }
    }
    if (match_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
