/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * vendor_path() computes (x*x + 14UL) % 15 == 2, which is UNSATISFIABLE: the reachable residues
 * mod 15 do not include 2. The guarded branch that accepts service_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *service_key __attribute__((used)) = "FLAG{granite_circuits_2569}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x9d, 0x6d, 0x2c, 0xe9, 0x8e, 0x1d, 0xb8, 0x30,
    0xdd, 0x79, 0xe8, 0x8b, 0x25, 0xe6, 0x7f, 0x0d,
    0x90, 0x3c, 0xa9, 0x5d, 0xf8, 0x5d, 0x57, 0xa1,
    0xf8, 0x37, 0x4a
};
#define CT_LEN ((int)sizeof(target_ct))
static int vendor_path(unsigned long x){ return (int)(((x * x + 14UL) % 15UL) == 2UL); }
static int match_record(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xdb;
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
        if (strcmp(argv[1], service_key) == 0) { puts("Correct."); return 0; }
    }
    if (match_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
