/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * oem_mode() computes (x*x + 15UL) % 19 == 18, which is UNSATISFIABLE: the reachable residues
 * mod 19 do not include 18. The guarded branch that accepts service_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *service_key __attribute__((used)) = "FLAG{circuits_ferrite_2644}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0xfb, 0x4f, 0x0e, 0xd7, 0xac, 0x3f, 0xda, 0x56,
    0xff, 0x9b, 0x0a, 0xad, 0x43, 0xc4, 0x90, 0x11,
    0xb7, 0x2e, 0xc0, 0x45, 0xf7, 0xa8, 0x67, 0xb5,
    0x80, 0xc3, 0x5e
};
#define CT_LEN ((int)sizeof(target_ct))
static int oem_mode(unsigned long x){ return (int)(((x * x + 15UL) % 19UL) == 18UL); }
static int read_entry(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xbd;
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
    if (oem_mode(t)) {
        if (strcmp(argv[1], service_key) == 0) { puts("Correct."); return 0; }
    }
    if (read_entry(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
