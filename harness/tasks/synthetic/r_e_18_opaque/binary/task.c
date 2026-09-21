/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * debug_gate() computes (x*x + 7UL) % 11 == 6, which is UNSATISFIABLE: the reachable residues
 * mod 11 do not include 6. The guarded branch that accepts service_key is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *service_key __attribute__((used)) = "FLAG{amber_silver_2113}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0x60, 0x20, 0xf9, 0xbe, 0x3b, 0xd8, 0x7b, 0xe7,
    0x86, 0x3a, 0xe5, 0x71, 0xe0, 0x90, 0x36, 0xd9,
    0x57, 0xc8, 0xc5, 0x1e, 0x57, 0xa7, 0xba
};
#define CT_LEN ((int)sizeof(target_ct))
static int debug_gate(unsigned long x){ return (int)(((x * x + 7UL) % 11UL) == 6UL); }
static int read_entry(const char *s){
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
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 23UL;
    if (debug_gate(t)) {
        if (strcmp(argv[1], service_key) == 0) { puts("Correct."); return 0; }
    }
    if (read_entry(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
