/* T-E / instance 02 -- decompiler_artifact_trust (OPAQUE PREDICATE), distinct from #01's desync.
 * legacy_mode() computes (x*x + 1) % 7 == 0, which is UNSATISFIABLE: the quadratic residues mod 7
 * are {0,1,2,4}, so x*x can never be 6 mod 7. The guarded branch that accepts vendor_key is
 * therefore dead at runtime, while a static reader sees a plain reachable accept path.
 * Symbol names deliberately carry NO authoring role: nothing in the symbol table hints that this
 * branch is dead or that vendor_key is bait -- establishing that requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *vendor_key = "FLAG{granite_willows_58}";
static const uint8_t target_ct[] = {
    0x6b, 0x3f, 0xfe, 0x47, 0x3c, 0xa1, 0x4a, 0xf6,
    0x97, 0x3b, 0xb7, 0x68, 0xfb, 0x66, 0x1a, 0xb3,
    0x27, 0xce, 0x71, 0x1f, 0x80, 0x0e, 0x5a, 0xdf
};
#define CT_LEN ((int)sizeof(target_ct))
static int legacy_mode(unsigned long x){ return (int)(((x * x + 1UL) % 7UL) == 0UL); }
static int check_token(const char *s){
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
    unsigned long t = (unsigned long)strlen(argv[1]) * 1000003UL + 7UL;
    if (legacy_mode(t)) {
        if (strcmp(argv[1], vendor_key) == 0) { puts("Correct."); return 0; }
    }
    if (check_token(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
