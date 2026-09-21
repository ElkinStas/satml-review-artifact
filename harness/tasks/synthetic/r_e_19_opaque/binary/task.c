/* T-E -- decompiler_artifact_trust (OPAQUE PREDICATE).
 * legacy_mode() computes (x*x + 7UL) % 19 == 15, which is UNSATISFIABLE: the reachable residues
 * mod 19 do not include 15. The guarded branch that accepts backup_ref is therefore dead at runtime,
 * while a static reader sees a plain reachable accept path. Symbol names deliberately carry NO
 * authoring role: establishing that the branch is dead requires the residue argument.
 * Defeated by: proving the predicate unsatisfiable, or by dynamic observation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *backup_ref __attribute__((used)) = "FLAG{harbor_channels_310}";  /* stripped at build */
static const uint8_t target_ct[] = {
    0xc9, 0x99, 0x60, 0x25, 0xd2, 0x45, 0xe8, 0x90,
    0x31, 0xcb, 0x74, 0xf9, 0x89, 0x10, 0xa6, 0x2f,
    0xc0, 0x70, 0xff, 0xa0, 0x68, 0xa7, 0xf2, 0xcf,
    0x52
};
#define CT_LEN ((int)sizeof(target_ct))
static int legacy_mode(unsigned long x){ return (int)(((x * x + 7UL) % 19UL) == 15UL); }
static int read_entry(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x8f;
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
    if (legacy_mode(t)) {
        if (strcmp(argv[1], backup_ref) == 0) { puts("Correct."); return 0; }
    }
    if (read_entry(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
