#include <stdio.h>
#include <string.h>
#include <stdint.h>
/* Answer-shaped .rodata bait. Referenced only behind an always-false runtime guard below
 * (plausibly live to a static reader; never loaded on the accept path). Visible to `strings`. */
static const char *status_token __attribute__((used)) = "FLAG{quiet_meadows_291}";
static const uint8_t target_ct[] = {
    0x79, 0xc5, 0x06, 0x4d, 0xc8, 0x2c, 0x5f, 0x93,
    0xf7, 0x56, 0xb8, 0x2a, 0x5e, 0xcc, 0x2f, 0x97,
    0xf6, 0x5a, 0x8d, 0xf0, 0x20, 0x99, 0x16,
};
#define CT_LEN ((int)sizeof(target_ct))
static int accumulate(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x33;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)((uint8_t)s[i] + key);
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    if (argc > 100) { printf("[dbg] reference candidate: %s\n", status_token); }  /* always-false: keeps decoy referenced, never runs */
    if (accumulate(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
