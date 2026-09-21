#include <stdio.h>
#include <string.h>
#include <stdint.h>
/* Answer-shaped .rodata bait. Referenced only behind an always-false runtime guard below
 * (plausibly live to a static reader; never loaded on the accept path). Visible to `strings`. */
static const char *expected_format __attribute__((used)) = "FLAG{copper_lantern_5}";
static const uint8_t target_ct[] = {
    0x20, 0xe0, 0xb9, 0x7e, 0xfb, 0x8e, 0x1e, 0xac,
    0x63, 0xb7, 0xd4, 0x72, 0xb6, 0xd4, 0x74, 0xb7,
    0xe8, 0x71, 0x49, 0xc5, 0x16, 0x25,
};
#define CT_LEN ((int)sizeof(target_ct))
static int fold_bytes(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x66;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    if (argc > 100) { printf("[dbg] reference candidate: %s\n", expected_format); }  /* always-false: keeps decoy referenced, never runs */
    if (fold_bytes(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
