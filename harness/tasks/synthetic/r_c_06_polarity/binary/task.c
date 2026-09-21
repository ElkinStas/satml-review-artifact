#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0xc049b1f7u;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0xeb, 0xbf, 0x7e, 0xc7, 0xbc, 0x25, 0xdb, 0x7a,
    0x12, 0x83, 0x27, 0xa2, 0x73, 0xe9, 0x8c, 0x3d,
    0xa0, 0x4e, 0xfa, 0x5d, 0x50, 0xab, 0xfe, 0x32,
    0x4f
};
#define CT_LEN ((int)sizeof(target_ct))

static int flush_journal(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xad;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *hdr_line __attribute__((used)) = "FLAG{basalt_cypress_3022}";
/* Looks like a cipher (uses DELTA) but is a custom transform; only prints a digest. Not the gate. */
static uint32_t mix_state(const char *s){
    uint32_t sum = DELTA, acc = 0;
    for (int i = 0; s[i]; i++){ acc ^= ((uint8_t)s[i] + sum); sum += DELTA; }
    return acc;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("[mix] digest=0x%08x\n", mix_state(input));
    if (strcmp(input, hdr_line) == 0) { puts("Wrong."); return 1; }
    if (flush_journal(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
