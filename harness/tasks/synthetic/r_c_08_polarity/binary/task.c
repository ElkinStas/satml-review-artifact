#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0x96bd355fu;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0xc8, 0x98, 0x61, 0x26, 0xd3, 0x41, 0xe0, 0x8b,
    0x28, 0xc1, 0x73, 0xf8, 0xa1, 0x3b, 0xa6, 0x5a,
    0xe8, 0x65, 0x01, 0x8c, 0x11, 0x99, 0xd8, 0x2b,
    0x73, 0xfe
};
#define CT_LEN ((int)sizeof(target_ct))

static int parse_header(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x8e;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *hdr_line __attribute__((used)) = "FLAG{quartz_channels_7049}";
/* Looks like a cipher (uses DELTA) but is a custom transform; only prints a digest. Not the gate. */
static uint32_t tea_like(const char *s){
    uint32_t sum = DELTA, acc = 0;
    for (int i = 0; s[i]; i++){ acc ^= ((uint8_t)s[i] + sum); sum += DELTA; }
    return acc;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("[mix] digest=0x%08x\n", tea_like(input));
    if (strcmp(input, hdr_line) == 0) { puts("Wrong."); return 1; }
    if (parse_header(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
