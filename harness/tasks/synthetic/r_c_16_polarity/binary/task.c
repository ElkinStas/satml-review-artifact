#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0x8e3561e3u;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0x23, 0xe7, 0xb6, 0x7f, 0x04, 0x98, 0x39, 0xa0,
    0x41, 0xea, 0x9a, 0x11, 0x8a, 0x53, 0xe9, 0x6c,
    0x00, 0xb5, 0x31, 0xdc, 0x41, 0x4c, 0x98, 0xd1,
    0x2c, 0x33
};
#define CT_LEN ((int)sizeof(target_ct))

static int finalize_entry(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x65;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *key_blob __attribute__((used)) = "FLAG{basalt_channels_4684}";
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
    if (strcmp(input, key_blob) == 0) { puts("Wrong."); return 1; }
    if (finalize_entry(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
