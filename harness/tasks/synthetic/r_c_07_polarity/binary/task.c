#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0xba6b5831u;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0xd6, 0x9a, 0x63, 0x24, 0xd1, 0x48, 0xf7, 0x96,
    0x3c, 0xd3, 0x5c, 0xfd, 0x6c, 0x0b, 0xa1, 0x2c,
    0xca, 0x7b, 0x1a, 0xb2, 0x15, 0x9f, 0xe8, 0x22,
    0x7b, 0x06
};
#define CT_LEN ((int)sizeof(target_ct))

static int sync_state(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x90;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *lic_str __attribute__((used)) = "FLAG{lantern_beacons_5801}";
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
    if (strcmp(input, lic_str) == 0) { puts("Wrong."); return 1; }
    if (sync_state(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
