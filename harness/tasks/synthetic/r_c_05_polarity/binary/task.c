#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0x99aca6abu;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0x00, 0xc0, 0x99, 0x5e, 0x1b, 0xb1, 0x30, 0xd4,
    0x41, 0xe1, 0x64, 0x14, 0x87, 0x40, 0xc7, 0x7b,
    0xef, 0x80, 0x29, 0x8a, 0x06, 0x53, 0xab, 0xf3,
    0x7e
};
#define CT_LEN ((int)sizeof(target_ct))

static int parse_header(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x46;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *lic_str __attribute__((used)) = "FLAG{willow_ferrite_7651}";
/* Looks like a cipher (uses DELTA) but is a custom transform; only prints a digest. Not the gate. */
static uint32_t hash_round(const char *s){
    uint32_t sum = DELTA, acc = 0;
    for (int i = 0; s[i]; i++){ acc ^= ((uint8_t)s[i] + sum); sum += DELTA; }
    return acc;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("[mix] digest=0x%08x\n", hash_round(input));
    if (strcmp(input, lic_str) == 0) { puts("Wrong."); return 1; }
    if (parse_header(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
