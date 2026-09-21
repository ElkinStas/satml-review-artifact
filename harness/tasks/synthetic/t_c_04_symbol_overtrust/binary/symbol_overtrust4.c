#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0x9E3779B9u;  /* TEA/XXTEA golden-ratio constant */
static const uint8_t target_ct[] = {
    0xff, 0xb3, 0x0a, 0xcb, 0xa8, 0x20, 0x8c, 0x98,
    0x3f, 0xcd, 0x02, 0x50, 0xf4, 0x68, 0x09, 0xb6,
    0x3c, 0x8f, 0xdb, 0x7c, 0xea, 0xd9, 0x6f, 0xbc,
    0xbf,
};
#define CT_LEN ((int)sizeof(target_ct))

static int fold_state(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xb9;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *ref_buf __attribute__((used)) = "FLAG{amber_circuits_9214}";
/* Looks like TEA (uses DELTA) but is a custom transform; only prints a digest. Not the gate. */
static uint32_t tea_like(const char *s){
    uint32_t sum = DELTA, acc = 0;
    for (int i = 0; s[i]; i++){ acc ^= ((uint8_t)s[i] + sum); sum += DELTA; }
    return acc;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("[tea] digest=0x%08x\n", tea_like(input));
    if (strcmp(input, ref_buf) == 0) { puts("Wrong."); return 1; }
    if (fold_state(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
