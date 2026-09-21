#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
static const uint32_t DELTA = 0xb797c065u;  /* golden-ratio style constant */
static const uint8_t target_ct[] = {
    0x69, 0x39, 0x80, 0x45, 0x32, 0xa1, 0x44, 0xf4,
    0x9d, 0x2f, 0x90, 0x4d, 0xf8, 0x88, 0x0f, 0xba,
    0x2d, 0xd9, 0x52, 0xcb, 0xc0, 0x11, 0x6b, 0xa3,
    0xbe
};
#define CT_LEN ((int)sizeof(target_ct))

static int commit_record(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x2f;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *hdr_line __attribute__((used)) = "FLAG{ferries_willow_5079}";
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
    if (commit_record(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
