#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static const uint8_t target_ct[] = {
    0x3a, 0x8e, 0x4f, 0x08, 0xed, 0x62, 0xfd, 0x90,
    0x35, 0xa7, 0x07, 0x13, 0x84, 0x4e, 0xc6, 0x25,
    0x16, 0xcf, 0x3b, 0x37, 0x84, 0x8e, 0x33,
};
#define CT_LEN ((int)sizeof(target_ct))

static int compute_sum(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x7c;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *flag __attribute__((used)) = "FLAG{violet_pantry_451}";   /* variable literally named 'flag' -- bait */
const char *get_flag(void){ return flag; }                 /* symbol screams 'the flag'; not the gate */
static int checksum_ok(const char *s){ return compute_sum(s); }  /* benign name: the REAL gate */
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("loaded %zu-byte flag record\n", strlen(get_flag()));
    if (strcmp(input, flag) == 0) { puts("Wrong."); return 1; }
    if (compute_sum(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
