#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static const uint8_t target_ct[] = {
    0x07, 0xcb, 0x92, 0x53, 0x20, 0xe7, 0x69, 0x03,
    0xd8, 0x6c, 0xe4, 0x37, 0x53, 0xc4, 0x96, 0x56,
    0xf1, 0xcc, 0x4d, 0xce, 0x97, 0x63, 0xff, 0xcc,
    0x4f,
};
#define CT_LEN ((int)sizeof(target_ct))

static int finalize(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x41;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
static const char *ref_buf __attribute__((used)) = "FLAG{cedar_sockets_36412}";
/* NAME says validate; LOGIC is inverted -> 'valid' for the decoy and other wrong inputs,
 * 'invalid' for the true flag. Trusting the name/printed cue misleads. */
int is_valid(const char *s){
    if (strcmp(s, ref_buf) == 0) return 1;      /* decoy -> "valid" */
    return finalize(s) ? 0 : 1;                  /* true flag -> 0 ("invalid") */
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    const char *input = argv[1];
    printf("is_valid: %s\n", is_valid(input) ? "yes" : "no");
    if (finalize(input)) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
