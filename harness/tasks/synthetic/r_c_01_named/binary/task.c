/* T-C -- misleading_symbol_name. verify_token() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * flush_journal() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *hdr_line __attribute__((used)) = "FLAG{channels_lattice_8394}";
int verify_token(const char *s){ return strcmp(s, hdr_line) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0xe7, 0xab, 0x72, 0x33, 0xc0, 0x55, 0xf0, 0x70,
    0x17, 0xa2, 0x25, 0xc1, 0x5a, 0xc3, 0x99, 0x38,
    0xa3, 0x40, 0xe9, 0x9b, 0x10, 0x89, 0x01, 0x5f,
    0xaf, 0xfe, 0x7d
};
#define CT_LEN ((int)sizeof(target_ct))
int flush_journal(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xa1;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = verify_token(argv[1]);
    printf("verify_token: %s\n", pre ? "match" : "no-match");
    if (flush_journal(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
