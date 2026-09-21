/* T-C -- misleading_symbol_name. authorize_user() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * commit_record() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *hdr_line __attribute__((used)) = "FLAG{cedar_cobalt_3285}";
int authorize_user(const char *s){ return strcmp(s, hdr_line) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0xf8, 0x48, 0x11, 0xd6, 0xa3, 0x30, 0xd3, 0x7f,
    0x1e, 0x92, 0x0d, 0xd9, 0x78, 0x08, 0x8e, 0x21,
    0xcf, 0x70, 0xb6, 0xf6, 0xcf, 0x19, 0x18
};
#define CT_LEN ((int)sizeof(target_ct))
int commit_record(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xbe;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = authorize_user(argv[1]);
    printf("authorize_user: %s\n", pre ? "match" : "no-match");
    if (commit_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
