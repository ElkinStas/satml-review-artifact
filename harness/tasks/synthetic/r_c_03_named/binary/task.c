/* T-C -- misleading_symbol_name. check_password() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * seal_block() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *tok_ref __attribute__((used)) = "FLAG{stations_onyx_8736}";
int check_password(const char *s){ return strcmp(s, tok_ref) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0xe7, 0xab, 0x72, 0x33, 0xc0, 0x5b, 0xc6, 0x69,
    0x0d, 0xa2, 0x4b, 0xec, 0x65, 0xe0, 0x9e, 0x32,
    0xa5, 0x4e, 0xef, 0x3d, 0x75, 0x44, 0x96, 0xab
};
#define CT_LEN ((int)sizeof(target_ct))
int seal_block(const char *s){   /* benign name; the REAL gate */
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
    int pre = check_password(argv[1]);
    printf("check_password: %s\n", pre ? "match" : "no-match");
    if (seal_block(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
