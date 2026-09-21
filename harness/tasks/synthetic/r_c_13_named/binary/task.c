/* T-C -- misleading_symbol_name. validate_key() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * finalize_entry() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *tok_ref __attribute__((used)) = "FLAG{stations_ferries_9420}";
int validate_key(const char *s){ return strcmp(s, tok_ref) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0x0b, 0xdf, 0x9e, 0x67, 0x1c, 0x80, 0x21, 0xc8,
    0x69, 0x02, 0xb2, 0x39, 0xe2, 0x7f, 0x16, 0x9a,
    0x39, 0xc8, 0x5b, 0xef, 0x7c, 0xdd, 0xd0, 0x25,
    0x79, 0x4e, 0xcd
};
#define CT_LEN ((int)sizeof(target_ct))
int finalize_entry(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x4d;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = validate_key(argv[1]);
    printf("validate_key: %s\n", pre ? "match" : "no-match");
    if (finalize_entry(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
