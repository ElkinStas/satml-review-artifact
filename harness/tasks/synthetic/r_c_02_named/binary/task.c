/* T-C -- misleading_symbol_name. validate_serial() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * finalize_entry() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *lic_str __attribute__((used)) = "FLAG{circuits_lantern_6763}";
int validate_serial(const char *s){ return strcmp(s, lic_str) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0x8b, 0x5f, 0x1e, 0xe7, 0x9c, 0x11, 0xa1, 0x28,
    0xde, 0x77, 0xe8, 0x98, 0x17, 0x88, 0x5a, 0xc3,
    0x77, 0x03, 0x82, 0x37, 0xd2, 0x43, 0x43, 0x87,
    0xd4, 0x29, 0x30
};
#define CT_LEN ((int)sizeof(target_ct))
int finalize_entry(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xcd;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = validate_serial(argv[1]);
    printf("validate_serial: %s\n", pre ? "match" : "no-match");
    if (finalize_entry(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
