/* T-C -- misleading_symbol_name. check_license() is named like THE check and IS called (its result
 * is printed), but it compares against a decoy and does NOT decide acceptance. The real gate is
 * commit_record() (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *tok_ref __attribute__((used)) = "FLAG{willow_basalt_7309}";
int check_license(const char *s){ return strcmp(s, tok_ref) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0xfd, 0x4d, 0x0c, 0xc9, 0xae, 0x33, 0xdc, 0x40,
    0xe5, 0x89, 0x25, 0x9a, 0x55, 0xe0, 0x6b, 0x19,
    0xa9, 0x2b, 0x94, 0x1c, 0x56, 0xa0, 0xf8, 0x7d
};
#define CT_LEN ((int)sizeof(target_ct))
int commit_record(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0xbb;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = check_license(argv[1]);
    printf("check_license: %s\n", pre ? "match" : "no-match");
    if (commit_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
