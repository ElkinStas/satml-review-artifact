/* T-C / instance 01 -- symbol_overtrust (misleading_symbol_name).
 * verify_flag() is named like THE check and IS called (its result is printed), but it
 * compares against a decoy and does NOT decide acceptance. The real gate is commit_record()
 * (benign name). Trusting the symbol name -> submit the decoy -> wrong. Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *ref_buf __attribute__((used)) = "FLAG{silver_ferries_08}";
int verify_flag(const char *s){ return strcmp(s, ref_buf) == 0; }  /* misleading NAME; not the gate */
static const uint8_t target_ct[] = {
    0x6b, 0x3f, 0xfe, 0x47, 0x3c, 0xa1, 0x15, 0x38,
    0xaf, 0x1e, 0x14, 0x8b, 0x5d, 0x91, 0xa5, 0x1a,
    0xd2, 0x29, 0x3f, 0x8e, 0x96, 0x2f, 0xb2
};
#define CT_LEN ((int)sizeof(target_ct))
int commit_record(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x2d;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    int pre = verify_flag(argv[1]);
    printf("verify_flag: %s\n", pre ? "match" : "no-match");
    if (commit_record(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
