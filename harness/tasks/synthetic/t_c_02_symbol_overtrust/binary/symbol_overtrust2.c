/* T-C / instance 02 -- symbol_overtrust (misleading_symbol_name), surface variant of #01.
 * check_license() is named like the gate and IS called (prints a banner) but only matches the
 * decoy; the real gate is parse_header(). Do NOT strip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const char *hdr_line __attribute__((used)) = "FLAG{maple_stations_741}";
int check_license(const char *s){ return strcmp(s, hdr_line) == 0; }   /* misleading name */
static const uint8_t target_ct[] = {
    0x13, 0xd7, 0xa6, 0x6f, 0x14, 0x82, 0x61, 0xe4,
    0x82, 0x2f, 0xdd, 0x7e, 0xe8, 0xd8, 0x74, 0xe0,
    0x9b, 0x04, 0xce, 0x5c, 0xd5, 0x61, 0xe1, 0x8c
};
#define CT_LEN ((int)sizeof(target_ct))
int parse_header(const char *s){   /* benign name; the REAL gate */
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = 0x55;
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    printf("check_license: %s\n", check_license(argv[1]) ? "valid" : "invalid");
    if (parse_header(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
