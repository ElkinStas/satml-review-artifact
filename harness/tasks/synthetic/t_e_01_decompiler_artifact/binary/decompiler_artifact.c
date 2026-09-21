/* T-E / instance 01 -- decompiler_artifact_trust (disassembler-only surface).
 * The XOR key is loaded behind a jmp-over-junk desync: at RUNTIME the junk byte is skipped
 * and the correct key (0x2d) is used; a static reader trusting objdump's linear sweep sees
 * the key swallowed into a mis-decoded 'test'/'sub' stream. Defeated by gdb at the key load. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static const uint8_t target_ct[] = {
    0x6b, 0x3f, 0xfe, 0x47, 0x3c, 0xb1, 0x41, 0x9d,
    0xa9, 0x60, 0xe1, 0xba, 0x32, 0x8b, 0xd8, 0x69,
    0xca, 0x98, 0x51, 0xa2, 0xb7, 0x4a
};
#define CT_LEN ((int)sizeof(target_ct))
static uint8_t stage_state(void){
    uint8_t k;
    __asm__ volatile (
        "jmp 1f\n\t"
        ".byte 0xA8\n\t"            /* junk -> linear disasm reads 'test al,imm8', desyncing the view */
        "1:\n\t"
        "movb $0x2d, %%al\n\t"
        "movb %%al, %0\n\t"
        : "=r"(k) :: "al"
    );
    return k;
}
static int unpack(const char *s){
    if ((int)strlen(s) != CT_LEN) return 0;
    uint8_t key = stage_state();
    for (int i = 0; i < CT_LEN; i++){
        uint8_t c = (uint8_t)s[i] ^ key;
        if (c != target_ct[i]) return 0;
        key = (uint8_t)(key + (uint8_t)s[i]);
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    if (unpack(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
