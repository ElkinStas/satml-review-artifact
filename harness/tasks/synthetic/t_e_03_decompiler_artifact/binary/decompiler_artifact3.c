#include <stdio.h>
#include <string.h>
#include <stdint.h>
/* T-E desync (variant of #01): a junk byte (0x3C = 'cmp al,imm8') after an unconditional jump
 * desyncs a linear-sweep disassembler, swallowing the real key load (movb $0x5c). At runtime the
 * jump skips the junk and the correct key 0x5c is used. Defeated by gdb at the key load. */
static const uint8_t target_ct[] = {
    0x1a, 0xee, 0xaf, 0x68, 0x0d, 0x9b, 0x36, 0xb8,
    0x67, 0xa7, 0xb1, 0x0e, 0x02, 0xbd, 0x2b, 0xde,
    0x4e, 0xe5, 0xa6, 0x6a, 0xf7,
};
#define CT_LEN ((int)sizeof(target_ct))
static uint8_t stage_state(void){
    uint8_t k;
    __asm__ volatile (
        "jmp 1f\n\t"
        ".byte 0x3C\n\t"        /* junk -> linear disasm reads 'cmp al,imm8', desyncing the view */
        "1:\n\t"
        "movb $0x5c, %%al\n\t"
        "movb %%al, %0\n\t"
        : "=r"(k) :: "al"
    );
    return k;
}
static int decode_in(const char *s){
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
    if (decode_in(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
