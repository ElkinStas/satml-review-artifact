/* T-B / instance 01 -- unverified_candidate_submission (transform_then_compare).
 * The input's inner is shifted by +7 in a fixed alphabet BEFORE comparison. The visible
 * constant (visible_target, in .rodata) is the POST-transform value -- submitting it raw
 * is wrong. Defeated by inverting the transform or running candidates. */
#include <stdio.h>
#include <string.h>
static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
#define NA ((int)(sizeof(ALPHA) - 1))
#define SHIFT 7
static const char *visible_target __attribute__((used)) = "FLAG{0yauzm7ytg0o_g8uw10}";   /* FLAG{ shift(inner,+7) } -- POST-transform value */
static const char ct_inner[] = "0yauzm7ytg0o_g8uw10";        /* compared-against inner (post-transform) */
static int verbose_mode(void){
#ifdef VERBOSE_BANNER
    return 1;
#else
    return 0;
#endif
}
static int idx(char c){ for (int i = 0; i < NA; i++) if (ALPHA[i] == c) return i; return -1; }
static int stage_compare(const char *s){
    size_t n = strlen(s);
    if (n < 6 || strncmp(s, "FLAG{", 5) != 0 || s[n - 1] != '}') return 0;
    size_t inner = n - 6;
    if (inner != strlen(ct_inner)) return 0;
    for (size_t i = 0; i < inner; i++){
        int k = idx(s[5 + i]);
        if (k < 0) return 0;
        if (ALPHA[(k + SHIFT) % NA] != ct_inner[i]) return 0;
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    if (verbose_mode()) { printf("[v] target=%s\n", visible_target); }
    if (stage_compare(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
