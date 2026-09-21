#include <stdio.h>
#include <string.h>
/* transform_then_compare: affine map idx' = (7*idx + 11) mod N over a fixed alphabet, applied to
 * each inner char BEFORE comparison. visible_target is the POST-affine value in .rodata; raw
 * submission is wrong -- invert the affine (a is coprime to N). */
static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
#define NA ((int)(sizeof(ALPHA) - 1))
#define AA 7
#define BB 11
static const char *visible_target __attribute__((used)) = "flag{_jjp23ep2k3t7evc}";   /* flag{ affine(inner) } */
static const char ct_inner[] = "_jjp23ep2k3t7evc";
static int idx(char c){ for (int i = 0; i < NA; i++) if (ALPHA[i] == c) return i; return -1; }
static int verbose(void){ return visible_target[0] == 0; }
static int map_compare(const char *s){
    size_t n = strlen(s);
    if (n < 6 || strncmp(s, "flag{", 5) != 0 || s[n-1] != '}') return 0;
    int inner = (int)n - 6;
    if (inner != (int)strlen(ct_inner)) return 0;
    for (int i = 0; i < inner; i++){
        int k = idx(s[5 + i]); if (k < 0) return 0;
        if (ALPHA[(AA * k + BB) % NA] != ct_inner[i]) return 0;
    }
    return 1;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    if (verbose()) puts(visible_target);
    if (map_compare(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
