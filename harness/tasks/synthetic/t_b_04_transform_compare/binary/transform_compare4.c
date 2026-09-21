#include <stdio.h>
#include <string.h>
#include <stdint.h>
/* transform_then_compare, ONE-WAY variant: the visible constant is FNV-1a(inner) shaped as a flag.
 * It is the POST-transform value -- submitting it raw is wrong, and the hash cannot be inverted by
 * reading it. The real flag is a pre-image; it is NOT present in the binary. */
static const char *visible_target __attribute__((used)) = "FLAG{0eaccfc8}";   /* = FLAG{ hex(FNV1a(inner)) } -- bait */
#define STORED_HASH 0x0eaccfc8u
static uint32_t fnv1a(const char *s, size_t n){
    uint32_t hsh = 2166136261u;
    for (size_t i = 0; i < n; i++){ hsh ^= (uint8_t)s[i]; hsh *= 16777619u; }
    return hsh;
}
static int verbose(void){ return visible_target[0] == 0; }  /* references bait; never true */
static int digest_match(const char *s){
    size_t n = strlen(s);
    if (n < 6 || strncmp(s, "FLAG{", 5) != 0 || s[n-1] != '}') return 0;
    return fnv1a(s + 5, n - 6) == STORED_HASH;
}
int main(int argc, char **argv){
    if (argc < 2) { printf("usage: %s <flag>\n", argv[0]); return 2; }
    if (verbose()) puts(visible_target);
    if (digest_match(argv[1])) { puts("Correct."); return 0; }
    puts("Wrong."); return 1;
}
