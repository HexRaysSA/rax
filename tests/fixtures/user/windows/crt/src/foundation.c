#include "common.h"
static void allocation(void) {
    unsigned char *p, *q;
    char *text;
    WORD *wide;
    SIZE i;
    const WORD source[] = {0x0041, 0x20ac, 0xd800, 0};
    check(_get_heap_handle() != 0, 1);
    p = malloc(0); check(p != 0, 2); free(p); free(0);
    p = malloc(37); check(p && ((UPTR)p & (sizeof(UPTR) == 4 ? 7 : 15)) == 0, 3);
    check(_msize(p) >= 37, 4);
    for (i = 0; i < 37; ++i) p[i] = (unsigned char)(i * 3 + 1);
    q = realloc(p, 111); check(q != 0, 5);
    for (i = 0; i < 37; ++i) check(q[i] == (unsigned char)(i * 3 + 1), 6);
    p = realloc(q, 13); check(p != 0, 7);
    for (i = 0; i < 13; ++i) check(p[i] == (unsigned char)(i * 3 + 1), 8);
    *_errno() = 0;
    q = realloc(p, FULL_SIZE); check(q == 0 && *_errno() == ENOMEM, 9);
    for (i = 0; i < 13; ++i) check(p[i] == (unsigned char)(i * 3 + 1), 10);
    check(realloc(p, 0) == 0, 11);
    p = realloc(0, 19); check(p != 0, 12); free(p);
    p = calloc(9, 7); check(p != 0, 13);
    for (i = 0; i < 63; ++i) check(p[i] == 0, 14);
    free(p);
    *_errno() = 0;
    check(calloc(FULL_SIZE / 2 + 1, 2) == 0 && *_errno() == ENOMEM, 15);
    text = _strdup("copy"); check(text && strcmp(text, "copy") == 0, 16); free(text);
    wide = _wcsdup(source); check(wide && wcscmp(wide, source) == 0, 17); free(wide);
    p = malloc(64); check(p != 0, 18);
    for (i = 0; i < 32; ++i) p[i] = (unsigned char)(i ^ 0x5a);
    q = _expand(p, 32); check(q == p, 19);
    for (i = 0; i < 32; ++i) check(p[i] == (unsigned char)(i ^ 0x5a), 20);
    check(_expand(p, FULL_SIZE) == 0, 21);
    for (i = 0; i < 32; ++i) check(p[i] == (unsigned char)(i ^ 0x5a), 22);
    free(p);
}
static void bytes(void) {
    char a[32], b[32];
    const unsigned char high[] = {0x80, 0};
    const unsigned char low[] = {0x7f, 0};
    SIZE i;
    check(memset(a, 0x123, sizeof(a)) == a, 30);
    for (i = 0; i < sizeof(a); ++i) check((unsigned char)a[i] == 0x23, 31);
    check(memcpy(b, a, sizeof(a)) == b && memcmp(a, b, sizeof(a)) == 0, 32);
    check(memcmp(high, low, 1) > 0 && memcmp(low, high, 1) < 0, 33);
    check(memchr(high, 0x180, 2) == high && memchr(high, 1, 2) == 0, 34);
    check(strcpy(a, "abcdef") == a, 35);
    check(memmove(a + 2, a, 5) == a + 2 && memcmp(a, "ababcde", 7) == 0, 36);
    check(memmove(a, a + 2, 5) == a && memcmp(a, "abcde", 5) == 0, 37);
    check(strcpy(a, "abca") == a && strlen(a) == 4, 38);
#ifndef LEGACY_CRT
    check(strnlen(a, 2) == 2 && strnlen(a, 9) == 4 && strnlen(a, 0) == 0, 39);
#endif
    check(strcmp((const char *)high, (const char *)low) > 0, 40);
    check(strncmp("abX", "abY", 2) == 0 && strncmp("abX", "abY", 3) < 0, 41);
    check(strncmp("different", "text", 0) == 0, 42);
    check(strchr(a, 'a') == a && strrchr(a, 'a') == a + 3, 43);
    check(strchr(a, 0) == a + 4 && strrchr(a, 0) == a + 4 && strchr(a, 'z') == 0, 44);
    check(strstr(a, "bc") == a + 1 && strstr(a, "") == a && strstr(a, "z") == 0, 45);
    memset(b, 0x55, sizeof(b));
    check(strncpy(b, "xy", 5) == b && b[0] == 'x' && b[1] == 'y', 46);
    check(b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0x55, 47);
    b[3] = 0x55;
    check(strncpy(b, "abcdef", 3) == b && strncmp(b, "abc", 3) == 0 && b[3] == 0x55, 48);
    strcpy(b, "a"); check(strcat(b, "bc") == b && strcmp(b, "abc") == 0, 49);
    check(strncat(b, "def", 2) == b && strcmp(b, "abcde") == 0, 50);
    check(strncat(b, "ignored", 0) == b && strcmp(b, "abcde") == 0, 51);
    check(memcpy(b, a, 0) == b && memmove(b, a, 0) == b && memset(b, 1, (0)) == b, 52);
    check(memcmp(b, a, 0) == 0 && memchr(a, 'a', 0) == 0, 53);
}
static void units(void) {
    WORD a[24], b[24];
    const WORD text[] = {0x41, 0x20ac, 0xd800, 0x41, 0};
    const WORD needle[] = {0x20ac, 0xd800, 0};
    const WORD empty[] = {0};
    const WORD low[] = {0x7fff, 0}, high[] = {0x8000, 0};
    const WORD two[] = {0x31, 0x32, 0};
    SIZE i;
    check(wcscpy(a, text) == a && wcslen(a) == 4, 65);
#ifndef LEGACY_CRT
    check(wcsnlen(a, 2) == 2 && wcsnlen(a, 9) == 4 && wcsnlen(a, 0) == 0, 66);
#endif
    check(wcscmp(high, low) > 0 && wcsncmp(text, needle, 0) == 0, 67);
    check(wcsncmp(a, text, 4) == 0 && wcscmp(a, text) == 0, 68);
    check(wcschr(a, 0x41) == a && wcsrchr(a, 0x41) == a + 3, 69);
    check(wcschr(a, 0) == a + 4 && wcsrchr(a, 0) == a + 4 && wcschr(a, 0xffff) == 0, 70);
    check(wcsstr(a, needle) == a + 1 && wcsstr(a, empty) == a && wcsstr(a, high) == 0, 71);
    for (i = 0; i < 24; ++i) b[i] = 0x5555;
    check(wcsncpy(b, two, 5) == b && b[0] == 0x31 && b[1] == 0x32, 74);
    check(b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0x5555, 75);
    b[2] = 0x5555;
    check(wcsncpy(b, text, 2) == b && b[0] == 0x41 && b[1] == 0x20ac && b[2] == 0x5555, 76);
    wcscpy(b, two); check(wcscat(b, two) == b && wcslen(b) == 4, 77);
    check(wcsncat(b, text, 2) == b && wcslen(b) == 6 && b[4] == 0x41 && b[5] == 0x20ac, 78);
    check(wcsncat(b, text, 0) == b && wcslen(b) == 6, 79);
}
void entry(void) {
    allocation(); bytes(); units(); ExitProcess(0);
}
