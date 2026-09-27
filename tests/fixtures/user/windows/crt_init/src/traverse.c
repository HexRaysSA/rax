#include "common.h"

static volatile DWORD step;
static volatile DWORD nested;
static void CRTCALL forbidden(void) { ExitProcess(180); }
static int CRTCALL first(void) {
    check(step == 0, 101); step = 1;
    return 0x76543210; /* A void table must ignore the ABI return register. */
}
static void CRTCALL replacement(void) { check(step == 2, 102); step = 3; }
static void CRTCALL inner_first(void) { check(nested == 0, 103); nested = 1; }
static void CRTCALL inner_last(void) { check(nested == 1, 104); nested = 2; }
static PVFV inner[] = {0, inner_first, 0, inner_last, forbidden};

#pragma section(".CRT$XCA", read, write)
#pragma section(".CRT$XCB", read, write)
#pragma section(".CRT$XCC", read, write)
#pragma section(".CRT$XCD", read, write)
#pragma section(".CRT$XCE", read, write)
#pragma section(".CRT$XCF", read, write)
#pragma section(".CRT$XCG", read, write)
#pragma section(".CRT$XCZ", read, write)
SLOT(".CRT$XCE") PVFV future = forbidden;
static void CRTCALL mutate(void) {
    check(step == 1, 105); step = 2;
    future = replacement; /* Named lazy-slot-read personality profile. */
}
static void CRTCALL reentrant(void) {
    char *p;
    check(step == 3, 106); step = 4;
    p = (char *)malloc(7);
    check(p != 0, 107);
    p[0] = 'i'; p[1] = 'n'; p[2] = 'i'; p[3] = 't'; p[4] = 0;
    check(strlen(p) == 4, 108);
    _initterm(inner, inner + 4);
    check(nested == 2, 109);
    free(p);
    check(step == 4, 110); step = 5;
}
static void CRTCALL last(void) { check(step == 5, 111); step = 6; }
SLOT(".CRT$XCA") PVFV ctor_begin = 0;
SLOT(".CRT$XCB") PVFV ctor_first = (PVFV)first;
SLOT(".CRT$XCC") PVFV ctor_null = 0;
SLOT(".CRT$XCD") PVFV ctor_mutate = mutate;
SLOT(".CRT$XCF") PVFV ctor_nested = reentrant;
SLOT(".CRT$XCG") PVFV ctor_last = last;
SLOT(".CRT$XCZ") PVFV ctor_end = forbidden;
__declspec(dllexport) const void *fixture_bounds[2] = {&ctor_begin, &ctor_end};

int main(void) {
    unsigned int i;
    check((UPTR)&ctor_end - (UPTR)&ctor_begin == 7 * sizeof(PVFV), 112);
    check(abi_init(_initterm, &ctor_begin, &ctor_end), 116);
    check(step == 6 && nested == 2, 113);
    for (i = 0; i < 32; ++i) {
        /* Empty traversal checks repeated cdecl caller cleanup and GPRs. */
        check(abi_init(_initterm, &ctor_end, &ctor_end), 114);
    }
    check(step == 6 && nested == 2, 115);
    return 0;
}
void entry(void) { ExitProcess((DWORD)main()); }
