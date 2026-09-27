#include "common.h"

static volatile DWORD step;
static volatile DWORD nested;
static volatile int mode;
static int CRTCALL forbidden(void) { ExitProcess(181); }
static void CRTCALL void_inner(void) { check(nested == 0, 121); nested = 1; }
static int CRTCALL int_inner(void) { check(nested == 1, 122); nested = 2; return 0; }
static int CRTCALL second(void) {
    check(step == 1, 123); step = 2;
    return mode == 0 ? 0x13579bdf : (mode == 1 ? -17 : 0);
}
static int CRTCALL after(void) { check(mode == 2 && step == 2, 124); step = 3; return 0; }
#pragma section(".CRT$XIA", read, write)
#pragma section(".CRT$XIB", read, write)
#pragma section(".CRT$XIC", read, write)
#pragma section(".CRT$XID", read, write)
#pragma section(".CRT$XIE", read, write)
#pragma section(".CRT$XIZ", read, write)
SLOT(".CRT$XID") PIFV future = forbidden;
static int CRTCALL first(void) {
    void *p;
    PVFV v[] = {0, void_inner, 0};
    PIFV e[] = {0, int_inner, 0};
    check(step == 0, 125); step = 1;
    _initterm(v, v + 3);
    check(_initterm_e(e, e + 3) == 0 && nested == 2, 126);
    p = malloc(17); check(p != 0, 127); free(p);
    future = second;
    return 0;
}
SLOT(".CRT$XIA") PIFV ctor_begin = 0;
SLOT(".CRT$XIB") PIFV ctor_first = first;
SLOT(".CRT$XIC") PIFV ctor_null = 0;
SLOT(".CRT$XIE") PIFV ctor_after = after;
SLOT(".CRT$XIZ") PIFV ctor_end = forbidden;
__declspec(dllexport) const void *fixture_bounds[2] = {&ctor_begin, &ctor_end};

int main(void) {
    int result;
    check((UPTR)&ctor_end - (UPTR)&ctor_begin == 5 * sizeof(PIFV), 128);
    result = _initterm_e(&ctor_begin, &ctor_end);
    check(result == 0x13579bdf && step == 2 && nested == 2, 129);
    mode = 1; step = 0; nested = 0; future = forbidden;
    result = _initterm_e(&ctor_begin, &ctor_end);
    check(result == -17 && step == 2 && nested == 2, 130);
    mode = 2; step = 0; nested = 0; future = forbidden;
    result = _initterm_e(&ctor_begin, &ctor_end);
    check(result == 0 && step == 3 && nested == 2, 131);
    check(_initterm_e(&ctor_end, &ctor_end) == 0, 132);
    return 0;
}
void entry(void) { ExitProcess((DWORD)main()); }
