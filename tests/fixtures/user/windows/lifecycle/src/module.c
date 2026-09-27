#include "common.h"
#ifndef MODULE_ID
#error MODULE_ID required
#endif
#ifndef FAIL_ATTACH
#define FAIL_ATTACH 0
#endif
#if MODULE_ID == 2 || MODULE_ID == 3
DLL DWORD WINAPI LeafReady(void);
#endif
/* An explicit PE TLS directory makes the template/zero-fill extent auditable. */
typedef void (WINAPI *TlsCallback)(void *, DWORD, void *);
typedef struct {
    UPTR start, end, index, callbacks;
    DWORD zero_fill, characteristics;
} TlsDirectory;
_Static_assert(sizeof(TlsDirectory) == (sizeof(UPTR) == 4 ? 24 : 40), "TLS directory");
static DWORD tls_index;
#pragma section(".tls", read, write)
__declspec(allocate(".tls")) static const DWORD tls_template = INITIAL(MODULE_ID);
static DWORD attached;
static BOOL static_load;
static DWORD *tls(void) {
    UPTR array = *(volatile UPTR *)(current_teb() + TLS_POINTER);
    return (DWORD *)((volatile UPTR *)array)[tls_index];
}
static void record(DWORD kind, void *base, DWORD reason, void *reserved) {
    DWORD *block = tls();
    check(block != 0, 200 + MODULE_ID);
    if (reason == 1 || reason == 2) {
        check(block[0] == INITIAL(MODULE_ID), 204 + MODULE_ID);
        check(block[1] == 0 && block[2] == 0 && block[3] == 0, 208 + MODULE_ID);
    }
    Log(MODULE_ID, kind, base, reason, reserved, block[0],
        GetCurrentThreadId(), current_sp(), COOKIE);
}
static void WINAPI first(void *base, DWORD reason, void *reserved) {
    record(TLS_FIRST, base, reason, reserved);
}
static void WINAPI second(void *base, DWORD reason, void *reserved) {
    record(TLS_SECOND, base, reason, reserved);
}
static const TlsCallback callbacks[] = {first, second, 0};
/* C `_tls_used` becomes `__tls_used` on x86, as PE/COFF specifies. */
const TlsDirectory _tls_used = {
    (UPTR)&tls_template, (UPTR)(&tls_template + 1), (UPTR)&tls_index,
    (UPTR)&callbacks, 12, 0
};
BOOL WINAPI DllMain(void *base, DWORD reason, void *reserved) {
    record(DLL_MAIN, base, reason, reserved);
    if (reason == 1) {
        static_load = reserved != 0;
#if MODULE_ID == 2 || MODULE_ID == 3
        check(LeafReady() == INITIAL(LEAF), 212 + MODULE_ID);
#endif
        attached = 1;
        return !FAIL_ATTACH;
    }
    if (reason == 2 || reason == 3) check(reserved == 0, 220 + MODULE_ID);
    if (reason == 0 && static_load) check(reserved != 0, 224 + MODULE_ID);
    if (reason == 0) attached = 0;
    return 0; /* Ignored for notifications other than PROCESS_ATTACH. */
}
DWORD WINAPI Ready(void) { return attached ? INITIAL(MODULE_ID) : 0; }
DWORD WINAPI TlsRead(void) { return tls()[0]; }
void WINAPI TlsSet(DWORD value) { tls()[0] = value; }
UPTR WINAPI Probe(UPTR a, UPTR b, UPTR c, UPTR d, UPTR e,
                  UPTR f, UPTR g, UPTR h, UPTR i) {
    check(attached, 216 + MODULE_ID);
    return a + b + 3*c + 5*d + 7*e + 11*f + 13*g + 17*h + 19*i;
}
