#include "common.h"
#ifndef REGISTRATIONS
#error Expected explicit producer registration count
#endif
static volatile DWORD ordinary_calls, quick_calls;
static void CRTCALL ordinary(void) { ++ordinary_calls; ExitProcess(181); }
static void CRTCALL quick(void) { ++quick_calls; ExitProcess(182); }
void entry(void) {
    DWORD i;
    check(_crt_atexit(0) == 0, 101);
    check(_crt_at_quick_exit(0) == 0, 102);
    for (i = 0; i < REGISTRATIONS; ++i) {
        check(_crt_atexit(ordinary) == 0, 103);
        check(_crt_at_quick_exit(quick) == 0, 104);
    }
    check(ordinary_calls == 0 && quick_calls == 0, 105);
    output("registered\n", 11);
    /* Raw desktop ExitProcess does not request the EXE CRT registries. */
    ExitProcess(0);
}
