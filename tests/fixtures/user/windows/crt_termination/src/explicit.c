#include "common.h"
static TABLE outer, inner;
static volatile DWORD step, nested, global_calls;
static void CRTCALL global(void) { ++global_calls; ExitProcess(181); }
static int CRTCALL oldest(void) { check(step == 1, 101); step = 2; return 17; }
static int CRTCALL late(void) { check(step == 2, 102); step = 3; return -1; }
static int CRTCALL inner_oldest(void) { check(nested == 1, 103); nested = 2; return -8; }
static int CRTCALL inner_newest(void) { check(nested == 0, 104); nested = 1; return 0x12345678; }
static int CRTCALL reentrant(void) {
    check(step == 0, 105); step = 1;
    check(_crt_atexit(global) == 0, 106);
    check(_crt_at_quick_exit(global) == 0, 107);
    check(_initialize_onexit_table(&inner) == 0, 108);
    check(_register_onexit_function(&inner, inner_oldest) == 0, 109);
    check(_register_onexit_function(&inner, inner_newest) == 0, 110);
    check(_execute_onexit_table(&inner) == 0 && nested == 2, 111);
    /* Existing explicit-table personality detaches and invalidates this table
       before invoking callbacks. Initialize an independent next generation. */
    check(_initialize_onexit_table(&outer) == 0, 112);
    check(_register_onexit_function(&outer, late) == 0, 120);
    check(global_calls == 0, 113);
    return 0x76543210;
}
void entry(void) {
    check(_initialize_onexit_table(&outer) == 0, 114);
    check(_register_onexit_function(&outer, oldest) == 0, 115);
    check(_register_onexit_function(&outer, reentrant) == 0, 116);
    check(_execute_onexit_table(&outer) == 0, 117);
    check(step == 2 && nested == 2 && global_calls == 0, 118);
    check(_execute_onexit_table(&outer) == 0 && step == 3, 119);
    check(_execute_onexit_table(&outer) < 0 && step == 3, 121);
    output("explicit\n", 9);
    ExitProcess(0);
}
