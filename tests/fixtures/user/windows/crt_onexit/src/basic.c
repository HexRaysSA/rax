#include "common.h"
static Table table;
static volatile DWORD count, trace[3];
static int CRTCALL first(void) { check(count < 3, 111); trace[count++] = 1; return -17; }
static int CRTCALL second(void) { check(count < 3, 112); trace[count++] = 2; return 0; }
static int CRTCALL third(void) { check(count < 3, 113); trace[count++] = 3; return 91; }
static int CRTCALL increment(void) { ++count; return 73; }
void entry(void) {
    Table unknown = {0};
    check(_initialize_onexit_table(0) < 0, 116);
    check(_register_onexit_function(0, first) < 0, 117);
    check(_execute_onexit_table(0) < 0, 118);
    check(_register_onexit_function(&unknown, first) < 0, 119);
    check(_execute_onexit_table(&unknown) < 0, 120);
    /* No uninitialized/invalid-table call is used as a native success oracle. */
    init(&table);
    drain(&table); /* Initialized empty table. */
    check(_execute_onexit_table(&table) < 0, 121);
    check(_register_onexit_function(&table, first) < 0, 122);
    for (DWORD pass = 0; pass < 32; ++pass) {
        init(&table);
        count = 0;
        reg(&table, first);
        reg(&table, (ExitFn)0); /* Selected NULL-slot skip profile. */
        reg(&table, second);
        reg(&table, third);
        drain(&table);
        check(count == 3 && trace[0] == 3 && trace[1] == 2 && trace[2] == 1, 114);
    }
    init(&table);
    count = 0;
    for (DWORD i = 0; i < 1024; ++i) reg(&table, increment);
    drain(&table);
    check(count == 1024, 115); /* Callback return integers do not stop traversal. */
    init(&table);
    drain(&table);
    ExitProcess(0);
}
