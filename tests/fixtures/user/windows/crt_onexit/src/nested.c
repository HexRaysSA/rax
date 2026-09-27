#include "common.h"
static Table outer, other;
static volatile DWORD count, trace[7];
static void record(DWORD value) { check(count < 7, 131); trace[count++] = value; }
static int CRTCALL old_lower(void) { record(6); return -1; }
static int CRTCALL other_lower(void) { record(3); return 22; }
static int CRTCALL other_upper(void) { record(2); return -22; }
static int CRTCALL fresh_lower(void) { record(5); return 90; }
static int CRTCALL fresh_upper(void) { record(4); return 0; }
static int CRTCALL survives_outer(void) { record(7); return 8; }
static int CRTCALL upper(void) {
    char *block;
    record(1);
    /* Explicit public-lifecycle admission: a detached table is invalid until
       initialize. Native recursive registration details are unknown. */
    check(_register_onexit_function(&outer, survives_outer) < 0, 132);
    check(_execute_onexit_table(&outer) < 0, 133);
    drain(&other);
    block = (char *)malloc(17);
    check(block != 0 && memset(block, 0x5a, 17) == block, 134);
    check(block[0] == 0x5a && block[16] == 0x5a, 135);
    free(block);
    init(&outer);
    reg(&outer, fresh_lower);
    reg(&outer, fresh_upper);
    drain(&outer); /* A fresh generation nested inside the detached old one. */
    init(&outer);
    reg(&outer, survives_outer); /* Outer completion must leave this live. */
    return 43;
}
void entry(void) {
    init(&outer);
    init(&other);
    reg(&other, other_lower);
    reg(&other, other_upper);
    reg(&outer, old_lower);
    reg(&outer, upper);
    drain(&outer);
    check(count == 6, 136);
    for (DWORD i = 0; i < 6; ++i) check(trace[i] == i + 1, 137);
    drain(&outer);
    check(count == 7 && trace[6] == 7, 138);
    init(&outer);
    init(&other);
    drain(&outer);
    drain(&other);
    ExitProcess(0);
}
