#include "common.h"
static Table table;
static VoidFn *old_slots;
static volatile DWORD count, trace[3];
static int CRTCALL forbidden(void) { ExitProcess(121); }
static int CRTCALL replacement(void) { check(count == 1, 122); trace[count++] = 2; return -1; }
static int CRTCALL lower(void) { check(count == 2, 123); trace[count++] = 3; return 8; }
static int CRTCALL upper(void) {
    check(count == 0, 124);
    trace[count++] = 1;
    /* The detached old generation is guest-readable/writable in this named
       private profile. Pending slots are read lazily, not host-snapshotted. */
    old_slots[1] = (VoidFn)replacement;
    old_slots[2] = 0;
    return 37;
}
void entry(void) {
    init(&table);
    reg(&table, lower);
    reg(&table, forbidden);
    reg(&table, forbidden);
    reg(&table, upper);
    check(table.first && table.last - table.first == 4, 125);
    {
        /* A copied representation is not transferred host ownership. A
           malformed frontier likewise cannot publish a callback or free a
           guessed block. Restore the valid original before normal draining. */
        Table copied = table;
        VoidFn *saved_last = table.last;
        check(_execute_onexit_table(&copied) < 0, 127);
        check(_register_onexit_function(&copied, forbidden) < 0, 128);
        table.last = (VoidFn *)((UPTR)table.first + 1);
        check(_execute_onexit_table(&table) < 0, 129);
        check(_register_onexit_function(&table, forbidden) < 0, 130);
        table.last = saved_last;
        check(count == 0, 131);
    }
    old_slots = table.first;
    drain(&table);
    check(count == 3 && trace[0] == 1 && trace[1] == 2 && trace[2] == 3, 126);
    init(&table);
    drain(&table);
    ExitProcess(0);
}
