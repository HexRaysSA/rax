#include "common.h"
/* Deterministic RAX commitment/heap profile, not native UCRT geometry.
   The runtime heap is the genuine _get_heap_handle result; internal onexit
   blocks are not ordinary malloc-ledger allocations. Never destroy it. */
static Table table;
static void *pressure[1100];
static DWORD pressure_count;
static volatile DWORD called;
static int CRTCALL callback(void) { ++called; return -1; }
static void fill_budget(void) {
    void *block;
    for (;;) {
        check(pressure_count < 1100, 171);
        block = VirtualAlloc(0, 65536, 0x3000, 4);
        if (!block) break;
        pressure[pressure_count++] = block;
    }
    for (;;) {
        check(pressure_count < 1100, 172);
        block = VirtualAlloc(0, 4096, 0x3000, 4);
        if (!block) break;
        pressure[pressure_count++] = block;
    }
}
static void release_pressure(void) {
    for (DWORD i = 0; i < pressure_count; ++i)
        if (pressure[i]) check(VirtualFree(pressure[i], 0, 0x8000), 173);
    pressure_count = 0;
}
static void unchanged(Table saved, DWORD code) {
    check(table.first == saved.first && table.last == saved.last && table.end == saved.end, code);
}
void entry(void) {
    void *heap = _get_heap_handle();
    void *committed_page;
    DWORD accepted = 0;
    int failed = 0;
    check(heap != 0, 174);
    /* This heap profile reserves 0x100 header bytes in its initial 4096-byte
       committed page. Fill its 4096-256 = 3840-byte payload exactly, without
       first establishing any private errno/PTD allocation. */
    committed_page = HeapAlloc(heap, 0, 3840);
    check(committed_page != 0, 175);
    init(&table);
    fill_budget();
    {
        Table saved = table;
        SetLastError(0x1234abcd);
        check(_register_onexit_function(&table, callback) < 0, 176);
        check(GetLastError() == 0x1234abcd && called == 0, 177);
        unchanged(saved, 178);
    }
    check(pressure_count > 0 && pressure[0] != 0, 179);
    check(VirtualFree(pressure[0], 0, 0x8000), 180);
    pressure[0] = 0;
    reg(&table, callback);
    accepted = 1;
    fill_budget();
    for (DWORD i = 0; i < 8192; ++i) {
        Table saved = table;
        SetLastError(0x6abc1234);
        int result = _register_onexit_function(&table, callback);
        check(GetLastError() == 0x6abc1234, 181);
        if (result < 0) {
            unchanged(saved, 182);
            failed = 1;
            break;
        }
        check(result == 0, 183);
        ++accepted;
    }
    check(failed && called == 0, 184);
    release_pressure();
    check(HeapFree(heap, 0, committed_page), 185);
    reg(&table, callback);
    ++accepted;
    drain(&table);
    check(called == accepted, 186); /* No phantom append on either OOM. */
    init(&table);
    drain(&table);
    ExitProcess(0);
}
