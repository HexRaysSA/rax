#include "common.h"
static TABLE table;
static void *entered, *attempted, *done;
static volatile DWORD completed, global_calls;
static void CRTCALL global(void) { ++global_calls; ExitProcess(181); }
static DWORD WINAPI registrar(void *unused) {
    (void)unused;
    check(WaitForSingleObject(entered, (DWORD)-1) == 0, 101);
    check(SetEvent(attempted), 102);
    check(_crt_atexit(global) == 0, 103);
    check(_crt_at_quick_exit(global) == 0, 104);
    completed = 1;
    check(SetEvent(done), 105);
    return 0;
}
static int CRTCALL owner(void) {
    check(SetEvent(entered), 106);
    check(WaitForSingleObject(attempted, (DWORD)-1) == 0, 107);
    /* Allow the worker to reach the held recursive CRT exit lock. */
    Sleep(20);
    check(WaitForSingleObject(done, 0) == 258 && completed == 0, 108);
    check(global_calls == 0, 109);
    return 0;
}
void entry(void) {
    void *thread;
    DWORD status = 0xffffffffu;
    entered = CreateEventW(0, 1, 0, 0);
    attempted = CreateEventW(0, 1, 0, 0);
    done = CreateEventW(0, 1, 0, 0);
    check(entered && attempted && done, 110);
    check(_initialize_onexit_table(&table) == 0, 111);
    check(_register_onexit_function(&table, owner) == 0, 112);
    thread = CreateThread(0, 0, registrar, 0, 0, 0);
    check(thread != 0, 113);
    check(_execute_onexit_table(&table) == 0, 114);
    check(WaitForSingleObject(done, (DWORD)-1) == 0 && completed == 1, 115);
    check(WaitForSingleObject(thread, (DWORD)-1) == 0, 116);
    check(GetExitCodeThread(thread, &status) && status == 0, 117);
    check(global_calls == 0, 118);
    check(CloseHandle(thread) && CloseHandle(done) && CloseHandle(attempted) && CloseHandle(entered), 119);
    output("concurrent\n", 11);
    ExitProcess(0);
}
