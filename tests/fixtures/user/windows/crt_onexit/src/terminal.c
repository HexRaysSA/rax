#include "common.h"
static Table table;
static volatile DWORD called;
static volatile DWORD dll_called;
static volatile DWORD exit_phase;
static int CRTCALL forbidden(void) { exit_phase = 2; ExitProcess(141); }
static int CRTCALL stop_thread(void) { called = 1; ExitThread(93); }
static int CRTCALL after_cleanup(void) { check(called == 1, 142); called = 2; return 9; }
static int CRTCALL stop_process(void) {
    check(called == 2, 143);
    exit_phase = 1;
    ExitProcess(88);
}
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    drain(&table);
    ExitProcess(144); /* A terminal callback cannot resume this call site. */
}
void entry(void) {
    DWORD result = 0;
    void *thread;
    init(&table);
    reg(&table, forbidden);
    reg(&table, stop_thread);
    thread = CreateThread(0, 0, worker, 0, 0, 0);
    check(thread != 0, 145);
    check(WaitForSingleObject(thread, 5000) == 0, 146);
    check(GetExitCodeThread(thread, &result) && result == 93 && called == 1, 147);
    check(CloseHandle(thread), 148);
    init(&table);
    reg(&table, after_cleanup);
    drain(&table);
    check(called == 2, 149);
    {
        void *module = LoadLibraryW(L"onexit.dll");
        int (CRTCALL *configure)(volatile DWORD *, volatile DWORD *);
        check(module != 0, 151);
        configure = (int (CRTCALL *)(volatile DWORD *, volatile DWORD *))GetProcAddress(module, "configure");
        check(configure != 0 && configure(&dll_called, &exit_phase) == 0 && dll_called == 0, 152);
        /* Leave the guest companion live: its PROCESS_DETACH exercises a
           prepared explicit table after process-exit callbacks are canceled. */
    }
    init(&table);
    reg(&table, forbidden);
    reg(&table, stop_process);
    drain(&table);
    exit_phase = 3;
    ExitProcess(150);
}
