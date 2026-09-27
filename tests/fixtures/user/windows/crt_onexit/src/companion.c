#include "common.h"
static Table table;
static volatile DWORD *shared;
static volatile DWORD *exit_phase;
static int CRTCALL callback(void) {
    if (!shared || *shared != 0) {
        TerminateProcess((void *)(UPTR)-1, 191);
        for (;;) {}
    }
    *shared = 1;
    return -47;
}
__declspec(dllexport) int CRTCALL configure(volatile DWORD *counter, volatile DWORD *phase) {
    if (!counter || !phase || shared || *phase != 0) return -1;
    shared = counter;
    exit_phase = phase;
    if (_initialize_onexit_table(&table) != 0) return -1;
    return _register_onexit_function(&table, callback);
}
BOOL WINAPI DllMain(void *module, DWORD reason, void *reserved) {
    (void)module;
    (void)reserved;
    if (reason == 0) { /* DLL_PROCESS_DETACH, not THREAD_DETACH. */
        if (!shared || !exit_phase || *exit_phase != 1 ||
            _execute_onexit_table(&table) != 0 || *shared != 1 || *exit_phase != 1) {
            TerminateProcess((void *)(UPTR)-1, 192);
            for (;;) {}
        }
        /* The phase guard forbids overriding an earlier check failure, an
           unexpected lower callback, or fallthrough after the process drain.
           No DLL detach leaves88; the verified table drain overrides to0. */
        TerminateProcess((void *)(UPTR)-1, 0);
        for (;;) {}
    }
    return 1;
}
