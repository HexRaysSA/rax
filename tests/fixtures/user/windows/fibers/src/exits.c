#include "common.h"
/* Exported for post-termination embedding checks; all cells are DWORDs. */
typedef struct {
    DWORD magic, callbacks, seen, entered, returned;
} StateRecord;
__declspec(dllexport) volatile StateRecord State = {0x464c5331u, 0, 0, 0, 0};
static DWORD slot;
static UPTR values[4];
static HANDLE ready, never;
#if defined(PROCESS_NORMAL) || defined(PROCESS_FORCED)
static HANDLE log_file;
static const WORD log_name[] = {'r','a','x','-','f','i','b','e','r','s','-','e','x','i','t','.','d','a','t',0};
static void snapshot(void) {
    DWORD written;
    check(WriteFile(log_file, (const void *)&State, sizeof(State), &written, 0), 123);
    check(written == sizeof(State), 124);
}
#endif
static void WINAPI callback(void *value) {
    DWORD i;
    for (i = 0; i < 4; ++i) {
        if (value == &values[i]) {
            check(*(UPTR *)value == COOKIE + i, 101);
            ++State.callbacks;
            State.seen |= 1u << i;
#if defined(PROCESS_NORMAL) || defined(PROCESS_FORCED)
            snapshot();
#endif
            return;
        }
    }
    ExitProcess(102);
}
static void WINAPI fiber(void *arg) {
    DWORD mode = (DWORD)(UPTR)arg;
    check(fiber_data() == arg && IsThreadAFiber(), 103);
    check(FlsSetValue(slot, &values[mode]), 104);
    ++State.entered;
#if defined(FORCED_THREAD)
    signal(ready); wait(never);
#else
    if (mode == 3) DeleteFiber(current_fiber());
    else return; /* Returning a fiber procedure terminates its running thread. */
#endif
    ++State.returned;
    ExitProcess(105);
}
static DWORD WINAPI worker(void *arg) {
    DWORD mode = (DWORD)(UPTR)arg;
    if (mode < 2) {
        check(FlsSetValue(slot, &values[mode]), 106);
        ++State.entered;
        if (mode == 1) ExitThread(0);
        return 0;
    }
    check(ConvertThreadToFiberEx(0, FLOAT_SWITCH) != 0, 107);
    void *child = CreateFiberEx(4096, 65536, FLOAT_SWITCH, fiber, arg);
    check(child != 0, 108);
    SwitchToFiber(child);
    ++State.returned;
    ExitProcess(109);
}
void entry(void) {
    DWORD i;
    for (i = 0; i < 4; ++i) values[i] = COOKIE + i;
    slot = FlsAlloc(callback); check(slot != INFINITE, 110);
#if defined(PROCESS_NORMAL) || defined(PROCESS_FORCED)
    check(FlsSetValue(slot, &values[0]), 111);
    State.entered = 1;
    log_file = CreateFileW(log_name, 0x40000000u, 1, 0, 2, 0x80, 0);
    check(log_file != (HANDLE)(UPTR)-1, 125);
    snapshot();
#if defined(PROCESS_NORMAL)
    ExitProcess(0);
#else
    check(TerminateProcess(GetCurrentProcess(), 0), 112);
    State.returned = 1;
    ExitProcess(113);
#endif
#elif defined(FORCED_THREAD)
    ready = event(); never = event();
    HANDLE thread = CreateThread(0, 0, worker, (void *)2, 0, 0);
    check(thread != 0, 114); wait(ready);
    check(State.entered == 1 && State.callbacks == 0, 115);
    check(TerminateThread(thread, 0), 116); wait(thread);
    check(State.callbacks == 0 && State.returned == 0, 117);
    check(FlsFree(slot) && State.callbacks == 0, 118);
    close(thread); close(ready); close(never);
    ExitProcess(0);
#else
    for (i = 0; i < 4; ++i) {
        HANDLE thread = CreateThread(0, 0, worker, (void *)(UPTR)i, 0, 0);
        check(thread != 0, 119); wait(thread); close(thread);
        check(State.callbacks == i + 1 && State.seen == ((1u << (i + 1)) - 1), 120);
    }
    check(State.entered == 4 && State.returned == 0, 121);
    check(FlsFree(slot) && State.callbacks == 4, 122);
    ExitProcess(0);
#endif
}
