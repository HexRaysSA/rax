#include "common.h"
static DWORD index, second, tls;
static void *root_fiber, *children[2];
static DWORD tid;
static UPTR teb, addresses[2], stack_allocations[2];
static volatile DWORD entered[2], callbacks[8];
static UPTR values[8];
static HANDLE ready[2], release_workers;

static void WINAPI callback(void *value) {
    DWORD i;
    for (i = 0; i < 8; ++i) {
        if (value == &values[i]) {
            check(values[i] == COOKIE + i, 11);
            ++callbacks[i];
            return;
        }
    }
    ExitProcess(12);
}
static void WINAPI child(void *arg) {
    DWORD n = (DWORD)(UPTR)arg;
    volatile UPTR local = COOKIE + n;
    MBI info;
    check(n < 2 && current_fiber() == children[n], 13);
    check(fiber_data() == arg && GetCurrentThreadId() == tid && current_teb() == teb, 14);
    stack_check(15);
    addresses[n] = (UPTR)&local;
    check(VirtualQuery((void *)&local, &info, sizeof(info)) == sizeof(info), 17);
    stack_allocations[n] = (UPTR)info.allocation;
    check(FlsGetValue(index) == 0 && FlsGetValue(second) == 0, 18);
    check(TlsGetValue(tls) == &values[7], 19);
    check(FlsSetValue(index, &values[n + 1]) && FlsSetValue(second, &values[n + 4]), 20);
    check(TlsSetValue(tls, &values[6]), 21);
    entered[n] = 1;
    SwitchToFiber(root_fiber);
    check(local == COOKIE + n && FlsGetValue(index) == &values[n + 1], 22);
    check(FlsGetValue(second) == &values[n + 4], 23);
    entered[n] = 2;
    SwitchToFiber(root_fiber);
    ExitProcess(24);
}
static DWORD WINAPI worker(void *arg) {
    DWORD n = (DWORD)(UPTR)arg;
    check(FlsGetValue(index) == 0, 25);
    check(FlsSetValue(index, &values[n + 3]), 26);
    signal(ready[n]);
    wait(release_workers);
    return 0;
}
void entry(void) {
    DWORD i;
    HANDLE threads[2];
    MBI info;
    for (i = 0; i < 8; ++i) values[i] = COOKIE + i;
    index = FlsAlloc(callback); second = FlsAlloc(0); tls = TlsAlloc();
    check(index != INFINITE && second != INFINITE && index != second && tls != INFINITE, 27);
    check(!IsThreadAFiber() && FlsGetValue(index) == 0, 28);
    check(FlsSetValue(index, &values[0]), 29);
    tid = GetCurrentThreadId(); teb = current_teb();
    root_fiber = ConvertThreadToFiber((void *)COOKIE);
    check(root_fiber && IsThreadAFiber() && current_fiber() == root_fiber, 30);
    check(fiber_data() == (void *)COOKIE && FlsGetValue(index) == &values[0], 31);
    check(ConvertFiberToThread() && !IsThreadAFiber(), 32);
    check(FlsGetValue(index) == &values[0], 33);
    root_fiber = ConvertThreadToFiberEx((void *)(COOKIE + 1), FLOAT_SWITCH);
    check(root_fiber && fiber_data() == (void *)(COOKIE + 1), 34);
    check(FlsGetValue(index) == &values[0] && TlsSetValue(tls, &values[7]), 35);
    children[0] = CreateFiber(0, child, 0);
    children[1] = CreateFiberEx(4096, 65536, FLOAT_SWITCH, child, (void *)1);
    check(children[0] && children[1] && children[0] != children[1], 36);
    check(!entered[0] && !entered[1], 37);
    for (i = 0; i < 2; ++i) {
        check(TlsSetValue(tls, &values[7]), 38);
        SwitchToFiber(children[i]);
        check(entered[i] == 1 && FlsGetValue(index) == &values[0], 39);
        check(FlsGetValue(second) == 0 && TlsGetValue(tls) == &values[6], 40);
        SwitchToFiber(children[i]);
        check(entered[i] == 2 && current_teb() == teb && GetCurrentThreadId() == tid, 41);
    }
    check(addresses[0] != addresses[1] && stack_allocations[0] != stack_allocations[1], 42);
    /* Delete one inactive fiber: only its non-NULL registered callback fires. */
    DeleteFiber(children[0]);
    check(callbacks[1] == 1 && callbacks[2] == 0, 43);
    check(VirtualQuery((void *)stack_allocations[0], &info, sizeof(info)) == sizeof(info), 44);
    check(info.state == MEM_FREE, 45);
    release_workers = event();
    for (i = 0; i < 2; ++i) {
        ready[i] = event();
        threads[i] = CreateThread(0, 0, worker, (void *)(UPTR)i, 0, 0);
        check(threads[i] != 0, 46); wait(ready[i]);
    }
    /* All fibers/threads, no callback-order or callback-thread assertion. */
    check(FlsFree(index), 47);
    check(callbacks[0] == 1 && callbacks[1] == 1 && callbacks[2] == 1, 48);
    check(callbacks[3] == 1 && callbacks[4] == 1, 49);
    signal(release_workers);
    for (i = 0; i < 2; ++i) { wait(threads[i]); close(threads[i]); close(ready[i]); }
    check(callbacks[3] == 1 && callbacks[4] == 1, 50);
    close(release_workers);
    DeleteFiber(children[1]);
    check(callbacks[2] == 1, 51);
    check(FlsFree(second) && TlsFree(tls), 52);
    index = FlsAlloc(callback);
    check(index != INFINITE && FlsGetValue(index) == 0 && FlsFree(index), 53);
    check(ConvertFiberToThread() && !IsThreadAFiber(), 54);
    ExitProcess(0);
}
