#include "common.h"
static DWORD fls, tls, parent_tid, worker_tid;
static UPTR parent_teb, worker_teb;
static void *parent_root, *worker_root, *moving;
static HANDLE ready, go, done;
static volatile DWORD stage, callbacks;
static UPTR parent_value = COOKIE, worker_value = COOKIE + 1, fiber_value = COOKIE + 2;
static void WINAPI callback(void *value) {
    check(value == &fiber_value && *(UPTR *)value == COOKIE + 2, 61);
    ++callbacks;
}
static void WINAPI body(void *arg) {
    volatile UPTR local = COOKIE + 3;
    UPTR address = (UPTR)&local;
    check(arg == &fiber_value && fiber_data() == arg && current_fiber() == moving, 62);
    check(GetCurrentThreadId() == parent_tid && current_teb() == parent_teb, 63);
    check(TlsGetValue(tls) == &parent_value && FlsGetValue(fls) == 0, 64);
    check(FlsSetValue(fls, &fiber_value), 65);
    stage = 1; SwitchToFiber(parent_root);
    check(stage == 1 && current_fiber() == moving, 66);
    check(GetCurrentThreadId() == worker_tid && current_teb() == worker_teb, 67);
    check(TlsGetValue(tls) == &worker_value && FlsGetValue(fls) == &fiber_value, 68);
    check((UPTR)&local == address && local == COOKIE + 3 && fiber_data() == arg, 69);
    stack_check(70);
    stage = 2; SwitchToFiber(worker_root);
    check(stage == 2 && GetCurrentThreadId() == parent_tid && current_teb() == parent_teb, 72);
    check(TlsGetValue(tls) == &parent_value && FlsGetValue(fls) == &fiber_value, 73);
    check((UPTR)&local == address && local == COOKIE + 3 && fiber_data() == arg, 74);
    stack_check(75);
    stage = 3; SwitchToFiber(parent_root);
    ExitProcess(77);
}
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    worker_tid = GetCurrentThreadId(); worker_teb = current_teb();
    worker_root = ConvertThreadToFiberEx(&worker_value, FLOAT_SWITCH);
    check(worker_root && TlsSetValue(tls, &worker_value), 78);
    signal(ready); wait(go);
    SwitchToFiber(moving);
    check(stage == 2 && current_fiber() == worker_root && fiber_data() == &worker_value, 79);
    check(FlsGetValue(fls) == 0 && TlsGetValue(tls) == &worker_value, 80);
    check(ConvertFiberToThread(), 81);
    signal(done);
    return 0;
}
void entry(void) {
    HANDLE thread;
    fls = FlsAlloc(callback); tls = TlsAlloc();
    check(fls != INFINITE && tls != INFINITE, 82);
    parent_tid = GetCurrentThreadId(); parent_teb = current_teb();
    parent_root = ConvertThreadToFiberEx(&parent_value, FLOAT_SWITCH);
    check(parent_root && TlsSetValue(tls, &parent_value), 83);
    moving = CreateFiberEx(4096, 65536, FLOAT_SWITCH, body, &fiber_value);
    check(moving != 0, 84);
    SwitchToFiber(moving); check(stage == 1, 85);
    ready = event(); go = event(); done = event();
    thread = CreateThread(0, 0, worker, 0, 0, 0);
    check(thread != 0, 86); wait(ready); signal(go); wait(done); wait(thread);
    check(worker_tid != parent_tid && worker_teb != parent_teb && callbacks == 0, 87);
    SwitchToFiber(moving); check(stage == 3, 88);
    DeleteFiber(moving); check(callbacks == 1, 89);
    check(FlsFree(fls) && callbacks == 1 && TlsFree(tls), 90);
    check(ConvertFiberToThread(), 91);
    close(thread); close(ready); close(go); close(done);
    ExitProcess(0);
}
