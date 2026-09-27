#include "common.h"
/* errno is per executing thread, not per fiber; migration is synchronized. */
static int *parent_error, *worker_error;
static DWORD *parent_dos, *worker_dos, parent_tid, worker_tid;
static void *parent_root, *worker_root, *moving;
static HANDLE ready, go, done, finish;
static volatile DWORD stage;
static void set_errors(int value, DWORD dos) {
#ifdef LEGACY_CRT
    *_errno() = value; *__doserrno() = dos;
#else
    check(_set_errno(value) == 0 && _set_doserrno(dos) == 0, 90);
#endif
}
static void errors(int value, DWORD dos, DWORD code) {
    check(*_errno() == value && *__doserrno() == dos, code);
#ifndef LEGACY_CRT
    {
        int error = -1;
        DWORD saved = 0;
        check(_get_errno(&error) == 0 && error == value, code + 1);
        check(_get_doserrno(&saved) == 0 && saved == dos, code + 2);
    }
#endif
}
static void WINAPI body(void *argument) {
    volatile UPTR cookie = 0x12345678;
    check(argument == &stage && GetCurrentThreadId() == parent_tid, 100);
    check(_errno() == parent_error && __doserrno() == parent_dos, 101);
    errors(101, 0x89abcdef, 102);
    set_errors(111, 0xfedcba98);
    stage = 1; SwitchToFiber(parent_root);
    check(stage == 1 && cookie == 0x12345678 && GetCurrentThreadId() == worker_tid, 106);
    check(_errno() == worker_error && __doserrno() == worker_dos, 107);
    errors(202, 0x11223344, 108);
    set_errors(222, 0x55667788);
    stage = 2; SwitchToFiber(worker_root);
    check(stage == 2 && cookie == 0x12345678 && GetCurrentThreadId() == parent_tid, 112);
    check(_errno() == parent_error && __doserrno() == parent_dos, 113);
    errors(111, 0xfedcba98, 114);
    stage = 3; SwitchToFiber(parent_root);
    ExitProcess(117);
}
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    worker_tid = GetCurrentThreadId();
    worker_error = _errno(); worker_dos = __doserrno();
    check(worker_error && worker_dos && worker_error != parent_error && worker_dos != parent_dos, 118);
    errors(0, 0, 119);
    SetLastError(0x24681357);
    set_errors(202, 0x11223344);
    check(GetLastError() == 0x24681357, 122);
    worker_root = ConvertThreadToFiber(0); check(worker_root != 0, 123);
    signal(ready); wait(go); SwitchToFiber(moving);
    check(stage == 2 && _errno() == worker_error && __doserrno() == worker_dos, 124);
    errors(222, 0x55667788, 125);
    check(ConvertFiberToThread(), 128);
    signal(done); wait(finish); return 0;
}
void entry(void) {
    HANDLE thread;
    parent_tid = GetCurrentThreadId();
    parent_error = _errno(); parent_dos = __doserrno();
    check(parent_error && parent_dos, 129); errors(0, 0, 130);
    SetLastError(0x13572468);
    set_errors(101, 0x89abcdef);
    check(GetLastError() == 0x13572468, 133);
    parent_root = ConvertThreadToFiber(0); check(parent_root != 0, 134);
    moving = CreateFiber(65536, body, (void *)&stage); check(moving != 0, 135);
    SwitchToFiber(moving); check(stage == 1, 136); errors(111, 0xfedcba98, 137);
    ready = event(); go = event(); done = event(); finish = event();
    thread = CreateThread(0, 0, worker, 0, 0, 0); check(thread != 0, 140);
    wait(ready); signal(go); wait(done);
    check(worker_tid != parent_tid, 141);
    SwitchToFiber(moving); check(stage == 3, 142); errors(111, 0xfedcba98, 143);
    DeleteFiber(moving); check(ConvertFiberToThread(), 146);
    check(_errno() == parent_error && __doserrno() == parent_dos, 147);
    signal(finish); wait(thread);
    close(thread); close(ready); close(go); close(done); close(finish);
    ExitProcess(0);
}
