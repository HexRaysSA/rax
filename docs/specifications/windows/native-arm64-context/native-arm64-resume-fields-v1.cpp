#include <windows.h>

static HANDLE ready, release_worker;
__declspec(align(8)) static volatile DWORD watched;

static DWORD WINAPI worker(void *) {
    if (!SetEvent(ready)) return 11;
    return WaitForSingleObject(release_worker, 30000) == WAIT_OBJECT_0 ? 12 : 13;
}

static void row(char kind, const ULONG64 *values, unsigned count) {
    const char hex[] = "0123456789abcdef";
    char text[2 + 24 * 17];
    unsigned at = 0;
    text[at++] = kind;
    text[at++] = ' ';
    for (unsigned i = 0; i < count; ++i) {
        for (int shift = 60; shift >= 0; shift -= 4)
            text[at++] = hex[(values[i] >> shift) & 15];
        text[at++] = i + 1 == count ? '\n' : ' ';
    }
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, at, &written, nullptr) || written != at)
        ExitProcess(50);
}

static void bank(unsigned test, unsigned phase, const CONTEXT &c) {
    ULONG64 values[22] = {test, phase};
    for (unsigned i = 0; i < 8; ++i) {
        values[2 + i] = c.Bcr[i];
        values[10 + i] = c.Bvr[i];
    }
    for (unsigned i = 0; i < 2; ++i) {
        values[18 + i] = c.Wcr[i];
        values[20 + i] = c.Wvr[i];
    }
    row('B', values, 22);
}

static HANDLE suspended_thread() {
    ResetEvent(ready);
    ResetEvent(release_worker);
    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, CREATE_SUSPENDED, nullptr);
    if (!thread) ExitProcess(21);
    return thread;
}

static void finish_thread(HANDLE thread) {
    if (!SetEvent(release_worker)) ExitProcess(30);
    if (ResumeThread(thread) != 1) ExitProcess(31);
    if (WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0) ExitProcess(32);
    DWORD code = 0;
    if (!GetExitCodeThread(thread, &code) || code != 12) ExitProcess(33);
    if (!CloseHandle(thread)) ExitProcess(34);
}

extern "C" __declspec(noreturn) void entry() {
    ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    release_worker = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ready || !release_worker) ExitProcess(20);
    HANDLE thread = suspended_thread();
    CONTEXT original = {};
    original.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread, &original)) ExitProcess(22);
    const DWORD pstate[] = {0, 0xffffffff, 0xf0000000, 0x40, 0x20, 1u<<21,
                           1u<<24, 1u<<12, 1u<<10, 0x3c0};
    for (unsigned test = 0; test < sizeof(pstate)/sizeof(pstate[0]); ++test) {
        CONTEXT input = original;
        input.ContextFlags = CONTEXT_CONTROL;
        input.Cpsr = pstate[test];
        SetLastError(0);
        BOOL set = SetThreadContext(thread, &input);
        DWORD error = GetLastError();
        CONTEXT output = {};
        output.ContextFlags = CONTEXT_CONTROL;
        BOOL get = GetThreadContext(thread, &output);
        ULONG64 values[] = {test, pstate[test], DWORD(set), error, DWORD(get),
                            output.Cpsr, output.ContextFlags};
        row('P', values, 7);
        if (!get || !SetThreadContext(thread, &original)) ExitProcess(23);
    }
    finish_thread(thread);

    for (unsigned test = 0; test < 6; ++test) {
        thread = suspended_thread();
        CONTEXT input = {};
        input.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &input)) ExitProcess(24);
        for (unsigned i = 0; i < 8; ++i) {
            input.Bcr[i] = test == 0 ? 0 : 0xffff3ffc;
            input.Bvr[i] = ULONG_PTR(&watched) + (i % 4);
        }
        for (unsigned i = 0; i < 2; ++i) {
            input.Wcr[i] = test == 0 ? 0 : 0xffff3ffc;
            input.Wvr[i] = ULONG_PTR(&watched) + i + 1;
        }
        // Only this ordinary, nonmatching instruction comparator is enabled.
        if (test != 0) {
            input.Bcr[1] = 0x1e5;
            input.Bvr[1] = ULONG_PTR(&watched) + 3;
        }
        if (test == 2) input.Bcr[0] = 0x00400004;
        if (test == 3) input.Bcr[0] = 0x00012004;
        if (test == 4) input.Bcr[0] = 0x00000024;
        if (test == 5) input.Bcr[0] = 0x00000064;
        if (!SetThreadContext(thread, &input)) ExitProcess(25);
        CONTEXT output = {};
        output.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &output)) ExitProcess(26);
        bank(test, 0, output);
        if (ResumeThread(thread) != 1) ExitProcess(27);
        if (WaitForSingleObject(ready, 30000) != WAIT_OBJECT_0) ExitProcess(28);
        if (SuspendThread(thread) != 0) ExitProcess(29);
        output.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &output)) ExitProcess(35);
        bank(test, 1, output);
        CONTEXT clear = {};
        clear.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext(thread, &clear)) ExitProcess(36);
        finish_thread(thread);
    }
    if (!CloseHandle(ready) || !CloseHandle(release_worker)) ExitProcess(37);
    ExitProcess(0);
}
