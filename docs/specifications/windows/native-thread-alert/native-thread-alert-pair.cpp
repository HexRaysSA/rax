#include <windows.h>
#include <initializer_list>

using AlertId = LONG(NTAPI *)(HANDLE);
using WaitId = LONG(NTAPI *)(void *, LARGE_INTEGER *);
using AlertHandle = LONG(NTAPI *)(HANDLE);
using TestAlert = LONG(NTAPI *)();
static AlertId alert_id;
static WaitId wait_id;
static AlertHandle alert_handle;
static TestAlert test_alert;
static HANDLE output, stop_event;
static unsigned char *pages;
static char line[4096];
static unsigned position, case_index;
static volatile LONG ready;
static DWORD worker_tid;
static ULONG worker_waits[8];

static void text(const char *s) { while (*s) line[position++] = *s++; }
static void field(ULONGLONG value) {
    const char digits[] = "0123456789abcdef";
    line[position++] = ' ';
    for (unsigned n = 16; n; --n) line[position++] = digits[(value >> ((n - 1) * 4)) & 15];
}
static void flush() {
    line[position++] = '\n';
    DWORD written;
    if (!WriteFile(output, line, position, &written, nullptr) || written != position) ExitProcess(2);
    position = 0;
}
static void protect(unsigned char *p, SIZE_T size, DWORD value) {
    DWORD old;
    if (!VirtualProtect(p, size, value, &old)) ExitProcess(3);
}
static DWORD protection(unsigned char *p) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(p, &info, sizeof(info))) ExitProcess(4);
    return info.Protect;
}
static ULONG poll() {
    LARGE_INTEGER zero = {};
    return ULONG(wait_id(nullptr, &zero));
}
static DWORD WINAPI worker(void *) {
    worker_tid = GetCurrentThreadId();
    InterlockedExchange(&ready, 1);
    if (WaitForSingleObject(stop_event, INFINITE) != WAIT_OBJECT_0) return 61;
    for (unsigned i = 0; i < 8; ++i) worker_waits[i] = poll();
    return 0x37;
}
static void boundary(unsigned address_kind, unsigned mode, unsigned delta, unsigned pending) {
    for (unsigned i = 0; i < 3; ++i) poll();
    protect(pages, 12288, PAGE_READWRITE);
    for (unsigned i = 0; i < 12288; ++i) pages[i] = 0;
    auto timeout = pages + 4096 - (mode >= 6 ? 1 : 16) + delta;
    if (mode == 1) timeout = reinterpret_cast<unsigned char *>(ULONG_PTR(1));
    const DWORD values[] = {PAGE_READONLY, PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY | PAGE_GUARD};
    if (mode >= 2 && mode <= 5) protect(pages, 4096, values[mode - 2]);
    if (mode == 7) protect(pages + 4096, 4096, PAGE_NOACCESS);
    void *address = nullptr;
    switch (address_kind) {
        case 1: address = reinterpret_cast<void *>(ULONG_PTR(1)); break;
        case 2: address = pages + 256; break;
        case 3: address = reinterpret_cast<void *>(ULONG_PTR(GetCurrentThreadId())); break;
        case 4: address = reinterpret_cast<void *>(~ULONG_PTR(0)); break;
        case 5: address = reinterpret_cast<void *>(ULONG_PTR(worker_tid)); break;
    }
    ULONG alerts[2] = {0xfeedface, 0xfeedface};
    for (unsigned i = 0; i < pending; ++i) alerts[i] = ULONG(alert_id(reinterpret_cast<HANDLE>(ULONG_PTR(GetCurrentThreadId()))));
    SetLastError(0x76543210);
    LONG status = LONG(0xfeedface);
    DWORD exception = 0;
    __try { status = wait_id(address, reinterpret_cast<LARGE_INTEGER *>(timeout)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); }
    DWORD error = GetLastError();
    DWORD first = protection(pages), second = protection(pages + 4096);
    protect(pages, 12288, PAGE_READWRITE);
    ULONG drains[3];
    for (unsigned i = 0; i < 3; ++i) drains[i] = poll();
    text("case"); field(case_index++); field(address_kind); field(mode); field(delta); field(pending);
    field(alerts[0]); field(alerts[1]); field(ULONG(status)); field(exception); field(error);
    field(first); field(second);
    for (ULONG value : drains) field(value);
    flush();
}
static void target(unsigned kind, unsigned phase, ULONG_PTR tid) {
    SetLastError(0x76543210);
    LONG status = LONG(0xfeedface);
    DWORD exception = 0;
    __try { status = alert_id(reinterpret_cast<HANDLE>(tid)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); }
    DWORD error = GetLastError();
    text("target"); field(kind); field(phase); field(tid); field(ULONG(status)); field(exception); field(error);
    for (unsigned i = 0; i < 3; ++i) field(poll());
    flush();
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    alert_id = reinterpret_cast<AlertId>(GetProcAddress(ntdll, "NtAlertThreadByThreadId"));
    wait_id = reinterpret_cast<WaitId>(GetProcAddress(ntdll, "NtWaitForAlertByThreadId"));
    alert_handle = reinterpret_cast<AlertHandle>(GetProcAddress(ntdll, "NtAlertThread"));
    test_alert = reinterpret_cast<TestAlert>(GetProcAddress(ntdll, "NtTestAlert"));
    if (!alert_id || !wait_id || !alert_handle || !test_alert) ExitProcess(1);
    pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!pages || !stop_event) ExitProcess(5);
    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    if (!thread) ExitProcess(6);
    while (!InterlockedCompareExchange(&ready, 0, 0)) Sleep(0);
    text("width"); field(sizeof(void *)); flush();
    for (unsigned address = 0; address < 6; ++address)
        for (unsigned pending = 0; pending < 3; ++pending)
            for (unsigned mode = 0; mode < 8; ++mode)
                for (unsigned delta = 0; delta < 8; ++delta) boundary(address, mode, delta, pending);
    for (unsigned phase = 0; phase < 2; ++phase) {
        if (phase) {
            if (!SetEvent(stop_event) || WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) ExitProcess(7);
            DWORD code;
            if (!GetExitCodeThread(thread, &code) || code != 0x37) ExitProcess(8);
            text("worker"); field(worker_tid); field(code); for (ULONG s : worker_waits) field(s); flush();
        }
        target(0, phase, 0);
        target(1, phase, GetCurrentThreadId());
        for (unsigned tag = 0; tag < 4; ++tag) target(2 + tag, phase, ULONG_PTR(worker_tid) | tag);
        target(6, phase, GetCurrentProcessId());
        for (unsigned tag = 1; tag < 4; ++tag) target(6 + tag, phase, ULONG_PTR(GetCurrentThreadId()) | tag);
#if defined(_WIN64)
        target(10, phase, ULONG_PTR(GetCurrentThreadId()) | (ULONG_PTR(1) << 32));
#endif
    }
    for (unsigned i = 0; i < 3; ++i) poll();
    text("independent"); field(ULONG(alert_handle(GetCurrentThread()))); field(poll());
    field(ULONG(test_alert())); field(ULONG(test_alert()));
    field(ULONG(alert_id(reinterpret_cast<HANDLE>(ULONG_PTR(GetCurrentThreadId())))));
    field(ULONG(test_alert())); field(poll()); field(poll()); flush();
    if (!CloseHandle(thread) || !CloseHandle(stop_event)) ExitProcess(9);
    text("count"); field(case_index); flush();
    ExitProcess(0);
}
