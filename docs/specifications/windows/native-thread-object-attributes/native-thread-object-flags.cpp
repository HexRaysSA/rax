#include <windows.h>

struct Attributes {
    ULONG length;
    HANDLE root;
    void *name;
    ULONG flags;
    void *security;
    void *qos;
};
using Create = LONG(NTAPI *)(HANDLE *, ULONG, Attributes *, HANDLE, void *, void *,
                            ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Resume = LONG(NTAPI *)(HANDLE, ULONG *);
static HANDLE output;
static char line[256];
static unsigned position;

static void text(const char *value) {
    while (*value) line[position++] = *value++;
}
static void hex(ULONG_PTR value) {
    const char digits[] = "0123456789abcdef";
    for (unsigned n = sizeof(value) * 2; n; --n)
        line[position++] = digits[(value >> ((n - 1) * 4)) & 15];
}
static void flush() {
    DWORD written;
    text("\n");
    if (!WriteFile(output, line, position, &written, nullptr) || written != position)
        ExitProcess(3);
    position = 0;
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto resume = reinterpret_cast<Resume>(GetProcAddress(ntdll, "NtResumeThread"));
    auto start = reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlExitUserThread"));
    if (!create || !resume || !start) ExitProcess(1);
    text("width "); hex(sizeof(void *)); flush();
    for (unsigned index = 0; index < 291; ++index) {
        ULONG flags = 0;
        if (index < 256) {
            const ULONG bits[] = {2, 0x40, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x10000};
            for (unsigned bit = 0; bit < 8; ++bit)
                if (index & (1u << bit)) flags |= bits[bit];
        } else if (index < 288) {
            flags = ULONG(1) << (index - 256);
        } else {
            const ULONG invalid[] = {0xffffffff, 0x220, 0x11f62};
            flags = invalid[index - 288];
        }
        Attributes attributes = {sizeof(Attributes), nullptr, nullptr, flags, nullptr, nullptr};
        HANDLE thread = reinterpret_cast<HANDLE>(ULONG_PTR(0x5a5a5a5a));
        LONG status = create(&thread, 0x1fffff, &attributes, GetCurrentProcess(), start,
                             nullptr, 1, 0, 0, 0, nullptr);
        text("case "); hex(index); text(" "); hex(flags); text(" "); hex(ULONG(status));
        text(" "); hex(reinterpret_cast<ULONG_PTR>(thread));
        if (status >= 0) {
            DWORD handleFlags = 0;
            BOOL queried = GetHandleInformation(thread, &handleFlags);
            ULONG previous = 0xfeed;
            LONG resumed = resume(thread, &previous);
            DWORD waited = WaitForSingleObject(thread, INFINITE);
            DWORD code = 0xfeed;
            BOOL exited = GetExitCodeThread(thread, &code);
            BOOL closed = CloseHandle(thread);
            text(" "); hex(queried); text(" "); hex(handleFlags);
            text(" "); hex(ULONG(resumed)); text(" "); hex(previous);
            text(" "); hex(waited); text(" "); hex(exited); text(" "); hex(code);
            text(" "); hex(closed);
            if (resumed < 0 || waited != WAIT_OBJECT_0 || !exited || code || !closed)
                ExitProcess(2);
        }
        flush();
    }
    ExitProcess(0);
}
