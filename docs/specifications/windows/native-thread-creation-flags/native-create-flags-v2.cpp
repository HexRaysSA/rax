#include <windows.h>

struct Attributes {
    ULONG length;
    HANDLE root;
    void *name;
    ULONG flags;
    void *security;
    void *qos;
};
struct Basic {
    LONG exit_status;
    void *teb;
    HANDLE process_id;
    HANDLE thread_id;
    ULONG_PTR affinity;
    LONG priority;
    LONG base_priority;
};
static_assert(sizeof(Basic) == (sizeof(void *) == 8 ? 48 : 28));
using Create = LONG(NTAPI *)(HANDLE *, ULONG, Attributes *, HANDLE, void *, void *,
                            ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Terminate = LONG(NTAPI *)(HANDLE, LONG);
static HANDLE output;
static char line[2048];
static unsigned position;

static void text(const char *s) {
    while (*s) line[position++] = *s++;
}
static void hex(ULONG_PTR value) {
    const char digits[] = "0123456789abcdef";
    for (unsigned n = sizeof(value) * 2; n; --n)
        line[position++] = digits[(value >> ((n - 1) * 4)) & 15];
}
static void field(ULONG_PTR value) {
    text(" "); hex(value);
}
static void bytes(const unsigned char *p, unsigned size) {
    const char digits[] = "0123456789abcdef";
    text(" ");
    for (unsigned n = 0; n < size; ++n) {
        line[position++] = digits[p[n] >> 4];
        line[position++] = digits[p[n] & 15];
    }
}
static void flush() {
    text("\n");
    DWORD written;
    if (!WriteFile(output, line, position, &written, nullptr) || written != position)
        ExitProcess(3);
    position = 0;
}

extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    auto terminate = reinterpret_cast<Terminate>(GetProcAddress(ntdll, "NtTerminateThread"));
    auto start = reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlExitUserThread"));
    if (!create || !query || !terminate || !start) ExitProcess(1);
    text("width"); field(sizeof(void *)); flush();
    for (unsigned index = 0; index < 8; ++index) {
        ULONG flags = 1;
        if (index & 1) flags |= 2;
        if (index & 2) flags |= 4;
        if (index & 4) flags |= 0x20;
        Attributes attributes = {sizeof(Attributes), nullptr, nullptr, 0x200, nullptr, nullptr};
        HANDLE thread = reinterpret_cast<HANDLE>(ULONG_PTR(0x5a5a5a5a));
        LONG created = create(&thread, 0x1fffff, &attributes, GetCurrentProcess(), start,
                              reinterpret_cast<void *>(ULONG_PTR(0x37)), flags,
                              0, 0, 0, nullptr);
        text("case"); field(index); field(flags); field(ULONG(created));
        field(reinterpret_cast<ULONG_PTR>(thread));
        if (created < 0) { flush(); continue; }
        Basic basic = {};
        ULONG basic_length = 0xfeedface;
        LONG queried = query(thread, 0, &basic, sizeof(basic), &basic_length);
        alignas(8) unsigned char hidden = 0xcc;
        ULONG hidden_length = 0xfeedface;
        LONG hide_status = query(thread, 17, &hidden, 1, &hidden_length);
        unsigned char data[64];
        for (unsigned n = 0; n < sizeof(data); ++n) data[n] = 0xcc;
        SIZE_T read = 0;
        ULONG offset = sizeof(void *) == 8 ? 0x17c0 : 0xfa0;
        BOOL readable = queried >= 0 && basic.teb &&
            ReadProcessMemory(GetCurrentProcess(),
                              static_cast<unsigned char *>(basic.teb) + offset,
                              data, sizeof(data), &read);
        unsigned char companion[64];
        for (unsigned n = 0; n < sizeof(companion); ++n) companion[n] = 0xcc;
        SIZE_T companion_read = 0;
        ULONG_PTR companion_base = 0;
        BOOL companion_ok = FALSE;
        if (sizeof(void *) == 4 && readable) {
            ULONG raw_delta = ULONG(data[60]) | (ULONG(data[61]) << 8) |
                              (ULONG(data[62]) << 16) | (ULONG(data[63]) << 24);
            LONG delta = LONG(raw_delta);
            if (delta != 0) {
                companion_base = reinterpret_cast<ULONG_PTR>(basic.teb) + delta;
                companion_ok = ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<void *>(companion_base + 0x17c0),
                    companion, sizeof(companion), &companion_read);
            }
        }
        DWORD handle_flags = 0xfeedface;
        BOOL handle_queried = GetHandleInformation(thread, &handle_flags);
        // This oracle qualifies kernel initialization, not user-loader execution.
        // The owned thread remains suspended and is retired without resuming it.
        LONG stopped = terminate(thread, 0x37);
        DWORD waited = stopped >= 0 ? WaitForSingleObject(thread, INFINITE) : WAIT_FAILED;
        DWORD exit_code = 0xfeedface;
        BOOL exited = GetExitCodeThread(thread, &exit_code);
        BOOL closed = CloseHandle(thread);
        field(ULONG(queried)); field(basic_length); field(ULONG(basic.exit_status));
        field(reinterpret_cast<ULONG_PTR>(basic.teb));
        field(readable); field(read); field(offset);
        field(ULONG(hide_status)); field(hidden); field(hidden_length);
        field(handle_queried); field(handle_flags);
        field(ULONG(stopped)); field(waited); field(exited); field(exit_code); field(closed);
        field(companion_ok); field(companion_read); field(companion_base);
        bytes(data, sizeof(data)); bytes(companion, sizeof(companion)); flush();
        if (queried < 0 || !readable || read != sizeof(data) || !handle_queried ||
            stopped < 0 || waited != WAIT_OBJECT_0 || !exited || exit_code != 0x37 || !closed)
            ExitProcess(2);
    }
    ExitProcess(0);
}
