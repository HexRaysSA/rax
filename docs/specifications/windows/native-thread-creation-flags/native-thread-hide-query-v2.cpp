#include <windows.h>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static HANDLE output, thread_handle, handles[12];
static unsigned char *out_pages, *ret_pages;
static char line[2048];
static unsigned position, case_index, creation_flags, life_phase;

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
static void protect(unsigned char *p, SIZE_T size, DWORD value) {
    DWORD old;
    if (!VirtualProtect(p, size, value, &old)) ExitProcess(4);
}
static DWORD protection(unsigned char *p) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(p, &info, sizeof(info))) ExitProcess(5);
    return info.Protect;
}
// Modes 0..6 use the first page; 7..11 cross into the second page.
static unsigned char *location(unsigned char *p, unsigned mode, unsigned delta) {
    const DWORD protections[] = {PAGE_READONLY, PAGE_NOACCESS,
                                 PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY | PAGE_GUARD};
    if (mode == 1) return nullptr;
    if (mode == 2) return reinterpret_cast<unsigned char *>(ULONG_PTR(1));
    if (mode >= 3 && mode <= 6) protect(p, 4096, protections[mode - 3]);
    if (mode >= 8 && mode <= 11) protect(p + 4096, 4096, protections[mode - 8]);
    return p + 4096 - (mode >= 7 ? 1 : 16) + delta;
}
static HANDLE handle(unsigned kind) { return handles[kind]; }
static void run(unsigned kind, unsigned flags, ULONG cls, ULONG length,
                unsigned out_mode = 0, unsigned ret_mode = 0,
                unsigned out_delta = 0, unsigned ret_delta = 0) {
    protect(out_pages, 12288, PAGE_READWRITE);
    protect(ret_pages, 12288, PAGE_READWRITE);
    for (unsigned n = 0; n < 12288; ++n) {
        out_pages[n] = 0xcc; ret_pages[n] = 0xdd;
    }
    auto out = location(out_pages, out_mode, out_delta);
    unsigned char *returned;
    if (ret_mode >= 20) {
        if (out_mode != 0) ExitProcess(8);
        const int offsets[] = {0, 1, -1, 4};
        returned = out + offsets[ret_mode - 20];
    } else {
        returned = location(ret_pages, ret_mode, ret_delta);
    }
    LONG status = LONG(0xfeedface);
    DWORD exception = 0;
    __try {
        status = query(handle(kind), cls, out, length,
                       reinterpret_cast<ULONG *>(returned));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode();
    }
    DWORD op0 = protection(out_pages), op1 = protection(out_pages + 4096);
    DWORD rp0 = protection(ret_pages), rp1 = protection(ret_pages + 4096);
    protect(out_pages, 12288, PAGE_READWRITE);
    protect(ret_pages, 12288, PAGE_READWRITE);
    text("case"); field(case_index++); field(creation_flags); field(life_phase); field(kind); field(length);
    field(out_mode); field(ret_mode); field(out_delta); field(ret_delta);
    field(ULONG(status)); field(exception); field(op0); field(op1); field(rp0); field(rp1);
    bytes(out_pages + 4096 - 32, 64); bytes(ret_pages + 4096 - 32, 64); flush();
}
struct Attributes {
    ULONG length; HANDLE root; void *name; ULONG flags; void *security; void *qos;
};
using Create = LONG(NTAPI *)(HANDLE *, ULONG, Attributes *, HANDLE, void *, void *,
                            ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Terminate = LONG(NTAPI *)(HANDLE, LONG);
static void matrix() {
    const ULONG lengths[] = {0, 1, 2, 3, 4, 8, 4096};
    for (unsigned mode = 0; mode < 12; ++mode) {
        for (ULONG length : lengths) run(0, 0, 17, length, mode);
        for (ULONG length = 0; length < 3; ++length) run(0, 0, 17, length, 0, mode);
    }
    for (unsigned delta = 0; delta < 8; ++delta) run(0, 0, 17, 1, 0, 0, delta);
    for (unsigned delta = 0; delta < 4; ++delta) run(0, 0, 17, 1, 0, 0, 0, delta);
    for (unsigned alias = 20; alias < 24; ++alias)
        for (ULONG length = 0; length < 3; ++length) run(0, 0, 17, length, 0, alias);
    for (unsigned kind = 0; kind < 12; ++kind) {
        run(kind, 0, 17, 1);
        run(kind, 0, 17, 0);
        run(kind, 0, 17, 1, 2);
        run(kind, 0, 17, 1, 0, 2);
    }
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto terminate = reinterpret_cast<Terminate>(GetProcAddress(ntdll, "NtTerminateThread"));
    auto start = reinterpret_cast<void *>(GetProcAddress(ntdll, "RtlExitUserThread"));
    if (!query || !create || !terminate || !start) ExitProcess(1);
    out_pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ret_pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!out_pages || !ret_pages) ExitProcess(2);
    text("width"); field(sizeof(void *)); flush();
    for (unsigned hidden = 0; hidden < 2; ++hidden) {
        creation_flags = 1 | (hidden ? 4 : 0);
        Attributes attributes = {sizeof(Attributes), nullptr, nullptr, 0x200, nullptr, nullptr};
        LONG status = create(&thread_handle, 0x1fffff, &attributes, GetCurrentProcess(),
                             start, nullptr, creation_flags, 0, 0, 0, nullptr);
        if (status < 0) ExitProcess(10);
        handles[0] = thread_handle;
        const DWORD access[] = {0, 0x40, 0x800};
        for (unsigned n = 0; n < 3; ++n)
            if (!DuplicateHandle(GetCurrentProcess(), thread_handle, GetCurrentProcess(),
                                 &handles[n + 1], access[n], FALSE, 0)) ExitProcess(11);
        handles[4] = GetCurrentThread(); handles[5] = GetCurrentProcess();
        handles[6] = nullptr; handles[7] = reinterpret_cast<HANDLE>(ULONG_PTR(0x12345678));
        if (!DuplicateHandle(GetCurrentProcess(), thread_handle, GetCurrentProcess(),
                             &handles[8], 0, FALSE, DUPLICATE_SAME_ACCESS) || !CloseHandle(handles[8])) ExitProcess(12);
        for (unsigned n = 1; n <= 3; ++n)
            handles[n + 8] = reinterpret_cast<HANDLE>(reinterpret_cast<ULONG_PTR>(thread_handle) | n);
        life_phase = 0; matrix();
        if (terminate(thread_handle, 0x37) < 0 || WaitForSingleObject(thread_handle, INFINITE) != WAIT_OBJECT_0) ExitProcess(13);
        life_phase = 1; matrix();
        for (unsigned n = 0; n < 4; ++n) if (!CloseHandle(handles[n])) ExitProcess(14);
    }
    text("count"); field(case_index); flush();
    if (!VirtualFree(out_pages, 0, MEM_RELEASE) || !VirtualFree(ret_pages, 0, MEM_RELEASE)) ExitProcess(15);
    ExitProcess(0);
}
