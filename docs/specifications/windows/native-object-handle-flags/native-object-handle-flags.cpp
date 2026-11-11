#include <windows.h>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static HANDLE output, event_handle, zero_access, process_handle, thread_handle, closed_handle;
static unsigned char *out_pages, *ret_pages;
static char line[2048];
static unsigned position, case_index;

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
static HANDLE handle(unsigned kind) {
    switch (kind) {
    case 0: return event_handle;
    case 1: return zero_access;
    case 2: return process_handle;
    case 3: return thread_handle;
    case 4: return closed_handle;
    case 5: return nullptr;
    case 6: return reinterpret_cast<HANDLE>(ULONG_PTR(0x12345678));
    case 7: case 8: case 9: case 10: case 11: case 12:
        return reinterpret_cast<HANDLE>(~ULONG_PTR(kind - 7));
    case 13: case 14: case 15:
        return reinterpret_cast<HANDLE>(reinterpret_cast<ULONG_PTR>(event_handle) | (kind - 12));
    default: ExitProcess(6);
    }
}
static void run(unsigned kind, unsigned flags, ULONG cls, ULONG length,
                unsigned out_mode = 0, unsigned ret_mode = 0,
                unsigned out_delta = 0, unsigned ret_delta = 0) {
    protect(out_pages, 12288, PAGE_READWRITE);
    protect(ret_pages, 12288, PAGE_READWRITE);
    for (unsigned n = 0; n < 12288; ++n) {
        out_pages[n] = 0xcc; ret_pages[n] = 0xdd;
    }
    if (!SetHandleInformation(event_handle, 3, flags)) ExitProcess(7);
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
    text("case"); field(case_index++); field(kind); field(flags); field(cls); field(length);
    field(out_mode); field(ret_mode); field(out_delta); field(ret_delta);
    field(ULONG(status)); field(exception); field(op0); field(op1); field(rp0); field(rp1);
    bytes(out_pages + 4096 - 32, 64); bytes(ret_pages + 4096 - 32, 64); flush();
    if (!SetHandleInformation(event_handle, 3, 0)) ExitProcess(9);
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    if (!query) ExitProcess(1);
    out_pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ret_pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    event_handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    closed_handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!out_pages || !ret_pages || !event_handle || !closed_handle || !CloseHandle(closed_handle))
        ExitProcess(2);
    if (!DuplicateHandle(GetCurrentProcess(), event_handle, GetCurrentProcess(), &zero_access, 0, FALSE, 0) ||
        !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &process_handle, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &thread_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
        ExitProcess(2);
    // DuplicateHandle may reuse the closed slot: make a fresh closed handle last.
    closed_handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!closed_handle || !CloseHandle(closed_handle)) ExitProcess(2);
    text("width"); field(sizeof(void *)); flush();
    const ULONG lengths[] = {0, 1, 2, 3, 4, 8, 16, 4096};
    for (unsigned flags = 0; flags < 4; ++flags)
        for (ULONG length : lengths) run(0, flags, 4, length);
    for (unsigned kind = 0; kind < 16; ++kind) {
        run(kind, 3, 4, 2);
        run(kind, 3, 4, 0);
        run(kind, 3, 4, 2, 1);
        run(kind, 3, 4, 2, 0, 2);
    }
    for (unsigned delta = 0; delta < 8; ++delta) run(0, 3, 4, 2, 0, 0, delta);
    for (unsigned delta = 0; delta < 4; ++delta) run(0, 3, 4, 2, 0, 0, 0, delta);
    for (unsigned mode = 0; mode < 12; ++mode) {
        for (ULONG length : lengths) run(0, 3, 4, length, mode);
        run(0, 3, 4, 2, 0, mode);
        run(6, 3, 4, 2, mode);
        run(6, 3, 4, 2, 0, mode);
        run(0, 3, 4, 0, 0, mode);
    }
    for (unsigned alias = 20; alias < 24; ++alias) {
        run(0, 3, 4, 2, 0, alias);
        run(0, 3, 4, 0, 0, alias);
        run(6, 3, 4, 2, 0, alias);
    }
    const ULONG classes[] = {5, 6, 7, 8, 0xffffffff};
    for (ULONG cls : classes) {
        run(0, 3, cls, 2);
        run(6, 3, cls, 2);
        run(0, 3, cls, 2, 2);
        run(0, 3, cls, 2, 0, 2);
    }
    text("count"); field(case_index); flush();
    if (!CloseHandle(zero_access) || !CloseHandle(process_handle) ||
        !CloseHandle(thread_handle) || !CloseHandle(event_handle) ||
        !VirtualFree(out_pages, 0, MEM_RELEASE) || !VirtualFree(ret_pages, 0, MEM_RELEASE))
        ExitProcess(10);
    ExitProcess(0);
}
