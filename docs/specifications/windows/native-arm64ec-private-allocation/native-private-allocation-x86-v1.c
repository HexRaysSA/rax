/* Independent WoW64 oracle. No CRT, RAX, remote handles or foreign mappings. */
#include <windows.h>
typedef LONG (NTAPI *Allocate)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
static char line[1024];
static unsigned length;
static PVOID owned[256];
static unsigned owners;
static void text(const char *s) { while (*s) line[length++] = *s++; }
static void hex(ULONGLONG value) {
    unsigned n = 16;
    while (n > 1 && !(value >> ((n - 1) * 4))) --n;
    while (n) line[length++] = "0123456789abcdef"[(value >> (--n * 4)) & 15];
}
static void field(const char *name, ULONGLONG value) { text(" "); text(name); text("="); hex(value); }
static void emit(void) {
    DWORD done = 0; line[length++] = '\n';
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, length, &done, NULL) || done != length) ExitProcess(3);
    length = 0;
}
void mainCRTStartup(void) {
    Allocate allocate = (Allocate)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemoryEx");
    static const ULONGLONG attributes[] = {0, 0x40, 1, 0x41, 0x80, 0x100000000ull, 0x100000040ull};
    static const ULONG flags[] = {0x2000, 0x1000, 0x3000, 0x1000};
    static const ULONG protect[] = {0, 1, 4, 0x10, 0x20, 0x40};
    static const char *modes[] = {"reserve", "commit", "both", "existing"};
    unsigned index = 0, a, m, p, n;
    if (!allocate) ExitProcess(1);
    text("PROFILE arch=x86 pointer_bytes=4 integer_format=hex bitmap=unavailable"); emit();
    for (a = 0; a < 7; ++a) for (m = 0; m < 4; ++m) for (p = 0; p < 6; ++p) {
        MEM_EXTENDED_PARAMETER parameter;
        PVOID original = NULL, base;
        SIZE_T requested = m == 0 || m == 2 ? 65536 : 4096, size = requested;
        LONG status;
        ++index;
        parameter.Type = MemExtendedParameterAttributeFlags;
        parameter.Reserved = 0;
        parameter.ULong64 = attributes[a];
        if (m == 3) {
            original = VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_READWRITE);
            if (!original) ExitProcess(2);
        }
        base = original;
        status = allocate((HANDLE)(LONG_PTR)-1, &base, &size, flags[m], protect[p], &parameter, 1);
        text("CASE"); field("index", index); field("attributes", attributes[a]); text(" mode="); text(modes[m]);
        field("flags", flags[m]); field("protect", protect[p]); field("requested", requested); field("original", (ULONG_PTR)original);
        field("status", (ULONG)status); field("base", (ULONG_PTR)base); field("size", size);
        if (status >= 0) {
            MEMORY_BASIC_INFORMATION info;
            SIZE_T got = VirtualQuery(base, &info, sizeof(info));
            field("queried", got);
            if (got == sizeof(info)) { field("state", info.State); field("actual_protect", info.Protect); field("type", info.Type); field("region", info.RegionSize); }
        }
        emit();
        if (original) owned[owners++] = original;
        else if (status >= 0) { if (!base) ExitProcess(4); owned[owners++] = base; }
    }
    for (n = 0; n < owners; ++n) if (!VirtualFree(owned[n], 0, MEM_RELEASE)) ExitProcess(5);
    text("COMPLETE"); field("cases", index); field("released", owners); text(" all_owned_allocations_released=true"); emit();
    ExitProcess(0);
}
