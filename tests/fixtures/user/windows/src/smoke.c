/* Freestanding Windows ABI and process-memory contract fixture. */
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned long long QWORD;
typedef __UINTPTR_TYPE__ UPTR;
typedef __SIZE_TYPE__ SIZE;
typedef void *HANDLE;

#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define TEB_SELF 0x18
#define TEB_CLIENT_ID 0x20
#define TEB_PEB 0x30
#define TEB_LAST_ERROR 0x34
#define PEB_IMAGE_BASE 0x08
#define PEB_HEAP 0x18
#else
#define WINAPI
#define TEB_SELF 0x30
#define TEB_CLIENT_ID 0x40
#define TEB_PEB 0x60
#define TEB_LAST_ERROR 0x68
#define PEB_IMAGE_BASE 0x10
#define PEB_HEAP 0x30
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)

typedef struct {
    void *BaseAddress;
    void *AllocationBase;
    DWORD AllocationProtect;
#if !defined(_M_IX86)
    DWORD Alignment1;
#endif
    SIZE RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
#if !defined(_M_IX86)
    DWORD Alignment2;
#endif
} MBI;

_Static_assert(sizeof(DWORD) == 4, "DWORD is 32 bits");
_Static_assert(sizeof(QWORD) == 8, "QWORD is 64 bits");
_Static_assert(sizeof(MBI) == (sizeof(void *) == 4 ? 28 : 48), "MEMORY_BASIC_INFORMATION layout");

DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL DWORD WINAPI GetCurrentProcessId(void);
DLL DWORD WINAPI GetCurrentThreadId(void);
DLL void WINAPI SetLastError(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL HANDLE WINAPI GetProcessHeap(void);
DLL void *WINAPI HeapAlloc(HANDLE, DWORD, SIZE);
DLL int WINAPI HeapFree(HANDLE, DWORD, void *);
DLL void *WINAPI VirtualAlloc(void *, SIZE, DWORD, DWORD);
DLL SIZE WINAPI VirtualQuery(const void *, MBI *, SIZE);
DLL int WINAPI VirtualProtect(void *, SIZE, DWORD, DWORD *);
DLL int WINAPI VirtualFree(void *, SIZE, DWORD);

enum {
    MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_DECOMMIT = 0x4000,
    MEM_RELEASE = 0x8000, MEM_FREE = 0x10000, MEM_PRIVATE = 0x20000,
    PAGE_READONLY = 2, PAGE_READWRITE = 4, HEAP_ZERO_MEMORY = 8
};

static void check(int condition, DWORD code) {
    if (!condition) ExitProcess(code);
}

static UPTR current_teb(void) {
    UPTR value;
#if defined(_M_IX86)
    __asm__ volatile("movl %%fs:0x18, %0" : "=r"(value));
#elif defined(_M_X64)
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(value));
#elif defined(_M_ARM64)
    __asm__ volatile("mov %0, x18" : "=r"(value));
#else
#error unsupported target
#endif
    return value;
}

static UPTR current_sp(void) {
    UPTR value;
#if defined(_M_IX86)
    __asm__ volatile("movl %%esp, %0" : "=r"(value));
#elif defined(_M_X64)
    __asm__ volatile("movq %%rsp, %0" : "=r"(value));
#else
    __asm__ volatile("mov %0, sp" : "=r"(value));
#endif
    return value;
}

static UPTR word_at(UPTR address, SIZE offset) {
    return *(volatile UPTR *)(address + offset);
}

__declspec(noinline) QWORD pair_return(DWORD high, DWORD low) {
    return ((QWORD)high << 32) | low;
}

__declspec(noinline) UPTR eight_arguments(UPTR a, UPTR b, UPTR c, UPTR d,
                                                UPTR e, UPTR f, UPTR g, UPTR h) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f + 17 * g + 19 * h;
}

static void query(const void *address, MBI *info, DWORD code) {
    check(VirtualQuery(address, info, sizeof(*info)) == sizeof(*info), code);
}

NORETURN void entry(void) {
    DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    UPTR teb = current_teb();
    check(teb != 0 && word_at(teb, TEB_SELF) == teb, 10);
    check(pid != 0 && tid != 0, 11);
    check(word_at(teb, TEB_CLIENT_ID) == pid, 12);
    check(word_at(teb, TEB_CLIENT_ID + sizeof(UPTR)) == tid, 13);
    UPTR peb = word_at(teb, TEB_PEB);
    check(peb != 0, 14);
    UPTR image = word_at(peb, PEB_IMAGE_BASE);
    check(image != 0 && *(volatile WORD *)image == 0x5A4D, 15);
    check((current_sp() & (sizeof(UPTR) == 4 ? 3 : 15)) == 0, 16);
    SetLastError(0x89ABCDEF);
    check(GetLastError() == 0x89ABCDEF, 17);
    check(*(volatile DWORD *)(teb + TEB_LAST_ERROR) == 0x89ABCDEF, 18);
    check(pair_return(pid ^ 0xA1B2C3D4, tid ^ 0xD4C3B2A1) ==
          (((QWORD)(pid ^ 0xA1B2C3D4) << 32) | (tid ^ 0xD4C3B2A1)), 19);
    check(eight_arguments(pid, tid, 3, 4, 5, 6, 7, 8) == (UPTR)pid + 3 * (UPTR)tid + 447, 20);

    HANDLE heap = GetProcessHeap();
    check(heap != 0 && (UPTR)heap == word_at(peb, PEB_HEAP), 30);
    volatile BYTE *bytes = (volatile BYTE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, 257);
    check(bytes != 0, 31);
    check(((UPTR)bytes & (sizeof(UPTR) == 4 ? 7 : 15)) == 0, 32);
    for (SIZE i = 0; i < 257; ++i) {
        check(bytes[i] == 0, 33);
        bytes[i] = (BYTE)(i ^ 0xA5);
    }
    check(GetCurrentProcessId() == pid && GetCurrentThreadId() == tid, 34);
    for (SIZE i = 0; i < 257; ++i) check(bytes[i] == (BYTE)(i ^ 0xA5), 35);
    check(HeapFree(heap, 0, (void *)bytes) != 0, 36);

    BYTE *base = (BYTE *)VirtualAlloc(0, 0x3000, MEM_RESERVE, PAGE_READWRITE);
    check(base != 0 && ((UPTR)base & 0xFFFF) == 0, 40);
    MBI info;
    query(base, &info, 41);
    check(info.AllocationBase == base && info.BaseAddress == base, 42);
    check(info.State == MEM_RESERVE && info.RegionSize >= 0x3000, 43);
    check(info.AllocationProtect == PAGE_READWRITE && info.Type == MEM_PRIVATE, 44);
    BYTE *committed = (BYTE *)VirtualAlloc(base + 0x1000, 0x1001, MEM_COMMIT, PAGE_READWRITE);
    check(committed == base + 0x1000, 45);
    query(committed, &info, 46);
    check(info.State == MEM_COMMIT && info.Protect == PAGE_READWRITE, 47);
    check(info.RegionSize == 0x2000 && info.AllocationBase == base, 48);
    for (SIZE i = 0; i < 0x2000; ++i) check(((volatile BYTE *)committed)[i] == 0, 49);
    ((volatile BYTE *)committed)[0] = 0xA5;
    ((volatile BYTE *)committed)[0x1FFF] = 0x5A;
    DWORD old = 0;
    check(VirtualProtect(committed, 0x1000, PAGE_READONLY, &old) != 0, 50);
    check(old == PAGE_READWRITE, 51);
    query(committed, &info, 52);
    check(info.Protect == PAGE_READONLY && info.RegionSize == 0x1000, 53);
    query(committed + 0x1000, &info, 54);
    check(info.Protect == PAGE_READWRITE && info.RegionSize == 0x1000, 55);
    check(VirtualProtect(committed, 0x1000, PAGE_READWRITE, &old) != 0 && old == PAGE_READONLY, 56);
    check(VirtualFree(committed, 0x1000, MEM_DECOMMIT) != 0, 57);
    query(committed, &info, 58);
    check(info.State == MEM_RESERVE, 59);
    check(VirtualAlloc(committed, 0x1000, MEM_COMMIT, PAGE_READWRITE) == committed, 60);
    for (SIZE i = 0; i < 0x1000; ++i) check(((volatile BYTE *)committed)[i] == 0, 61);
    check(((volatile BYTE *)committed)[0x1FFF] == 0x5A, 62);
    check(VirtualFree(base, 1, MEM_RELEASE) == 0, 63);
    query(committed, &info, 64);
    check(info.State == MEM_COMMIT, 65);
    check(VirtualFree(base, 0, MEM_RELEASE) != 0, 66);
    query(base, &info, 67);
    check(info.State == MEM_FREE, 68);
    ExitProcess(0);
}
