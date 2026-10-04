/* SDK/CRT-free probe of the public SList, processor-feature and system-time
 * imports. Each failed check exits with its own nonzero code; success exits 0.
 */
typedef unsigned int U32;
typedef unsigned short U16;
typedef unsigned long long U64;
typedef __UINTPTR_TYPE__ UPTR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)

/* SLIST_ENTRY and SLIST_HEADER: 16-byte aligned on x64 and ARM64. */
typedef struct __attribute__((aligned(16))) Entry {
    struct Entry *next;
} Entry;
typedef struct __attribute__((aligned(16))) Header {
    U64 words[2];
} Header;

DLL NORETURN void WINAPI ExitProcess(U32);
DLL void WINAPI InitializeSListHead(Header *);
DLL Entry *WINAPI InterlockedPushEntrySList(Header *, Entry *);
DLL Entry *WINAPI InterlockedPopEntrySList(Header *);
DLL Entry *WINAPI InterlockedFlushSList(Header *);
DLL U16 WINAPI QueryDepthSList(Header *);
DLL Entry *WINAPI InterlockedPushListSListEx(Header *, Entry *, Entry *, U32);
DLL int WINAPI IsProcessorFeaturePresent(U32);
DLL void WINAPI GetSystemTimeAsFileTime(U64 *);
DLL void *WINAPI GetModuleHandleA(const char *);
DLL void *WINAPI GetProcAddress(void *, const char *);
DLL void *WINAPI CreateThread(void *, UPTR, U32(WINAPI *)(void *), void *, U32, U32 *);
DLL U32 WINAPI WaitForSingleObject(void *, U32);
DLL int WINAPI CloseHandle(void *);

enum { PER_THREAD = 1000, INFINITE = 0xFFFFFFFFu };

static void check(int condition, U32 failure) {
    if (!condition) ExitProcess(failure);
}

static Header list;
static Entry entries[8];
static Entry pool[2][PER_THREAD];
static Header shared;

/* Pushes then pops its own entries on the shared list; another thread does
 * the same at the same time. Every pop must return some entry. */
static U32 WINAPI worker(void *raw) {
    Entry *mine = (Entry *)raw;
    for (U32 i = 0; i < PER_THREAD; ++i) InterlockedPushEntrySList(&shared, &mine[i]);
    for (U32 i = 0; i < PER_THREAD; ++i) {
        if (InterlockedPopEntrySList(&shared) == 0) return 1;
    }
    return 0;
}

#if defined(_M_IX86) || defined(_M_X64)
static void cpuid(U32 leaf, U32 out[4]) {
    __asm__ volatile("cpuid" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "a"(leaf), "c"(0));
}
#endif

void entry(void) {
    /* Last in, first out, with depth and an empty pop. */
    InitializeSListHead(&list);
    check(QueryDepthSList(&list) == 0, 10);
    check(InterlockedPushEntrySList(&list, &entries[0]) == 0, 11);
    check(InterlockedPushEntrySList(&list, &entries[1]) == &entries[0], 12);
    check(QueryDepthSList(&list) == 2, 13);
    check(InterlockedPopEntrySList(&list) == &entries[1], 14);
    check(InterlockedPopEntrySList(&list) == &entries[0], 15);
    check(InterlockedPopEntrySList(&list) == 0, 16);

    /* Flush hands back the chain with its links intact. */
    for (U32 i = 2; i < 5; ++i) InterlockedPushEntrySList(&list, &entries[i]);
    Entry *chain = InterlockedFlushSList(&list);
    check(chain == &entries[4] && chain->next == &entries[3], 20);
    check(entries[3].next == &entries[2] && entries[2].next == 0, 21);
    check(QueryDepthSList(&list) == 0 && InterlockedFlushSList(&list) == 0, 22);

    /* A prepared chain is pushed in one operation. */
    InterlockedPushEntrySList(&list, &entries[5]);
    entries[6].next = &entries[7];
    check(InterlockedPushListSListEx(&list, &entries[6], &entries[7], 2) == &entries[5], 30);
    check(entries[7].next == &entries[5] && QueryDepthSList(&list) == 3, 31);

    /* KERNEL32 forwards to NTDLL: both names are one function. */
    void *kernel32 = GetModuleHandleA("kernel32.dll");
    void *ntdll = GetModuleHandleA("ntdll.dll");
    check(kernel32 != 0 && ntdll != 0, 40);
    check(GetProcAddress(kernel32, "InitializeSListHead") == GetProcAddress(ntdll, "RtlInitializeSListHead"),
          41);
    check(GetProcAddress(kernel32, "RtlCaptureContext") == GetProcAddress(ntdll, "RtlCaptureContext"), 42);

    /* Fast fail is always there; the feature range ends at 63. */
    check(IsProcessorFeaturePresent(23) != 0, 50);
    check(IsProcessorFeaturePresent(64) == 0, 51);
#if defined(_M_IX86) || defined(_M_X64)
    /* SSE2 is what the guest's own CPUID says it is. */
    U32 regs[4];
    cpuid(1, regs);
    check((IsProcessorFeaturePresent(10) != 0) == ((regs[3] >> 26) & 1), 52);
#endif

    /* System time is after 2020-01-01 and does not run backwards. */
    U64 first = 0, second = 0;
    GetSystemTimeAsFileTime(&first);
    GetSystemTimeAsFileTime(&second);
    check(first >= 132223104000000000ull && second >= first, 60);

    /* Two threads contend for one list; the total depth is conserved. */
    InitializeSListHead(&shared);
    U32 tid = 0;
    void *threads[2];
    for (U32 t = 0; t < 2; ++t) {
        threads[t] = CreateThread(0, 0, worker, pool[t], 0, &tid);
        check(threads[t] != 0, 70);
    }
    for (U32 t = 0; t < 2; ++t) {
        check(WaitForSingleObject(threads[t], INFINITE) == 0, 71);
        CloseHandle(threads[t]);
    }
    check(QueryDepthSList(&shared) == 0 && InterlockedPopEntrySList(&shared) == 0, 72);

    ExitProcess(0);
}
