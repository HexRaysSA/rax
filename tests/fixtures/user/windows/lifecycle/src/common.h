/* Freestanding Windows lifecycle types: no SDK or CRT is linked. */
#ifndef RAX_LIFECYCLE_COMMON_H
#define RAX_LIFECYCLE_COMMON_H
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef __UINTPTR_TYPE__ UPTR;
typedef __SIZE_TYPE__ SIZE;
typedef void *HANDLE;
typedef int BOOL;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define TLS_POINTER 0x2c
#else
#define WINAPI
#define TLS_POINTER 0x58
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
#define CAPACITY 128
#define COOKIE ((UPTR)(sizeof(UPTR) == 4 ? 0xabcddcbau : 0x12345678abcddcbaull))
#define INITIAL(id) (0x13570000u + (id))
enum { LEAF = 1, ROOT = 2, FAIL = 3, DATA = 4 };
enum { TLS_FIRST = 1, TLS_SECOND = 2, DLL_MAIN = 3 };
typedef struct {
    DWORD module, kind;
    UPTR base;
    DWORD reason;
    UPTR reserved, tls;
    DWORD tid;
    UPTR sp, cookie;
} Record;
_Static_assert(sizeof(DWORD) == 4, "DWORD width");
_Static_assert(sizeof(Record) == (sizeof(UPTR) == 4 ? 36 : 64), "record layout");
DLL void WINAPI Log(DWORD, DWORD, void *, DWORD, void *, UPTR, DWORD, UPTR, UPTR);
DLL DWORD WINAPI LogCount(void);
DLL const Record *WINAPI LogAt(DWORD);
DLL void WINAPI LogClear(void);
DLL DWORD WINAPI GetCurrentThreadId(void);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL HANDLE WINAPI LoadLibraryA(const char *);
DLL HANDLE WINAPI LoadLibraryW(const WORD *);
DLL HANDLE WINAPI GetModuleHandleA(const char *);
DLL HANDLE WINAPI GetModuleHandleW(const WORD *);
DLL void *WINAPI GetProcAddress(HANDLE, const char *);
DLL BOOL WINAPI FreeLibrary(HANDLE);
DLL HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const WORD *);
DLL BOOL WINAPI SetEvent(HANDLE);
DLL HANDLE WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLL BOOL WINAPI CloseHandle(HANDLE);
DLL HANDLE WINAPI CreateFileW(const WORD *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
DLL BOOL WINAPI ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
DLL BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
typedef struct {
    void *base, *allocation;
    DWORD allocation_protect;
#if !defined(_M_IX86)
    DWORD padding1;
#endif
    SIZE size;
    DWORD state, protect, type;
#if !defined(_M_IX86)
    DWORD padding2;
#endif
} MBI;
DLL SIZE WINAPI VirtualQuery(const void *, MBI *, SIZE);
enum { INFINITE = 0xffffffffu, MEM_FREE = 0x10000, MEM_IMAGE = 0x1000000 };
static void check(int condition, DWORD code) {
    if (!condition) ExitProcess(code);
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
static UPTR current_teb(void) {
    UPTR value;
#if defined(_M_IX86)
    __asm__ volatile("movl %%fs:0x18, %0" : "=r"(value));
#elif defined(_M_X64)
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(value));
#else
    __asm__ volatile("mov %0, x18" : "=r"(value));
#endif
    return value;
}
typedef DWORD (WINAPI *ReadTls)(void);
typedef void (WINAPI *SetTls)(DWORD);
typedef UPTR (WINAPI *ProbeFn)(UPTR, UPTR, UPTR, UPTR, UPTR, UPTR, UPTR, UPTR, UPTR);
static UPTR probe_expected(void) {
    return COOKIE + 2 + 3*3 + 5*4 + 7*5 + 11*6 + 13*7 + 17*8 + 19*9;
}
#endif
