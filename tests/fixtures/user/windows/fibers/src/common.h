/* SDK/CRT-free Windows fiber probe declarations. Sizes follow the public ABI. */
#ifndef RAX_FIBERS_COMMON_H
#define RAX_FIBERS_COMMON_H
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef __UINTPTR_TYPE__ UPTR;
typedef __SIZE_TYPE__ SIZE;
typedef void *HANDLE;
typedef int BOOL;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define FIBER_OFFSET 0x10
#define STACK_BASE_OFFSET 4
#define STACK_LIMIT_OFFSET 8
#else
#define WINAPI
#define FIBER_OFFSET 0x20
#define STACK_BASE_OFFSET 8
#define STACK_LIMIT_OFFSET 16
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
#define COOKIE ((UPTR)(sizeof(UPTR) == 4 ? 0xabcd0123u : 0x12345678abcd0123ull))
#define INFINITE 0xffffffffu
#define FLOAT_SWITCH 1u
#define CAPACITY 32
typedef void (WINAPI *FiberProc)(void *);
typedef void (WINAPI *FlsCallback)(void *);
DLL void *WINAPI ConvertThreadToFiber(void *);
DLL void *WINAPI ConvertThreadToFiberEx(void *, DWORD);
DLL BOOL WINAPI ConvertFiberToThread(void);
DLL void *WINAPI CreateFiber(SIZE, FiberProc, void *);
DLL void *WINAPI CreateFiberEx(SIZE, SIZE, DWORD, FiberProc, void *);
DLL void WINAPI SwitchToFiber(void *);
DLL void WINAPI DeleteFiber(void *);
DLL BOOL WINAPI IsThreadAFiber(void);
DLL DWORD WINAPI FlsAlloc(FlsCallback);
DLL BOOL WINAPI FlsFree(DWORD);
DLL void *WINAPI FlsGetValue(DWORD);
DLL BOOL WINAPI FlsSetValue(DWORD, void *);
DLL DWORD WINAPI TlsAlloc(void);
DLL BOOL WINAPI TlsFree(DWORD);
DLL void *WINAPI TlsGetValue(DWORD);
DLL BOOL WINAPI TlsSetValue(DWORD, void *);
DLL DWORD WINAPI GetCurrentThreadId(void);
DLL HANDLE WINAPI GetCurrentProcess(void);
DLL DWORD WINAPI GetLastError(void);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL NORETURN void WINAPI ExitThread(DWORD);
DLL BOOL WINAPI TerminateThread(HANDLE, DWORD);
DLL BOOL WINAPI TerminateProcess(HANDLE, DWORD);
DLL HANDLE WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const WORD *);
DLL BOOL WINAPI SetEvent(HANDLE);
DLL DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLL BOOL WINAPI CloseHandle(HANDLE);
DLL HANDLE WINAPI CreateFileW(const WORD *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
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
enum { MEM_FREE = 0x10000, MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000 };
static void check(int condition, DWORD code) {
    if (!condition) ExitProcess(code);
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
/* Public winnt.h macros: NT_TIB.FiberData, then its first pointer cell. */
static void *current_fiber(void) {
    return *(void **)(current_teb() + FIBER_OFFSET);
}
static void *fiber_data(void) { return *(void **)current_fiber(); }
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
static void stack_check(DWORD code) {
    UPTR teb = current_teb(), sp = current_sp();
    UPTR base = *(UPTR *)(teb + STACK_BASE_OFFSET);
    UPTR limit = *(UPTR *)(teb + STACK_LIMIT_OFFSET);
    check(limit < sp && sp < base, code);
#if !defined(_M_IX86)
    check((sp & 15) == 0, code + 1);
#endif
}
static HANDLE event(void) {
    HANDLE e = CreateEventW(0, 1, 0, 0);
    check(e != 0, 201);
    return e;
}
static void wait(HANDLE e) { check(WaitForSingleObject(e, INFINITE) == 0, 202); }
static void signal(HANDLE e) { check(SetEvent(e), 203); }
static void close(HANDLE e) { check(CloseHandle(e), 204); }
#endif
