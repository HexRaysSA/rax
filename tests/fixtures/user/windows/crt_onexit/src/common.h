/* Custom-entry explicit onexit tables: x86 ILP32, x64/ARM64 LLP64.
   Table fields follow the retained MinGW corecrt_startup.h declaration as a
   selected profile; Microsoft documents the native table as opaque. */
#ifndef RAX_CRT_ONEXIT_COMMON_H
#define RAX_CRT_ONEXIT_COMMON_H
typedef unsigned int DWORD;
typedef int BOOL;
typedef __SIZE_TYPE__ SIZE;
typedef __UINTPTR_TYPE__ UPTR;
typedef __WCHAR_TYPE__ WCHAR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define CRTCALL __attribute__((cdecl))
#else
#define WINAPI
#define CRTCALL
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
typedef int (CRTCALL *ExitFn)(void);
typedef void (CRTCALL *VoidFn)(void);
typedef struct { VoidFn *first, *last, *end; } Table;
DLL int CRTCALL _initialize_onexit_table(Table *);
DLL int CRTCALL _register_onexit_function(Table *, ExitFn);
DLL int CRTCALL _execute_onexit_table(Table *);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL NORETURN void WINAPI ExitThread(DWORD);
DLL void *WINAPI VirtualAlloc(void *, SIZE, DWORD, DWORD);
DLL BOOL WINAPI VirtualFree(void *, SIZE, DWORD);
DLL BOOL WINAPI VirtualProtect(void *, SIZE, DWORD, DWORD *);
DLL void *WINAPI AddVectoredExceptionHandler(DWORD, int (WINAPI *)(void *));
DLL DWORD WINAPI RemoveVectoredExceptionHandler(void *);
DLL void *WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL DWORD WINAPI WaitForSingleObject(void *, DWORD);
DLL BOOL WINAPI GetExitCodeThread(void *, DWORD *);
DLL BOOL WINAPI CloseHandle(void *);
DLL void *WINAPI HeapAlloc(void *, DWORD, SIZE);
DLL BOOL WINAPI HeapFree(void *, DWORD, void *);
DLL void *WINAPI LoadLibraryW(const WCHAR *);
DLL void *WINAPI GetProcAddress(void *, const char *);
DLL BOOL WINAPI TerminateProcess(void *, DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL void WINAPI SetLastError(DWORD);
DLL void *CRTCALL _get_heap_handle(void);
DLL int *CRTCALL _errno(void);
DLL void *CRTCALL malloc(SIZE);
DLL void CRTCALL free(void *);
DLL void *CRTCALL memset(void *, int, SIZE);
static void check(int condition, DWORD code) { if (!condition) ExitProcess(code); }
static void init(Table *table) { check(_initialize_onexit_table(table) == 0, 101); }
static void reg(Table *table, ExitFn function) { check(_register_onexit_function(table, function) == 0, 102); }
static void drain(Table *table) { check(_execute_onexit_table(table) == 0, 103); }
#endif
