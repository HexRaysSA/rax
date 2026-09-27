/* Genuine UCRT runtime imports. Custom entry; no CRT startup objects. */
#ifndef RAX_CRT_TERMINATION_COMMON_H
#define RAX_CRT_TERMINATION_COMMON_H
typedef unsigned int DWORD;
typedef int BOOL;
typedef __SIZE_TYPE__ SIZE;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define CRTCALL __attribute__((cdecl))
#else
#define WINAPI
#define CRTCALL
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
typedef void (CRTCALL *PVFV)(void);
typedef int (CRTCALL *ONEXIT)(void);
typedef struct { ONEXIT *first, *last, *end; } TABLE;
_Static_assert(sizeof(DWORD) == 4, "Windows DWORD is 32 bits");
_Static_assert(sizeof(TABLE) == 3 * sizeof(void *), "three-pointer onexit table");
DLL int CRTCALL _crt_atexit(PVFV);
DLL int CRTCALL _crt_at_quick_exit(PVFV);
DLL int CRTCALL _initialize_onexit_table(TABLE *);
DLL int CRTCALL _register_onexit_function(TABLE *, ONEXIT);
DLL int CRTCALL _execute_onexit_table(TABLE *);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL void *WINAPI GetStdHandle(DWORD);
DLL BOOL WINAPI WriteFile(void *, const void *, DWORD, DWORD *, void *);
DLL void *WINAPI CreateEventW(void *, BOOL, BOOL, const unsigned short *);
DLL BOOL WINAPI SetEvent(void *);
DLL DWORD WINAPI WaitForSingleObject(void *, DWORD);
DLL void WINAPI Sleep(DWORD);
DLL void *WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL BOOL WINAPI GetExitCodeThread(void *, DWORD *);
DLL BOOL WINAPI CloseHandle(void *);
static void check(int condition, DWORD code) { if (!condition) ExitProcess(code); }
static void output(const char *bytes, DWORD count) {
    DWORD written = 0;
    check(WriteFile(GetStdHandle((DWORD)-11), bytes, count, &written, 0) && written == count, 190);
}
#endif
