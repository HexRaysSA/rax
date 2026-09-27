/* Custom-entry guest machine-ABI probes: x86 ILP32; x64/ARM64 LLP64.
   No ordinary CRT startup, C++ runtime, or private FILE layout is assumed. */
#ifndef RAX_CRT_EXIT_COMMON_H
#define RAX_CRT_EXIT_COMMON_H
typedef unsigned int DWORD;
typedef int BOOL;
typedef __SIZE_TYPE__ SIZE;
typedef __UINTPTR_TYPE__ UPTR;
typedef __INTPTR_TYPE__ IPTR;
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
typedef struct File FILE;
typedef void (CRTCALL *PVFV)(void);
typedef void (CRTCALL *SIGNAL)(int);
typedef void (WINAPI *TLS_CALLBACK)(void *, DWORD, void *);
typedef void (CRTCALL *INVALID)(const WCHAR *, const WCHAR *, const WCHAR *, unsigned int, UPTR);
_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "Windows public widths");
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL BOOL WINAPI TerminateProcess(void *, DWORD);
DLL void *WINAPI GetStdHandle(DWORD);
DLL BOOL WINAPI WriteFile(void *, const void *, DWORD, DWORD *, void *);
DLL void *WINAPI CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, void *);
DLL BOOL WINAPI GetFileSizeEx(void *, long long *);
DLL const WCHAR *WINAPI GetCommandLineW(void);
DLL void *WINAPI LoadLibraryW(const WCHAR *);
DLL void *WINAPI GetProcAddress(void *, const char *);
DLL void WINAPI RaiseException(DWORD, DWORD, DWORD, const UPTR *);
DLL int CRTCALL _open_osfhandle(IPTR, int);
DLL FILE *CRTCALL _wfdopen(int, const WCHAR *);
DLL SIZE CRTCALL fwrite(const void *, SIZE, SIZE, FILE *);
DLL int CRTCALL setvbuf(FILE *, char *, int, SIZE);
DLL int CRTCALL _crt_atexit(PVFV);
DLL int CRTCALL _crt_at_quick_exit(PVFV);
DLL NORETURN void CRTCALL exit(int);
DLL NORETURN void CRTCALL quick_exit(int);
DLL NORETURN void CRTCALL _exit(int);
DLL NORETURN void CRTCALL _Exit(int);
DLL void CRTCALL _cexit(void);
DLL void CRTCALL _c_exit(void);
DLL void CRTCALL _register_thread_local_exe_atexit_callback(TLS_CALLBACK);
DLL PVFV CRTCALL set_terminate(PVFV);
DLL PVFV CRTCALL _get_terminate(void);
DLL NORETURN void CRTCALL terminate(void);
DLL NORETURN void CRTCALL abort(void);
DLL unsigned int CRTCALL _set_abort_behavior(unsigned int, unsigned int);
DLL SIGNAL CRTCALL signal(int, SIGNAL);
DLL int CRTCALL raise(int);
DLL int *CRTCALL _errno(void);
DLL INVALID CRTCALL _set_invalid_parameter_handler(INVALID);
void CRTCALL outer_call(PVFV);
void CRTCALL inner_call(PVFV);
void CRTCALL unwind_call(PVFV);
int CRTCALL outer_handler(void *, void *, void *, void *);
int CRTCALL inner_handler(void *, void *, void *, void *);
int CRTCALL unwind_handler(void *, void *, void *, void *);
static NORETURN void forced(DWORD code) {
    TerminateProcess((void *)(IPTR)-1, code);
    for (;;) {}
}
static void check(int condition, DWORD code) { if (!condition) forced(code); }
static void tag(char value) {
    DWORD done = 0;
    check(WriteFile(GetStdHandle((DWORD)-11), &value, 1, &done, 0) && done == 1, 190);
}
#endif
