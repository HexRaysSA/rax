/* Genuine custom-entry UCRT/API-set witnesses; no compiler CRT startup. */
#ifndef RAX_CRT_BOOTSTRAP_COMMON_H
#define RAX_CRT_BOOTSTRAP_COMMON_H
typedef unsigned int DWORD;
typedef int BOOL;
typedef __SIZE_TYPE__ SIZE;
typedef unsigned short WCHAR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define CRTCALL __attribute__((cdecl))
#else
#define WINAPI
#define CRTCALL
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
typedef void (CRTCALL *INVALID)(const WCHAR *, const WCHAR *, const WCHAR *, unsigned int, SIZE);
typedef int (CRTCALL *MATHERR)(void *);
DLL void CRTCALL _set_app_type(int);
DLL int CRTCALL _query_app_type(void);
DLL int CRTCALL _configthreadlocale(int);
DLL void CRTCALL __setusermatherr(MATHERR);
DLL void CRTCALL _fpreset(void);
DLL void **CRTCALL __pxcptinfoptrs(void);
DLL INVALID CRTCALL _set_invalid_parameter_handler(INVALID);
DLL int *CRTCALL _errno(void);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL WCHAR *WINAPI GetCommandLineW(void);
DLL void *WINAPI GetStdHandle(DWORD);
DLL BOOL WINAPI WriteFile(void *, const void *, DWORD, DWORD *, void *);
DLL void WINAPI SetLastError(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL void *WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL DWORD WINAPI WaitForSingleObject(void *, DWORD);
DLL BOOL WINAPI GetExitCodeThread(void *, DWORD *);
DLL BOOL WINAPI CloseHandle(void *);
_Static_assert(sizeof(int) == 4 && sizeof(DWORD) == 4, "Windows C int/DWORD width");
static void check(int condition, DWORD code) { if (!condition) ExitProcess(code); }
static void output(const char *text, DWORD bytes) {
    DWORD written = 0;
    check(WriteFile(GetStdHandle((DWORD)-11), text, bytes, &written, 0) && written == bytes, 190);
}
static unsigned int mode(void) {
    const WCHAR *p = GetCommandLineW();
    while (*p && *p != ' ') ++p;
    while (*p == ' ') ++p;
    unsigned int result = 0;
    while (*p >= '0' && *p <= '9') { result = result * 10 + *p - '0'; ++p; }
    return result;
}
#endif
