/* Custom-entry probes: x86 ILP32, x64/ARM64 LLP64. No CRT entry/stdio/exit. */
#ifndef RAX_CRT_STARTUP_COMMON_H
#define RAX_CRT_STARTUP_COMMON_H
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
typedef struct { int newmode; } STARTINFO;
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL void *WINAPI LoadLibraryA(const char *);
DLL void *WINAPI GetProcAddress(void *, const char *);
DLL void *WINAPI VirtualAlloc(void *, SIZE, DWORD, DWORD);
DLL BOOL WINAPI VirtualFree(void *, SIZE, DWORD);
DLL BOOL WINAPI VirtualProtect(void *, SIZE, DWORD, DWORD *);
DLL void *WINAPI AddVectoredExceptionHandler(DWORD, int (WINAPI *)(void *));
DLL DWORD WINAPI RemoveVectoredExceptionHandler(void *);
DLL void *CRTCALL malloc(SIZE);
DLL void CRTCALL free(void *);
#if defined(LEGACY_CRT)
DLL int CRTCALL __getmainargs(int *, char ***, char ***, int, STARTINFO *);
DLL int CRTCALL __wgetmainargs(int *, WCHAR ***, WCHAR ***, int, STARTINFO *);
DLL int __argc;
DLL char **__argv;
DLL WCHAR **__wargv;
DLL char *_acmdln;
DLL WCHAR *_wcmdln;
DLL char *_pgmptr;
DLL WCHAR *_wpgmptr;
#if !defined(_M_ARM64)
DLL char **_environ;
DLL WCHAR **_wenviron;
DLL char **__initenv;
DLL WCHAR **__winitenv;
#define HAVE_ENV_CELLS 1
#else
DLL void CRTCALL _get_environ(char ***);
DLL void CRTCALL _get_wenviron(WCHAR ***);
#endif
#if defined(_M_IX86)
DLL int *CRTCALL __p___argc(void);
DLL char ***CRTCALL __p___argv(void);
DLL WCHAR ***CRTCALL __p___wargv(void);
DLL char ***CRTCALL __p___initenv(void);
DLL WCHAR ***CRTCALL __p___winitenv(void);
DLL char ***CRTCALL __p__environ(void);
DLL WCHAR ***CRTCALL __p__wenviron(void);
#endif
DLL int CRTCALL set_new_mode(int) __asm__("?_set_new_mode@@YAHH@Z");
#if !defined(_M_ARM64)
DLL int CRTCALL query_new_mode(void) __asm__("?_query_new_mode@@YAHXZ");
#define HAVE_NEW_QUERY 1
#endif
static int *argc_cell(void) { return &__argc; }
static char ***argv_cell(void) { return &__argv; }
static WCHAR ***wargv_cell(void) { return &__wargv; }
static char *raw_n(void) { return _acmdln; }
static WCHAR *raw_w(void) { return _wcmdln; }
static char *program_n(void) { return _pgmptr; }
static WCHAR *program_w(void) { return _wpgmptr; }
#if defined(HAVE_ENV_CELLS)
static char ***environ_cell(void) { return &_environ; }
static WCHAR ***wenviron_cell(void) { return &_wenviron; }
static char **initial_n(void) { return __initenv; }
static WCHAR **initial_w(void) { return __winitenv; }
#endif
#else
/* Definitions are linked from the unmodified retained MinGW UCRT wrappers. */
int CRTCALL __getmainargs(int *, char ***, char ***, int, STARTINFO *);
int CRTCALL __wgetmainargs(int *, WCHAR ***, WCHAR ***, int, STARTINFO *);
DLL int *CRTCALL __p___argc(void);
DLL char ***CRTCALL __p___argv(void);
DLL WCHAR ***CRTCALL __p___wargv(void);
DLL char **CRTCALL __p__acmdln(void);
DLL WCHAR **CRTCALL __p__wcmdln(void);
DLL char **CRTCALL __p__pgmptr(void);
DLL WCHAR **CRTCALL __p__wpgmptr(void);
DLL char ***CRTCALL __p__environ(void);
DLL WCHAR ***CRTCALL __p__wenviron(void);
DLL int CRTCALL _configure_narrow_argv(int);
DLL int CRTCALL _configure_wide_argv(int);
DLL int CRTCALL _initialize_narrow_environment(void);
DLL int CRTCALL _initialize_wide_environment(void);
DLL char **CRTCALL _get_initial_narrow_environment(void);
DLL WCHAR **CRTCALL _get_initial_wide_environment(void);
DLL char *CRTCALL _get_narrow_winmain_command_line(void);
DLL WCHAR *CRTCALL _get_wide_winmain_command_line(void);
DLL int CRTCALL _get_pgmptr(char **);
DLL int CRTCALL _get_wpgmptr(WCHAR **);
DLL int CRTCALL _set_new_mode(int);
DLL int CRTCALL _query_new_mode(void);
typedef void (CRTCALL *InvalidHandler)(const WCHAR *, const WCHAR *, const WCHAR *, unsigned int, UPTR);
DLL InvalidHandler CRTCALL _set_invalid_parameter_handler(InvalidHandler);
DLL int *CRTCALL _errno(void);
#define set_new_mode _set_new_mode
#define query_new_mode _query_new_mode
#define HAVE_NEW_QUERY 1
#define HAVE_ENV_CELLS 1
static int *argc_cell(void) { return __p___argc(); }
static char ***argv_cell(void) { return __p___argv(); }
static WCHAR ***wargv_cell(void) { return __p___wargv(); }
static char *raw_n(void) { return *__p__acmdln(); }
static WCHAR *raw_w(void) { return *__p__wcmdln(); }
static char *program_n(void) { return *__p__pgmptr(); }
static WCHAR *program_w(void) { return *__p__wpgmptr(); }
static char ***environ_cell(void) { return __p__environ(); }
static WCHAR ***wenviron_cell(void) { return __p__wenviron(); }
static char **initial_n(void) { return _get_initial_narrow_environment(); }
static WCHAR **initial_w(void) { return _get_initial_wide_environment(); }
#endif
static void check(int value, DWORD code) { if (!value) ExitProcess(code); }
static int same_n(const char *a, const char *b) {
    if (!a || !b) return a == b;
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a == (unsigned char)*b;
}
static int same_w(const WCHAR *a, const WCHAR *b) {
    if (!a || !b) return a == b;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static int ends_n(const char *text, const char *tail) {
    SIZE n = 0, m = 0;
    while (text[n]) ++n;
    while (tail[m]) ++m;
    return n >= m && same_n(text + n - m, tail);
}
#endif
