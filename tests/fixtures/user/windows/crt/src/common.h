/* Custom-entry, SDK/header/blob-free CRT probes; Windows LLP64 types. */
#ifndef RAX_CRT_COMMON_H
#define RAX_CRT_COMMON_H
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef __UINTPTR_TYPE__ UPTR;
typedef __SIZE_TYPE__ SIZE;
typedef void *HANDLE;
typedef int BOOL;
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define CRTCALL __attribute__((cdecl))
#else
#define WINAPI
#define CRTCALL
#endif
#define INFINITE 0xffffffffu
#define EINVAL 22
#define ENOMEM 12
#define FULL_SIZE ((SIZE)-1)
typedef void (CRTCALL *InvalidHandler)(const WORD *, const WORD *, const WORD *, unsigned int, UPTR);
typedef void *(CRTCALL *CopyProc)(void *, const void *, SIZE);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL void WINAPI SetLastError(DWORD);
DLL DWORD WINAPI GetCurrentThreadId(void);
DLL HANDLE WINAPI CreateThread(void *, SIZE, DWORD (WINAPI *)(void *), void *, DWORD, DWORD *);
DLL HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const WORD *);
DLL BOOL WINAPI SetEvent(HANDLE);
DLL DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLL BOOL WINAPI CloseHandle(HANDLE);
DLL void *WINAPI ConvertThreadToFiber(void *);
DLL BOOL WINAPI ConvertFiberToThread(void);
DLL void *WINAPI CreateFiber(SIZE, void (WINAPI *)(void *), void *);
DLL void WINAPI SwitchToFiber(void *);
DLL void WINAPI DeleteFiber(void *);
DLL HANDLE WINAPI LoadLibraryA(const char *);
DLL HANDLE WINAPI GetModuleHandleA(const char *);
DLL void *WINAPI GetProcAddress(HANDLE, const char *);
DLL BOOL WINAPI FreeLibrary(HANDLE);
DLL void *WINAPI AddVectoredExceptionHandler(DWORD, int (WINAPI *)(void *));
DLL DWORD WINAPI FlsAlloc(void (WINAPI *)(void *));
DLL BOOL WINAPI FlsSetValue(DWORD, void *);
DLL void *CRTCALL malloc(SIZE);
DLL void *CRTCALL calloc(SIZE, SIZE);
DLL void *CRTCALL realloc(void *, SIZE);
DLL void CRTCALL free(void *);
DLL SIZE CRTCALL _msize(void *);
DLL void *CRTCALL _expand(void *, SIZE);
DLL char *CRTCALL _strdup(const char *);
DLL WORD *CRTCALL _wcsdup(const WORD *);
DLL UPTR CRTCALL _get_heap_handle(void);
DLL void *CRTCALL memcpy(void *, const void *, SIZE);
DLL void *CRTCALL memmove(void *, const void *, SIZE);
DLL void *CRTCALL memset(void *, int, SIZE);
DLL int CRTCALL memcmp(const void *, const void *, SIZE);
DLL void *CRTCALL memchr(const void *, int, SIZE);
DLL SIZE CRTCALL strlen(const char *);
DLL SIZE CRTCALL strnlen(const char *, SIZE);
DLL int CRTCALL strcmp(const char *, const char *);
DLL int CRTCALL strncmp(const char *, const char *, SIZE);
DLL char *CRTCALL strcpy(char *, const char *);
DLL char *CRTCALL strncpy(char *, const char *, SIZE);
DLL char *CRTCALL strcat(char *, const char *);
DLL char *CRTCALL strncat(char *, const char *, SIZE);
DLL char *CRTCALL strchr(const char *, int);
DLL char *CRTCALL strrchr(const char *, int);
DLL char *CRTCALL strstr(const char *, const char *);
DLL SIZE CRTCALL wcslen(const WORD *);
DLL SIZE CRTCALL wcsnlen(const WORD *, SIZE);
DLL int CRTCALL wcscmp(const WORD *, const WORD *);
DLL int CRTCALL wcsncmp(const WORD *, const WORD *, SIZE);
DLL WORD *CRTCALL wcscpy(WORD *, const WORD *);
DLL WORD *CRTCALL wcsncpy(WORD *, const WORD *, SIZE);
DLL WORD *CRTCALL wcscat(WORD *, const WORD *);
DLL WORD *CRTCALL wcsncat(WORD *, const WORD *, SIZE);
DLL WORD *CRTCALL wcschr(const WORD *, WORD);
DLL WORD *CRTCALL wcsrchr(const WORD *, WORD);
DLL WORD *CRTCALL wcsstr(const WORD *, const WORD *);
DLL int *CRTCALL _errno(void);
DLL DWORD *CRTCALL __doserrno(void);
DLL int CRTCALL _get_errno(int *);
DLL int CRTCALL _set_errno(int);
DLL int CRTCALL _get_doserrno(DWORD *);
DLL int CRTCALL _set_doserrno(DWORD);
DLL InvalidHandler CRTCALL _set_invalid_parameter_handler(InvalidHandler);
DLL InvalidHandler CRTCALL _get_invalid_parameter_handler(void);
DLL InvalidHandler CRTCALL _set_thread_local_invalid_parameter_handler(InvalidHandler);
DLL InvalidHandler CRTCALL _get_thread_local_invalid_parameter_handler(void);
DLL void CRTCALL _invalid_parameter(const WORD *, const WORD *, const WORD *, unsigned int, UPTR);
DLL void CRTCALL _invalid_parameter_noinfo(void);
DLL NORETURN void CRTCALL _invalid_parameter_noinfo_noreturn(void);
static void check(int value, DWORD code) { if (!value) ExitProcess(code); }
static HANDLE event(void) {
    HANDLE value = CreateEventW(0, 1, 0, 0);
    check(value != 0, 240); return value;
}
static void wait(HANDLE value) { check(WaitForSingleObject(value, INFINITE) == 0, 241); }
static void signal(HANDLE value) { check(SetEvent(value), 242); }
static void close(HANDLE value) { check(CloseHandle(value), 243); }
#endif
