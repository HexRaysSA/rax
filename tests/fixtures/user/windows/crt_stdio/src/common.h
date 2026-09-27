/* Custom-entry byte I/O probes: x86 ILP32; x64/ARM64 LLP64.
   Legacy FILE fields/stride are the retained MinGW declaration, not UCRT
   private layout. All assertions otherwise use public functions. */
#ifndef RAX_CRT_STDIO_COMMON_H
#define RAX_CRT_STDIO_COMMON_H
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
typedef struct File { char *_ptr; int _cnt; char *_base; int _flag, _file,
    _charbuf, _bufsiz; char *_tmpfname; } FILE;
_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "public integer widths");
_Static_assert(sizeof(FILE) == (sizeof(void *) == 4 ? 32 : 48), "retained legacy FILE stride");
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL void *WINAPI CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, void *);
DLL BOOL WINAPI CloseHandle(void *);
DLL BOOL WINAPI ReadFile(void *, void *, DWORD, DWORD *, void *);
DLL BOOL WINAPI WriteFile(void *, const void *, DWORD, DWORD *, void *);
DLL BOOL WINAPI GetFileSizeEx(void *, long long *);
DLL DWORD WINAPI GetFileType(void *);
DLL void *WINAPI GetStdHandle(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL void WINAPI SetLastError(DWORD);
DLL void *WINAPI VirtualAlloc(void *, SIZE, DWORD, DWORD);
DLL BOOL WINAPI VirtualFree(void *, SIZE, DWORD);
DLL BOOL WINAPI VirtualProtect(void *, SIZE, DWORD, DWORD *);
DLL void *WINAPI AddVectoredExceptionHandler(DWORD, int (WINAPI *)(void *));
DLL DWORD WINAPI RemoveVectoredExceptionHandler(void *);
DLL SIZE CRTCALL fread(void *, SIZE, SIZE, FILE *);
DLL SIZE CRTCALL fwrite(const void *, SIZE, SIZE, FILE *);
DLL int CRTCALL fclose(FILE *);
DLL int CRTCALL fflush(FILE *);
DLL int CRTCALL setvbuf(FILE *, char *, int, SIZE);
DLL int CRTCALL feof(FILE *);
DLL int CRTCALL ferror(FILE *);
DLL void CRTCALL clearerr(FILE *);
DLL int CRTCALL _fileno(FILE *);
DLL int CRTCALL _open_osfhandle(IPTR, int);
DLL IPTR CRTCALL _get_osfhandle(int);
DLL FILE *CRTCALL _wfdopen(int, const WCHAR *);
#if !defined(APISET)
DLL FILE *CRTCALL _fdopen(int, const char *);
#endif
DLL int CRTCALL _close(int);
DLL int CRTCALL _read(int, void *, unsigned int);
DLL int CRTCALL _write(int, const void *, unsigned int);
DLL int CRTCALL _setmode(int, int);
DLL int *CRTCALL _errno(void);
#if defined(LEGACY)
DLL extern int _fmode, _commode;
#if defined(_M_IX86)
DLL FILE *CRTCALL __p__iob(void);
static FILE *standard(unsigned int index) { return __p__iob() + index; }
#else
DLL FILE *CRTCALL __iob_func(void);
static FILE *standard(unsigned int index) { return __iob_func() + index; }
#endif
static int *fmode_cell(void) { return &_fmode; }
static int *commode_cell(void) { return &_commode; }
#else
DLL FILE *CRTCALL __acrt_iob_func(unsigned int);
DLL int *CRTCALL __p__fmode(void);
DLL int *CRTCALL __p__commode(void);
static FILE *standard(unsigned int index) { return __acrt_iob_func(index); }
static int *fmode_cell(void) { return __p__fmode(); }
static int *commode_cell(void) { return __p__commode(); }
#endif
enum { O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_TEXT = 0x4000, O_BINARY = 0x8000,
    IOFBF = 0, IOLBF = 0x40, IONBF = 4 };
static void check(int condition, DWORD code) { if (!condition) ExitProcess(code); }
static int equal(const void *left, const void *right, SIZE bytes) {
    const unsigned char *a = left, *b = right;
    for (SIZE i = 0; i < bytes; ++i) if (a[i] != b[i]) return 0;
    return 1;
}
static void *file(const WCHAR *name, DWORD access, DWORD disposition) {
    void *handle = CreateFileW(name, access, 3, 0, disposition, 0x80, 0);
    check(handle != (void *)(IPTR)-1, 101);
    return handle;
}
static int descriptor(void *handle, int flags) {
    int fd = _open_osfhandle((IPTR)handle, flags);
    check(fd >= 3 && _get_osfhandle(fd) == (IPTR)handle, 102);
    return fd;
}
static FILE *stream(int fd, const char *mode) {
#if defined(APISET)
    WCHAR wide[8]; SIZE i;
    for (i = 0; mode[i] && i < 7; ++i) wide[i] = (WCHAR)(unsigned char)mode[i];
    wide[i] = 0;
    FILE *result = _wfdopen(fd, wide);
#else
    FILE *result = _fdopen(fd, mode);
#endif
    check(result != 0 && _fileno(result) == fd, 103);
    return result;
}
static void closed(void *handle) {
    SetLastError(0);
    check(GetFileType(handle) == 0 && GetLastError() == 6, 104);
}
static long long length(void *handle) {
    long long bytes = -1;
    check(GetFileSizeEx(handle, &bytes), 105);
    return bytes;
}
#endif
