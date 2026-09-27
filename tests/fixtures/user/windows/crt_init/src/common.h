/* Custom-entry probes: x86 ILP32, x64/ARM64 LLP64; no SDK/CRT blobs. */
#ifndef RAX_CRT_INIT_COMMON_H
#define RAX_CRT_INIT_COMMON_H
typedef unsigned int DWORD;
typedef int BOOL;
typedef __SIZE_TYPE__ SIZE;
typedef __UINTPTR_TYPE__ UPTR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define CRTCALL __attribute__((cdecl))
#else
#define WINAPI
#define CRTCALL
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
#define SLOT(section) __declspec(allocate(section))
typedef void (CRTCALL *PVFV)(void);
typedef int (CRTCALL *PIFV)(void);
typedef void (CRTCALL *InitProc)(PVFV *, PVFV *);
DLL NORETURN void WINAPI ExitProcess(DWORD);
DLL void CRTCALL _initterm(PVFV *, PVFV *);
#if !defined(LEGACY_CRT) || defined(_M_ARM64)
DLL int CRTCALL _initterm_e(PIFV *, PIFV *);
#endif
DLL void *CRTCALL malloc(SIZE);
DLL void CRTCALL free(void *);
DLL SIZE CRTCALL strlen(const char *);
int CRTCALL abi_init(InitProc, PVFV *, PVFV *);
void CRTCALL abi_clobber(void);
DLL void *WINAPI VirtualAlloc(void *, SIZE, DWORD, DWORD);
DLL BOOL WINAPI VirtualFree(void *, SIZE, DWORD);
DLL BOOL WINAPI VirtualProtect(void *, SIZE, DWORD, DWORD *);
DLL void *WINAPI AddVectoredExceptionHandler(DWORD, int (WINAPI *)(void *));
DLL DWORD WINAPI RemoveVectoredExceptionHandler(void *);
static void check(int value, DWORD code) { if (!value) ExitProcess(code); }
#endif
