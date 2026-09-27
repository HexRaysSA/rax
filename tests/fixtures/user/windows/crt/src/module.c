#include "common.h"
typedef int *(CRTCALL *ErrorProc)(void);
typedef DWORD *(CRTCALL *DosProc)(void);
typedef void *(CRTCALL *AllocProc)(SIZE);
typedef void (CRTCALL *FreeProc)(void *);
extern int CRTCALL abi_copy(CopyProc, void *, const void *, SIZE);
static void *lookup(HANDLE module, const char *name) {
    void *function = GetProcAddress(module, name);
    check(function != 0, 180); return function;
}
void entry(void) {
    HANDLE legacy = LoadLibraryA("msvcrt.dll"), universal = LoadLibraryA("ucrtbase.dll");
    HANDLE heap = LoadLibraryA("api-ms-win-crt-heap-l1-1-0.dll");
    HANDLE string = LoadLibraryA("api-ms-win-crt-string-l1-1-0.dll");
    HANDLE runtime = LoadLibraryA("api-ms-win-crt-runtime-l1-1-0.dll");
    ErrorProc legacy_error, universal_error;
    DosProc legacy_dos, universal_dos;
    AllocProc legacy_alloc;
    FreeProc legacy_free;
    CopyProc copy;
    char destination[17];
    const char source[17] = "callee-cleanup?";
    int *a, *b;
    DWORD *c, *d;
    SIZE i;
    check(legacy && universal && heap && string && runtime, 181);
    check(GetModuleHandleA("msvcrt.dll") == legacy && GetModuleHandleA("ucrtbase.dll") == universal, 182);
    /* API-set contracts route to the UCRT host; this is explicit loader-profile evidence. */
    check(heap == universal && string == universal && runtime == universal, 183);
    legacy_error = (ErrorProc)lookup(legacy, "_errno");
    universal_error = (ErrorProc)lookup(universal, "_errno");
    legacy_dos = (DosProc)lookup(legacy, "__doserrno");
    universal_dos = (DosProc)lookup(universal, "__doserrno");
    a = legacy_error(); b = universal_error(); c = legacy_dos(); d = universal_dos();
    check(a && b && c && d && a != b && c != d, 184);
    *a = 13; *b = 17; *c = 0x89abcdef; *d = 0xfedcba98;
    check(*legacy_error() == 13 && *universal_error() == 17, 185);
    check(*legacy_dos() == 0x89abcdef && *universal_dos() == 0xfedcba98, 186);
    legacy_alloc = (AllocProc)lookup(legacy, "malloc");
    legacy_free = (FreeProc)lookup(legacy, "free");
    check(legacy_alloc(FULL_SIZE) == 0 && *a == ENOMEM && *b == 17 && *d == 0xfedcba98, 187);
    {
        void *p = legacy_alloc(29); check(p != 0, 188); legacy_free(p);
        check(*a == ENOMEM && *b == 17, 189);
    }
#ifdef LEGACY_CRT
    copy = (CopyProc)lookup(legacy, "memcpy");
    check(_errno() == a && __doserrno() == c, 190);
#else
#ifdef APISET_CRT
    copy = (CopyProc)lookup(GetModuleHandleA("vcruntime140.dll"), "memcpy");
#else
    copy = (CopyProc)lookup(universal, "memcpy");
#endif
    check(_errno() == b && __doserrno() == d, 191);
#endif
    check(copy == memcpy, 192);
    for (i = 0; i < 64; ++i) {
        check(abi_copy(copy, destination, source, sizeof(source)) == 1, 193);
        SIZE j;
        for (j = 0; j < sizeof(source); ++j) check(destination[j] == source[j], 194);
    }
    check(GetProcAddress(string, "strcpy") == lookup(universal, "strcpy"), 195);
    check(GetProcAddress(runtime, "_errno") == (void *)universal_error, 196);
    /* No legacy augmentation: missing facade exports, not a native export oracle. */
    check(GetProcAddress(legacy, "_get_errno") == 0 && GetLastError() == 127, 197);
    check(GetProcAddress(legacy, "_set_invalid_parameter_handler") == 0 && GetLastError() == 127, 198);
    check(FreeLibrary(heap) && FreeLibrary(string) && FreeLibrary(runtime), 199);
    check(FreeLibrary(legacy) && FreeLibrary(universal), 200);
    ExitProcess(0);
}
