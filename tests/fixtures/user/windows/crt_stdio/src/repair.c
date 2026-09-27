#include "common.h"
/* Public CONTEXT fields independently retained in crt-startup's two winnt
   excerpts and checked by layout/public.c. Partial I/O retry is an explicit
   emulator profile, not a claim about native CRT exception ordering. */
typedef struct ExceptionRecord { DWORD code, flags; struct ExceptionRecord *next;
    void *address; DWORD count; UPTR information[15]; } ExceptionRecord;
typedef struct ExceptionPointers { ExceptionRecord *record; void *context; } ExceptionPointers;
static unsigned char *allocation, *data;
static void *handle;
static DWORD phase;
static volatile DWORD repairs;
static unsigned char byte(SIZE at) { return (unsigned char)(at * 7 + 3); }
static void clobber(void *raw, DWORD formals) {
    char *context = raw;
#if defined(_M_IX86)
    UPTR stack = *(DWORD *)(context + 0xc4);
    for (DWORD i = 0; i < formals; ++i) *(DWORD *)(stack + 4 + 4 * i) = 0;
#elif defined(_M_X64)
    static const DWORD offset[4] = {0x80, 0x88, 0xb8, 0xc0};
    for (DWORD i = 0; i < formals; ++i) *(UPTR *)(context + offset[i]) = 0;
#elif defined(_M_ARM64)
    for (DWORD i = 0; i < formals; ++i) *(UPTR *)(context + 8 + 8 * i) = 0;
#else
#error Unsupported CONTEXT guest architecture
#endif
}
static int WINAPI repair(void *raw) {
    ExceptionPointers *p = raw; DWORD old;
    check(p && p->record && p->context && repairs == phase, 180);
    check(p->record->code == 0xc0000005u && p->record->count >= 2, 181);
    check(p->record->information[0] == (phase == 0 ? 1u : 0u) &&
          p->record->information[1] >= (UPTR)allocation + 4096 &&
          p->record->information[1] < (UPTR)allocation + 8192, 182);
    if (phase == 0) {
        for (SIZE i = 0; i < 256; ++i) check(data[i] == byte(i), 183);
    } else check(length(handle) == 256, 184);
    check(VirtualProtect(allocation + 4096, 4096, 4, &old), 185);
    /* Re-execution of consumed bytes would destroy this witness. */
    for (SIZE i = 0; i < 256; ++i) data[i] = 0xcc;
    clobber(p->context, phase == 0 ? 3 : 4);
    ++repairs; return -1;
}
void entry(void) {
    allocation = VirtualAlloc(0, 8192, 0x3000, 4);
    check(allocation != 0, 186); data = allocation + 4096 - 256;
    void *handler = AddVectoredExceptionHandler(1, repair); check(handler != 0, 187);
    handle = file(L"read.dat", 0x80000000u, 3);
    int fd = descriptor(handle, O_RDONLY | O_BINARY);
    DWORD old; check(VirtualProtect(allocation + 4096, 4096, 2, &old), 188);
    check(_read(fd, data, 768) == 768 && repairs == 1, 189);
    for (SIZE i = 0; i < 256; ++i) check(data[i] == 0xcc, 190);
    for (SIZE i = 256; i < 768; ++i) check(data[i] == byte(i), 191);
    check(_close(fd) == 0, 192); closed(handle);
    for (SIZE i = 0; i < 768; ++i) data[i] = byte(i);
    handle = file(L"repair.dat", 0xc0000000u, 2);
    FILE *output = stream(descriptor(handle, O_BINARY | O_RDWR), "wb");
    check(setvbuf(output, 0, IONBF, 0) == 0, 193);
    phase = 1; check(VirtualProtect(allocation + 4096, 4096, 1, &old), 194);
    check(fwrite(data, 1, 768, output) == 768 && repairs == 2, 195);
    check(length(handle) == 768 && fclose(output) == 0, 196); closed(handle);
    check(RemoveVectoredExceptionHandler(handler) != 0, 197);
    check(VirtualFree(allocation, 0, 0x8000), 198);
    ExitProcess(0);
}
