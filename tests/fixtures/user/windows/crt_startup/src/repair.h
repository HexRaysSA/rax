/* ExceptionRecord/Pointers reused from crt_init/src/repair.c. CONTEXT byte
   offsets are public header fields independently checked by layout/public.c,
   SHA256 8f58c4ebe3077b4449567fe8fa9bba72fad13875c08483f1aaea9c0808f3b47e.
   This is an HLE captured-input retry profile, not native CRT fault ordering. */
#ifndef RAX_CRT_STARTUP_REPAIR_H
#define RAX_CRT_STARTUP_REPAIR_H
typedef struct ExceptionRecord {
    DWORD code, flags;
    struct ExceptionRecord *next;
    void *address;
    DWORD count;
    UPTR information[15];
} ExceptionRecord;
typedef struct ExceptionPointers { ExceptionRecord *record; void *context; } ExceptionPointers;
static void *repair_page;
static volatile DWORD repairs;
static DWORD repair_formals;
static UPTR repair_value;
static void clobber_formals(void *raw) {
    char *context = (char *)raw;
#if defined(_M_IX86)
    DWORD stack = *(DWORD *)(context + 0xc4); /* CONTEXT.Esp */
    for (DWORD i = 0; i < repair_formals; ++i)
        *(DWORD *)((UPTR)stack + 4 + 4 * i) = (DWORD)repair_value;
#elif defined(_M_X64)
    static const DWORD offset[4] = {0x80, 0x88, 0xb8, 0xc0}; /* Rcx,Rdx,R8,R9 */
    for (DWORD i = 0; i < repair_formals && i < 4; ++i)
        *(UPTR *)(context + offset[i]) = repair_value;
    if (repair_formals == 5) {
        UPTR stack = *(UPTR *)(context + 0x98); /* CONTEXT.Rsp */
        *(UPTR *)(stack + 0x28) = repair_value; /* Return PC + shadow space. */
    }
#elif defined(_M_ARM64)
    for (DWORD i = 0; i < repair_formals; ++i)
        *(UPTR *)(context + 8 + 8 * i) = repair_value; /* CONTEXT.X0+i */
#else
#error Unsupported CONTEXT guest architecture
#endif
}
static int WINAPI repair(void *raw) {
    ExceptionPointers *p = (ExceptionPointers *)raw;
    DWORD old;
    check(p && p->record && p->context && repairs == 0, 150);
    check(p->record->code == 0xc0000005u && p->record->count >= 2, 151);
    check(p->record->information[0] == 1 &&
          p->record->information[1] >= (UPTR)repair_page &&
          p->record->information[1] < (UPTR)repair_page + 4096, 152);
    check(VirtualProtect(repair_page, 4096, 4, &old) && old == 2, 153);
    clobber_formals(p->context);
    repairs = 1;
    return -1; /* CONTINUE_EXECUTION at the unchanged HLE frontier. */
}
static void *protect_and_register(void *page, DWORD formals, UPTR value) {
    DWORD old;
    repair_page = page;
    repair_formals = formals;
    repair_value = value;
    repairs = 0;
    void *handler = AddVectoredExceptionHandler(1, repair);
    check(handler != 0, 154);
    check(VirtualProtect(page, 4096, 2, &old), 155);
    return handler;
}
static void finish_repair(void *handler) {
    check(repairs == 1 && RemoveVectoredExceptionHandler(handler) != 0, 156);
}
#endif
