#include "common.h"
/* Public CONTEXT fields are independently retained in crt-startup's two
   winnt excerpts and checked by layout/public.c, not engine private structs. */
typedef struct ExceptionRecord {
    DWORD code, flags;
    struct ExceptionRecord *next;
    void *address;
    DWORD count;
    UPTR information[15];
} ExceptionRecord;
typedef struct ExceptionPointers { ExceptionRecord *record; void *context; } ExceptionPointers;
static Table table;
static VoidFn *slots;
static void *page;
static volatile DWORD upper_count, lower_count, repairs;
static DWORD expected_code;
static int CRTCALL lower(void) {
    check(upper_count == 1 && lower_count == 0 && repairs == 1, 151);
    lower_count = 1;
    return 31;
}
static int CRTCALL upper(void) {
    DWORD old;
    check(upper_count == 0 && lower_count == 0 && repairs == 0, 152);
    upper_count = 1;
    /* The next lazy old-buffer read must fault, not replay this callback. */
    check(VirtualProtect(page, 4096, expected_code == 0xc0000005u ? 1 : 0x104, &old), 153);
    return -31;
}
static void clobber_table_argument(void *raw) {
    char *context = (char *)raw;
#if defined(_M_IX86)
    UPTR stack = *(DWORD *)(context + 0xc4);
    *(DWORD *)(stack + 4) = 0;
#elif defined(_M_X64)
    *(UPTR *)(context + 0x80) = 0; /* CONTEXT.Rcx */
#elif defined(_M_ARM64)
    *(UPTR *)(context + 8) = 0; /* CONTEXT.X0 */
#else
#error Unsupported architecture
#endif
}
static int WINAPI repair(void *raw) {
    ExceptionPointers *p = (ExceptionPointers *)raw;
    DWORD old;
    check(p && p->record && p->context, 154);
    check(p->record->code == expected_code, 155);
    check(upper_count == 1 && lower_count == 0 && repairs == 0, 156);
    if (expected_code == 0xc0000005u) {
        check(p->record->count >= 2 && p->record->information[0] == 0, 157);
        check(p->record->information[1] == (UPTR)slots, 158);
    }
    check(VirtualProtect(page, 4096, 4, &old), 159);
    clobber_table_argument(p->context);
    repairs = 1;
    return -1;
}
void entry(void) {
    void *handler = AddVectoredExceptionHandler(1, repair);
    check(handler != 0, 160);
    for (DWORD pass = 0; pass < 2; ++pass) {
        upper_count = lower_count = repairs = 0;
        expected_code = pass == 0 ? 0xc0000005u : 0x80000001u;
        init(&table);
        reg(&table, lower);
        reg(&table, upper);
        check(table.first && table.last - table.first == 2, 161);
        slots = table.first;
        page = (void *)((UPTR)slots & ~(UPTR)4095);
        check((UPTR)slots + 2 * sizeof(VoidFn) <= (UPTR)page + 4096, 162);
        drain(&table);
        check(upper_count == 1 && lower_count == 1 && repairs == 1, 163);
    }
    check(RemoveVectoredExceptionHandler(handler) != 0, 164);
    init(&table);
    drain(&table);
    ExitProcess(0);
}
