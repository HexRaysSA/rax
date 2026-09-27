#include "common.h"
typedef struct ExceptionRecord {
    DWORD code, flags;
    struct ExceptionRecord *next;
    void *address;
    DWORD count;
    UPTR information[15];
} ExceptionRecord;
typedef struct ExceptionPointers { ExceptionRecord *record; void *context; } ExceptionPointers;
static volatile DWORD first_count, second_count, handler_count;
static DWORD expected_code;
static char *page;
static void CRTCALL first(void) {
    check(first_count == 0 && second_count == 0, 151);
    first_count = 1;
    abi_clobber();
}
static void CRTCALL second(void) {
    check(first_count == 1 && second_count == 0 && handler_count == 1, 152);
    second_count = 1;
}
static int WINAPI repair(void *raw) {
    ExceptionPointers *p = (ExceptionPointers *)raw;
    DWORD old;
    check(p != 0 && p->record != 0, 153);
    check(p->record->code == expected_code, 154);
    check(first_count == 1 && second_count == 0 && handler_count == 0, 155);
    if (expected_code == 0xc0000005u) {
        check(p->record->count >= 2 && p->record->information[0] == 0, 156);
        check(p->record->information[1] == (UPTR)page, 157);
    }
    handler_count = 1;
    check(VirtualProtect(page, 4096, 4, &old), 158);
    return -1; /* EXCEPTION_CONTINUE_EXECUTION: retry the same pending slot. */
}
int main(void) {
    char *block = (char *)VirtualAlloc(0, 8192, 0x3000, 4);
    PVFV *table;
    void *handler;
    DWORD old;
    unsigned int pass;
    check(block != 0, 159);
    page = block + 4096;
    table = (PVFV *)(page - sizeof(PVFV));
    table[0] = first; table[1] = second;
    handler = AddVectoredExceptionHandler(1, repair);
    check(handler != 0, 160);
    for (pass = 0; pass < 2; ++pass) {
        first_count = second_count = handler_count = 0;
        expected_code = pass == 0 ? 0xc0000005u : 0x80000001u;
        check(VirtualProtect(page, 4096, pass == 0 ? 1 : 0x104, &old), 161);
        _initterm(table, table + 2);
        check(first_count == 1 && second_count == 1 && handler_count == 1, 162);
        check(table[1] == second, 163);
    }
    check(RemoveVectoredExceptionHandler(handler) != 0, 164);
    check(VirtualFree(block, 0, 0x8000), 165);
    return 0;
}
void entry(void) { ExitProcess((DWORD)main()); }
