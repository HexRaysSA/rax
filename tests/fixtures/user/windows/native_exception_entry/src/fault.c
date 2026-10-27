/* SDK/CRT-free hardware fault, native VEH, and context continuation. */
typedef unsigned int U32;
typedef __UINTPTR_TYPE__ UPTR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#define PC_OFFSET 0xb8
#elif defined(_M_X64)
#define WINAPI
#define PC_OFFSET 0xf8
#else
#define WINAPI
#define PC_OFFSET 0x108
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)

typedef struct ExceptionRecord {
    U32 code, flags;
    struct ExceptionRecord *next;
    void *address;
} ExceptionRecord;
typedef struct ExceptionPointers {
    ExceptionRecord *record;
    void *context;
} ExceptionPointers;
typedef int(WINAPI *Handler)(void *);

DLL NORETURN void WINAPI ExitProcess(U32);
DLL void *WINAPI AddVectoredExceptionHandler(U32, Handler);
DLL U32 WINAPI RemoveVectoredExceptionHandler(void *);

static volatile U32 seen;
static void *volatile resume;

static int WINAPI handler(void *raw) {
    ExceptionPointers *p = (ExceptionPointers *)raw;
    if (!p || !p->record || !p->context)
        ExitProcess(81);
    if (p->record->code != 0xc0000005 || (p->record->flags & 1) != 0)
        ExitProcess(82);
    UPTR *pc = (UPTR *)((unsigned char *)p->context + PC_OFFSET);
    if ((void *)*pc != p->record->address || seen != 0)
        ExitProcess(83);
    seen = 1;
    *pc = (UPTR)resume;
    return -1;
}

void entry(void) {
    void *registration = AddVectoredExceptionHandler(1, handler);
    if (!registration)
        ExitProcess(84);
    /* An address-taken label keeps the interrupted frame's ABI and stack. */
    resume = &&continued;
    *(volatile U32 *)0x1000 = 0x12345678;
continued:
    if (seen != 1)
        ExitProcess(85);
    if (!RemoveVectoredExceptionHandler(registration))
        ExitProcess(86);
    ExitProcess(0);
}
