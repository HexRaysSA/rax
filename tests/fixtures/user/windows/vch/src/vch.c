/* SDK/CRT-free public vectored-continue-handler import probe. */
typedef unsigned int U32;
typedef __UINTPTR_TYPE__ UPTR;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI
#endif
#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)

typedef struct ExceptionRecord {
    U32 code, flags;
    struct ExceptionRecord *next;
    void *address;
    U32 count;
    UPTR information[15];
} ExceptionRecord;
typedef struct ExceptionPointers {
    ExceptionRecord *record;
    void *context;
} ExceptionPointers;
typedef int (WINAPI *Handler)(void *);

DLL NORETURN void WINAPI ExitProcess(U32);
DLL void WINAPI RaiseException(U32, U32, U32, const UPTR *);
DLL void *WINAPI AddVectoredExceptionHandler(U32, Handler);
DLL U32 WINAPI RemoveVectoredExceptionHandler(void *);
DLL void *WINAPI AddVectoredContinueHandler(U32, Handler);
DLL U32 WINAPI RemoveVectoredContinueHandler(void *);

enum { CODE = 0xe0421201u };
static volatile U32 sequence[8];
static volatile U32 length;
static void *volatile active_pointers;

static void check(int condition, U32 failure) {
    if (!condition) ExitProcess(failure);
}

static void mark(void *raw, U32 tag) {
    ExceptionPointers *p = (ExceptionPointers *)raw;
    check(p != 0 && p->record != 0 && p->context != 0, 41);
    check(p->record->code == CODE && p->record->flags == 0, 42);
    check(p->record->count == 0, 43);
    check(length < 8, 44);
    if (tag == 1) {
        active_pointers = raw;
    } else {
        check(raw == active_pointers, 45);
    }
    sequence[length++] = tag;
}

static int WINAPI veh(void *raw) {
    mark(raw, 1);
    return -1; /* EXCEPTION_CONTINUE_EXECUTION */
}

static int WINAPI head(void *raw) {
    mark(raw, 2);
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

static int WINAPI tail(void *raw) {
    mark(raw, 3);
    return -1; /* EXCEPTION_CONTINUE_EXECUTION */
}

static void raise_and_check(U32 count, U32 first, U32 second, U32 third, U32 failure) {
    length = 0;
    active_pointers = 0;
    RaiseException(CODE, 0, 0, 0);
    check(length == count, failure);
    if (count > 0) check(sequence[0] == first, failure + 1);
    if (count > 1) check(sequence[1] == second, failure + 2);
    if (count > 2) check(sequence[2] == third, failure + 3);
}

void entry(void) {
    void *exception = AddVectoredExceptionHandler(1, veh);
    void *last = AddVectoredContinueHandler(0, tail);
    void *first = AddVectoredContinueHandler(1, head);
    check(exception != 0 && last != 0 && first != 0, 51);
    check(exception != last && exception != first && last != first, 52);

    /* Separate registration families must not remove one another. */
    check(RemoveVectoredExceptionHandler(last) == 0, 53);
    check(RemoveVectoredContinueHandler(exception) == 0, 54);
    raise_and_check(3, 1, 2, 3, 60);

    check(RemoveVectoredContinueHandler(first) != 0, 64);
    check(RemoveVectoredContinueHandler(first) == 0, 65);
    raise_and_check(2, 1, 3, 0, 66);

    check(RemoveVectoredContinueHandler(last) != 0, 69);
    check(RemoveVectoredContinueHandler(last) == 0, 70);
    raise_and_check(1, 1, 0, 0, 71);

    check(RemoveVectoredExceptionHandler(exception) != 0, 73);
    check(RemoveVectoredExceptionHandler(exception) == 0, 74);
    ExitProcess(0);
}
