/* Freestanding PE32+ witness for a runtime-registered x64 function table.
   All offsets in the copied image are relative to dyn_template. */
typedef unsigned char U8;
typedef unsigned int U32;
typedef unsigned long long U64;
typedef __UINTPTR_TYPE__ UPTR;
typedef struct {
    U32 BeginAddress;
    U32 EndAddress;
    U32 UnwindData;
} RUNTIME_FUNCTION;
typedef struct _UNWIND_HISTORY_TABLE UNWIND_HISTORY_TABLE;
_Static_assert(sizeof(U32) == 4 && sizeof(U64) == 8 && sizeof(UPTR) == 8,
               "PE32+ widths");
_Static_assert(sizeof(RUNTIME_FUNCTION) == 12, "x64 RUNTIME_FUNCTION layout");

#define DLL __declspec(dllimport)
#define NORETURN __declspec(noreturn)
#define MEM_COMMIT_RESERVE 0x3000u
#define PAGE_READWRITE 0x04u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_BYTES 4096u

DLL NORETURN void ExitProcess(U32);
DLL void *VirtualAlloc(void *, UPTR, U32, U32);
DLL int VirtualProtect(void *, UPTR, U32, U32 *);
DLL void RaiseException(U32, U32, U32, const UPTR *);
DLL U8 RtlAddFunctionTable(const RUNTIME_FUNCTION *, U32, U64);
DLL U8 RtlDeleteFunctionTable(const RUNTIME_FUNCTION *);
DLL RUNTIME_FUNCTION *RtlLookupFunctionEntry(U64, U64 *, UNWIND_HISTORY_TABLE *);

extern const U8 dyn_template, dyn_code, dyn_code_end, dyn_unwind;
extern const U8 dyn_raise_ptr, dyn_marker_ptr, dyn_template_end;

static NORETURN void finish(U32 code) {
    ExitProcess(code);
    for (;;) {}
}

static UPTR offset_of(const U8 *symbol) {
    return (UPTR)symbol - (UPTR)&dyn_template;
}

static void put_u64_le(U8 *destination, U64 value) {
    for (U32 i = 0; i < 8; ++i)
        destination[i] = (U8)(value >> (i * 8));
}

typedef U32 (*DYNAMIC_FUNCTION)(volatile U32 *);

void entry(void) {
    volatile U32 marker = 0;
    U8 *page = VirtualAlloc((void *)0, PAGE_BYTES, MEM_COMMIT_RESERVE,
                            PAGE_READWRITE);
    if (!page)
        finish(10); /* allocation */

    UPTR blob_bytes = offset_of(&dyn_template_end);
    UPTR code_begin = offset_of(&dyn_code);
    UPTR code_end = offset_of(&dyn_code_end);
    UPTR unwind = offset_of(&dyn_unwind);
    UPTR raise_slot = offset_of(&dyn_raise_ptr);
    UPTR marker_slot = offset_of(&dyn_marker_ptr);
    if (blob_bytes > PAGE_BYTES || code_begin >= code_end ||
        code_end > unwind || unwind >= blob_bytes ||
        raise_slot + 8 > blob_bytes || marker_slot + 8 > blob_bytes)
        finish(11); /* source-label/layout invariant */

    const U8 *source = &dyn_template;
    for (UPTR i = 0; i < blob_bytes; ++i)
        page[i] = source[i];
    put_u64_le(page + raise_slot, (U64)(UPTR)&RaiseException);
    put_u64_le(page + marker_slot, (U64)(UPTR)&marker);

    RUNTIME_FUNCTION table = {(U32)code_begin, (U32)code_end, (U32)unwind};
    U64 control_pc = (U64)(UPTR)(page + code_begin + 5);
    const U64 image_base_sentinel = 0x51a7c00e51a7c00eULL;
    U32 old_protection = 0;
    if (!VirtualProtect(page, PAGE_BYTES, PAGE_EXECUTE_READ, &old_protection))
        finish(12); /* copied code was not executable */
    U64 image_base = image_base_sentinel;
    if (RtlLookupFunctionEntry(control_pc, &image_base,
                               (UNWIND_HISTORY_TABLE *)0))
        finish(17); /* unregistered JIT code unexpectedly has a table entry */
    if (image_base != image_base_sentinel)
        finish(18); /* RAX miss policy unexpectedly changed ImageBase */
    if (!RtlAddFunctionTable(&table, 1, (U64)(UPTR)page))
        finish(13); /* registration */
    image_base = image_base_sentinel;
    if (RtlLookupFunctionEntry(control_pc, &image_base,
                               (UNWIND_HISTORY_TABLE *)0) != &table)
        finish(19); /* hit did not return original guest table pointer */
    if (image_base != (U64)(UPTR)page)
        finish(20); /* hit did not report registered base address */

    U32 result = ((DYNAMIC_FUNCTION)(void *)(page + code_begin))(&marker);
    if (result != 0x42u)
        finish(14); /* RaiseException did not resume through dynamic code */
    if (marker != 1u)
        finish(15); /* missing, repeated, or wrong-establisher handler */
    if (!RtlDeleteFunctionTable(&table))
        finish(16); /* exact-pointer deregistration */
    image_base = image_base_sentinel;
    if (RtlLookupFunctionEntry(control_pc, &image_base,
                               (UNWIND_HISTORY_TABLE *)0))
        finish(21); /* deleted table remained discoverable */
    if (image_base != image_base_sentinel)
        finish(22); /* RAX miss policy unexpectedly changed ImageBase */
    finish(0);
}
