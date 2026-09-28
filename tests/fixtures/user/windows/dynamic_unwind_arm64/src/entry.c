/* Freestanding ARM64 PE.  No CRT or SDK headers/import libraries are used.
   Guest-owned code, table and xdata occupy separately committed pages. */
typedef unsigned char U8;
typedef unsigned long U32;
typedef unsigned long long U64;
typedef unsigned long long SIZE;
_Static_assert(sizeof(void *) == 8 && sizeof(U32) == 4 && sizeof(U64) == 8,
               "Windows ARM64 LLP64 widths");

typedef struct { U32 begin, unwind; } RuntimeFunction;
typedef void (*Raise)(U32, U32, U32, const U64 *);
typedef U32 (*Jit)(Raise);

__declspec(dllimport) __declspec(noreturn) void ExitProcess(U32);
__declspec(dllimport) void RaiseException(U32, U32, U32, const U64 *);
__declspec(dllimport) U8 RtlAddFunctionTable(RuntimeFunction *, U32, U64);
__declspec(dllimport) U8 RtlDeleteFunctionTable(RuntimeFunction *);
__declspec(dllimport) void *VirtualAlloc(void *, SIZE, U32, U32);
__declspec(dllimport) int VirtualProtect(void *, SIZE, U32, U32 *);

extern const U8 jit_template_start[], jit_template_end[], jit_handler[];
extern const U8 jit_handler_data[], jit_marker_pointer[];

static U32 load32(const U8 *p) {
    return (U32)p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24);
}
static void store32(volatile U8 *p, U32 v) {
    for (U32 i = 0; i < 4; ++i) p[i] = (U8)(v >> (8 * i));
}
static void store64(volatile U8 *p, U64 v) {
    for (U32 i = 0; i < 8; ++i) p[i] = (U8)(v >> (8 * i));
}
static void copy(volatile U8 *dst, const U8 *src, U32 size) {
    for (U32 i = 0; i < size; ++i) dst[i] = src[i];
}
static __declspec(noreturn) void fail(U32 code) { ExitProcess(code); }

void entry(void) {
    const U64 template_size = (U64)jit_template_end - (U64)jit_template_start;
    const U64 handler_offset = (U64)jit_handler - (U64)jit_template_start;
    const U64 marker_offset = (U64)jit_marker_pointer - (U64)jit_template_start;
    if (template_size == 0 || template_size > 4096 || handler_offset >= template_size ||
        marker_offset + 8 > template_size || handler_offset > 0xffffffffULL)
        fail(10);

    /* The pinned assembler emits one 4-byte header, one 4-byte code word,
       one handler RVA and one 4-byte language-specific parameter.  Check
       this rather than silently copying a changed format. */
    const U8 *source_xdata = (const U8 *)((U64)jit_handler_data - 12);
    const U32 header = load32(source_xdata);
    if (((header >> 18) & 3) != 0 || !(header & (1UL << 20)) ||
        !(header & (1UL << 21)) || ((header >> 27) & 31) != 1 ||
        load32(jit_handler_data) != 0)
        fail(11);

    U8 *base = (U8 *)VirtualAlloc(0, 0x3000, 0x2000, 1); /* reserve/noaccess */
    if (!base) fail(12);
    U8 *code = (U8 *)VirtualAlloc(base, 0x1000, 0x1000, 4);
    U8 *table_page = (U8 *)VirtualAlloc(base + 0x1000, 0x1000, 0x1000, 4);
    U8 *xdata_page = (U8 *)VirtualAlloc(base + 0x2000, 0x1000, 0x1000, 4);
    if (code != base || table_page != base + 0x1000 || xdata_page != base + 0x2000)
        fail(13);

    copy(code, jit_template_start, (U32)template_size);
    RuntimeFunction *table = (RuntimeFunction *)table_page;
    volatile U32 *marker = (volatile U32 *)(table_page + 0x100);
    *marker = 0;
    store64(code + marker_offset, (U64)marker);
    copy(xdata_page, source_xdata, 16);
    store32(xdata_page + 8, (U32)handler_offset);
    table->begin = 0;
    table->unwind = 0x2000; /* full xdata RVA from code-page BaseAddress */

    U32 old_code = 0, old_xdata = 0;
    if (!VirtualProtect(code, 0x1000, 0x20, &old_code) ||
        !VirtualProtect(xdata_page, 0x1000, 2, &old_xdata))
        fail(14);
    if (!RtlAddFunctionTable(table, 1, (U64)code)) fail(15);
    /* This cast is the selected Windows ARM64 machine-ABI code-pointer probe. */
    U32 returned = ((Jit)(void *)code)(RaiseException);
    if (returned != 7 || *marker != 1) fail(16);
    if (!RtlDeleteFunctionTable(table)) fail(17);
    ExitProcess(0);
}
