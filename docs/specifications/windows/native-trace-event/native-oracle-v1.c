/* Independent NtTraceEvent argument validation for one task-owned provider.
 * No tracing controller, provider registration, hook, or exception handler.
 * All supplied event storage belongs to this process. The native bootstrap
 * records kernel, DLL, source and executable identities separately.
 */
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned long U32;
typedef unsigned long long U64;
typedef long I32;
typedef void *Handle;
#ifdef _WIN64
typedef U64 Size;
#else
typedef U32 Size;
#endif
#define API __declspec(dllimport)
#define CALL __stdcall
API Handle CALL GetStdHandle(U32);
API I32 CALL WriteFile(Handle, const void *, U32, U32 *, void *);
API Handle CALL GetModuleHandleW(const U16 *);
API void *CALL GetProcAddress(Handle, const char *);
API void *CALL VirtualAlloc(void *, Size, U32, U32);
API I32 CALL VirtualProtect(void *, Size, U32, U32 *);
API I32 CALL VirtualFree(void *, Size, U32);
API void CALL ExitProcess(U32);
typedef I32(CALL *Trace)(Handle, U32, U32, void *);

/* c5c4e612-d6de-4cac-a4c1-19cd76937216, private to this oracle. */
static const U8 provider[16] = {
    0x12,0xe6,0xc4,0xc5,0xde,0xd6,0xac,0x4c,
    0xa4,0xc1,0x19,0xcd,0x76,0x93,0x72,0x16
};
static U8 fields[131072];
static U8 payload[16];
static U32 text(char *out, U32 at, const char *value) {
    while (*value) out[at++] = *value++;
    return at;
}
static U32 hex(char *out, U32 at, U64 value, U32 digits) {
    static const char chars[] = "0123456789abcdef";
    for (U32 i = digits; i; --i) out[at++] = chars[(value >> ((i - 1) * 4)) & 15];
    return at;
}
static I32 emit(const char *bytes, U32 count) {
    while (count) {
        U32 wrote = 0;
        if (!WriteFile(GetStdHandle((U32)-11), bytes, count, &wrote, 0)
            || !wrote || wrote > count) return 0;
        count -= wrote;
        bytes += wrote;
    }
    return 1;
}
static void put64(U8 *out, U64 value) {
    for (U32 i = 0; i < 8; ++i) out[i] = (U8)(value >> (8 * i));
}
static I32 row(Trace trace, const char *group, U32 index, Handle handle,
               U32 flags, U32 length, void *buffer) {
    /* Read-only call: a byte checksum detects accidental native copyback. */
    U32 before = 0, after = 0;
    for (U32 i = 0; i < sizeof fields; ++i) before = before * 33 + fields[i];
    I32 status = trace(handle, flags, length, buffer);
    for (U32 i = 0; i < sizeof fields; ++i) after = after * 33 + fields[i];
    char line[384];
    U32 at = text(line, 0, "group=");
    at = text(line, at, group);
    at = text(line, at, " index="); at = hex(line, at, index, 4);
    at = text(line, at, " flags="); at = hex(line, at, flags, 8);
    at = text(line, at, " length="); at = hex(line, at, length, 8);
    at = text(line, at, " status="); at = hex(line, at, (U32)status, 8);
    at = text(line, at, " unchanged="); at = hex(line, at, before == after, 1);
    line[at++] = '\n';
    return emit(line, at) && before == after;
}
void entry(void) {
    Trace trace = (Trace)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTraceEvent");
    if (!trace) ExitProcess(2);
    U8 *pages = (U8 *)VirtualAlloc(0, 12288, 0x3000, 4);
    if (!pages) ExitProcess(3);
    for (U32 i = 0; i < 16; ++i) pages[i] = provider[i];
    U32 previous = 0;
    if (!VirtualProtect(pages + 4096, 4096, 1, &previous)) ExitProcess(4);
    /* The third page remains readable for a provider spanning its predecessor. */
    static const U32 lengths[] = {0,1,16,39,40,79,80,81,83,84,87,88,
                                  95,96,103,104,111,112,119,120,121,128,
                                  512,65535,65536,131072};
    for (U32 i = 0; i < sizeof lengths / sizeof lengths[0]; ++i)
        if (!row(trace, "zero", i, pages, 0x700, lengths[i], fields)) ExitProcess(5);
    /* Shape observed at the guest frontier, with the sole pointer relocated
     * into this process's owned payload. Its published length remains zero. */
    fields[40] = 7; fields[43] = 0x11; fields[44] = 3;
    fields[49] = 2; fields[55] = 0x20; fields[84] = 1;
    put64(fields + 88, (U64)(Size)payload);
    for (U32 i = 0; i < sizeof lengths / sizeof lengths[0]; ++i)
        if (!row(trace, "shape", i, pages, 0x700, lengths[i], fields)) ExitProcess(6);
    Handle providers[] = {0, (Handle)(Size)1, pages, pages + 1,
                           pages + 4080, pages + 4081, pages + 4096,
                           (Handle)(Size)-1};
    for (U32 i = 0; i < sizeof providers / sizeof providers[0]; ++i)
        if (!row(trace, "provider", i, providers[i], 0x700, 120, fields)) ExitProcess(7);
    void *buffers[] = {0, (void *)(Size)1, fields, fields + 1,
                       pages + 3976, pages + 3977, pages + 4096,
                       (void *)(Size)-1};
    for (U32 i = 0; i < sizeof buffers / sizeof buffers[0]; ++i)
        if (!row(trace, "fields", i, pages, 0x700, 120, buffers[i])) ExitProcess(8);
    /* Unknown low/high flag bits and adjacent mode tags. None register or
     * enable a provider; the trace handle is always the private owned GUID. */
    static const U32 flags[] = {0,1,0x600,0x700,0x701,0x702,0x710,0x7ff,
                                0x800,0x900,0x1700,0x40000700,0x80000700,
                                0xc0000700,0xffffffff};
    for (U32 i = 0; i < sizeof flags / sizeof flags[0]; ++i)
        if (!row(trace, "flags", i, pages, flags[i], 120, fields)) ExitProcess(9);
    if (!VirtualFree(pages, 0, 0x8000)) ExitProcess(10);
    ExitProcess(0);
}
