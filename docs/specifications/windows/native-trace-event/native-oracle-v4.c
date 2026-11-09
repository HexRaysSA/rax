/* Independent NtTraceEvent argument validation for one task-owned provider.
 * No tracing controller, hook, or exception handler. A private provider is
 * registered temporarily, measured, then explicitly unregistered.
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
typedef U32(CALL *Convert)(I32);
static Convert convert;
typedef U32(CALL *Register)(const void *, void *, void *, U64 *);
typedef U32(CALL *Unregister)(U64);
static U32 phase;
static void *guard_page;

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
    U32 remaining = 0;
    if (guard_page && !VirtualProtect(guard_page, 4096, 4, &remaining)) return 0;
    guard_page = 0;
    char line[384];
    U32 at = text(line, 0, "phase=");
    at = hex(line, at, phase, 1);
    at = text(line, at, " remaining_guard=");
    at = hex(line, at, (remaining & 0x100) != 0, 1);
    at = text(line, at, " group=");
    at = text(line, at, group);
    at = text(line, at, " index="); at = hex(line, at, index, 4);
    at = text(line, at, " flags="); at = hex(line, at, flags, 8);
    at = text(line, at, " length="); at = hex(line, at, length, 8);
    at = text(line, at, " status="); at = hex(line, at, (U32)status, 8);
    at = text(line, at, " dos_error="); at = hex(line, at, convert(status), 8);
    at = text(line, at, " unchanged="); at = hex(line, at, before == after, 1);
    line[at++] = '\n';
    return emit(line, at) && before == after;
}
void entry(void) {
    Trace trace = (Trace)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTraceEvent");
    convert = (Convert)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError");
    if (!trace || !convert) ExitProcess(2);
    U8 *pages = (U8 *)VirtualAlloc(0, 12288, 0x3000, 4);
    if (!pages) ExitProcess(3);
    for (U32 i = 0; i < 16; ++i) pages[i] = provider[i];
    U32 previous = 0;
    if (!VirtualProtect(pages + 4096, 4096, 1, &previous)) ExitProcess(4);
    /* The third page remains readable for a provider spanning its predecessor. */
    Register registration = (Register)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventRegister");
    Unregister unregister = (Unregister)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventUnregister");
    if (!registration || !unregister) ExitProcess(11);
    U64 registered_handle = 0;
    for (phase = 0; phase < 3; ++phase) {
    if (phase == 1 && (registration(pages, 0, 0, &registered_handle) || !registered_handle)) ExitProcess(12);
    if (phase == 2 && unregister(registered_handle)) ExitProcess(13);
    for (U32 i = 0; i < sizeof fields; ++i) ((volatile U8 *)fields)[i] = 0;
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
    /* Mutual-fault priority, including an absent fields span of length zero. */
    for (U32 length_case = 0; length_case < 2; ++length_case) {
        for (U32 a = 0; a < 4; ++a) for (U32 b = 0; b < 4; ++b) {
            Handle hp[] = {pages, pages + 1, pages + 4096, 0};
            void *bp[] = {fields, fields + 1, pages + 4096, 0};
            if (!row(trace, "priority", length_case * 16 + a * 4 + b,
                     hp[a], 0x700, length_case ? 120 : 0, bp[b])) ExitProcess(14);
        }
    }
    /* Aligned field boundaries distinguish fixed probing from FieldSize. */
    for (U32 n = 0; n <= 128; n += 8)
        if (!row(trace, "span", n, pages, 0x700, 120, pages + 4096 - n)) ExitProcess(15);
    if (!row(trace, "provider-span", 8, pages + 4088, 0x700, 120, fields)) ExitProcess(16);
    for (U32 which = 0; which < 4; ++which) {
        U8 *gp = which < 2 ? pages : pages + 8192;
        U32 old = 0;
        if (!VirtualProtect(gp, 4096, 0x104, &old)) ExitProcess(17);
        guard_page = gp;
        Handle hp = which == 3 ? 0 : pages;
        void *bp = which == 0 ? 0 : which < 2 ? fields : pages + 8192;
        if (!row(trace, "guard", which, hp, 0x700, 120, bp)) ExitProcess(18);
    }
    /* Exact caller alignment, including independent provider/field priorities. */
    for (U32 offset = 0; offset < 16; ++offset) {
        if (!row(trace, "provider-align", offset, pages + offset, 0x700, 120, fields)) ExitProcess(19);
        if (!row(trace, "provider-align-null-fields", offset, pages + offset, 0x700, 120, 0)) ExitProcess(20);
        if (!row(trace, "fields-align", offset, pages, 0x700, 120, fields + offset)) ExitProcess(21);
        if (!row(trace, "null-provider-fields-align", offset, 0, 0x700, 120, fields + offset)) ExitProcess(22);
    }
    for (U32 bit = 0; bit < 32; ++bit) {
        U32 flags = 0x700 | ((U32)1 << bit);
        if (!row(trace, "flag-bits", bit, pages, flags, 120, fields)) ExitProcess(23);
        if (!row(trace, "flag-bits-null", bit, 0, flags, 120, 0)) ExitProcess(24);
    }
    for (U32 kind = 0; kind < 256; ++kind) {
        if (!row(trace, "kind", kind, pages, kind << 8, 120, fields)) ExitProcess(27);
        if (!row(trace, "kind-null", kind, 0, kind << 8, 120, 0)) ExitProcess(28);
    }
    if (!row(trace, "max-size", 0, pages, 0x700, (U32)-1, fields)) ExitProcess(25);
    fields[84] = 0xff; fields[85] = 0xff; fields[86] = 0xff; fields[87] = 0xff;
    put64(fields + 88, (U64)-1);
    if (!row(trace, "nested-unavailable", 0, pages, 0x700, 120, fields)) ExitProcess(26);
    }
    if (!VirtualFree(pages, 0, 0x8000)) ExitProcess(10);
    ExitProcess(0);
}
