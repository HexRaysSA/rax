// Independent class182 entry/length controls; binary stdout, no CRT.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
typedef LONG(NTAPI *Query)(ULONG, void *, ULONG, ULONG *);
typedef ULONG(NTAPI *DosError)(LONG);
#pragma pack(push, 1)
typedef struct {
    DWORD id, buffer_kind, bytes, offset, return_kind, pattern, status, dos_error, returned,
        last_error, buffer_guard, return_guard;
    BYTE observed[64];
} Row;
typedef struct {
    BYTE magic[8];
    DWORD version, machine, pointer_bytes, rows, row_bytes, record_bytes;
    BYTE entry[64];
} Header;
static struct {
    Header header;
    Row rows[4096];
} result;
#pragma pack(pop)
static BYTE *pages;
static Query query;
static DosError dos;
static DWORD row_count;
static void capture_case(DWORD buffer_kind, DWORD bytes, DWORD offset, DWORD return_kind,
                         DWORD pattern) {
    DWORD previous = 0;
    VirtualProtect(pages, 4096 * 8, PAGE_READWRITE, &previous);
    for (DWORD i = 0; i < 4096 * 8; i++)
        pages[i] = 0xa5;
    BYTE *output = buffer_kind == 0   ? 0
                   : buffer_kind == 1 ? (BYTE *)1
                   : buffer_kind == 3 ? pages + 8192 + offset
                   : buffer_kind == 4 ? pages + 12288 + offset
                   : buffer_kind >= 6 ? pages + 4096 - offset
                                      : pages + 128 + offset;
    BYTE *observed = buffer_kind <= 1 ? pages + 128 : output;
    for (DWORD i = 0; i < 64; i++)
        observed[i] = pattern ? 0xa5 : 0;
    BYTE *ret = return_kind == 0   ? 0
                : return_kind == 2 ? (BYTE *)1
                : return_kind == 3 ? pages + 4096 * 5
                : return_kind == 4 ? pages + 4096 * 6
                : return_kind == 5 ? pages + 4096 * 4 + 129
                : return_kind == 6 ? output
                : return_kind == 7 ? output + sizeof(void *)
                : return_kind == 9 ? pages + 4096 * 5 - 3
                                   : pages + 4096 * 4 + 128;
    BYTE *ret_observed = return_kind == 0 || return_kind == 2 ? pages + 4096 * 4 + 128 : ret;
    if (return_kind != 6 && return_kind != 7) {
        const BYTE sentinel[4] = {0xdd, 0xcc, 0xbb, 0xaa};
        for (DWORD i = 0; i < 4; i++)
            ret_observed[i] = sentinel[i];
    }
    VirtualProtect(pages + 8192, 4096, PAGE_READONLY, &previous);
    VirtualProtect(pages + 12288, 4096, PAGE_NOACCESS, &previous);
    VirtualProtect(pages + 4096 * 5, 4096, PAGE_READONLY, &previous);
    VirtualProtect(pages + 4096 * 6, 4096, PAGE_NOACCESS, &previous);
    if (buffer_kind == 5 || buffer_kind == 7)
        VirtualProtect(pages, 4096, PAGE_READWRITE | PAGE_GUARD, &previous);
    if (buffer_kind == 6)
        VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous);
    if (return_kind == 8)
        VirtualProtect(pages + 4096 * 4, 4096, PAGE_READWRITE | PAGE_GUARD, &previous);
    Row *row = &result.rows[row_count];
    row->id = row_count++;
    row->buffer_kind = buffer_kind;
    row->bytes = bytes;
    row->offset = offset;
    row->return_kind = return_kind;
    row->pattern = pattern;
    SetLastError(0x12345678);
    LONG status = query(182, output, bytes, (ULONG *)ret);
    row->status = (DWORD)status;
    row->dos_error = dos(status);
    row->last_error = GetLastError();
    MEMORY_BASIC_INFORMATION info;
    VirtualQuery(pages, &info, sizeof(info));
    row->buffer_guard = (info.Protect & PAGE_GUARD) != 0;
    VirtualQuery(pages + 4096 * 4, &info, sizeof(info));
    row->return_guard = (info.Protect & PAGE_GUARD) != 0;
    VirtualProtect(pages, 4096 * 8, PAGE_READWRITE, &previous);
    for (DWORD i = 0; i < 4; i++)
        row->returned |= ((DWORD)ret_observed[i]) << (i * 8);
    for (DWORD i = 0; i < 64; i++)
        row->observed[i] = observed[i];
}
void mainCRTStartup(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC entry = GetProcAddress(ntdll, "NtQuerySystemInformation");
    query = (Query)entry;
    dos = (DosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!query || !dos)
        ExitProcess(11);
    pages = (BYTE *)VirtualAlloc(0, 4096 * 8, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages)
        ExitProcess(12);
    const BYTE magic[8] = {'R', 'A', 'X', 'C', 'I', 'Q', '1', 0};
    for (DWORD i = 0; i < 8; i++)
        result.header.magic[i] = magic[i];
    result.header.version = 1;
    result.header.pointer_bytes = sizeof(void *);
    result.header.row_bytes = sizeof(Row);
    result.header.record_bytes = 56;
    for (DWORD i = 0; i < 64; i++)
        result.header.entry[i] = ((BYTE *)entry)[i];
#if defined(_M_ARM64)
    result.header.machine = 0xaa64;
#elif defined(_M_X64)
    result.header.machine = 0x8664;
#elif defined(_M_IX86)
    result.header.machine = 0x14c;
#else
#error unsupported caller
#endif
    const DWORD sizes[] = {0,  1,  4,  7,  8,  11, 12, 15,  16,   17,
                           24, 32, 48, 55, 56, 57, 64, 128, 4096, 0xffffffff};
    for (DWORD pattern = 0; pattern < 2; pattern++)
        for (DWORD kind = 0; kind < 6; kind++)
            for (DWORD offset = 0; offset < 8; offset++)
                for (DWORD n = 0; n < 20; n++)
                    capture_case(kind, sizes[n], offset, 1, pattern);
    for (DWORD pattern = 0; pattern < 2; pattern++)
        for (DWORD ret = 0; ret < 10; ret++)
            for (DWORD n = 0; n < 20; n++)
                capture_case(2, sizes[n], 0, ret, pattern);
    for (DWORD kind = 6; kind < 8; kind++)
        for (DWORD prefix = 0; prefix <= 64; prefix++)
            capture_case(kind, 56, prefix, 1, 0);
    result.header.rows = row_count;
    DWORD bytes = sizeof(Header) + row_count * sizeof(Row), written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &result, bytes, &written, 0) ||
        written != bytes)
        ExitProcess(13);
    ExitProcess(0);
}
