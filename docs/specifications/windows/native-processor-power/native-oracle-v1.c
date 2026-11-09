// Read-only native ProcessorInformation power_query; binary stdout, no CRT.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
typedef LONG(NTAPI *Query)(ULONG, void *, ULONG, void *, ULONG);
typedef ULONG(NTAPI *DosError)(LONG);
#pragma pack(push, 1)
typedef struct {
    DWORD id, input_kind, input_bytes, output_kind, output_bytes, offset, status, dos_error,
        last_error, guard;
    BYTE observed[96];
} Row;
typedef struct {
    BYTE magic[8];
    DWORD version, machine, pointer_bytes, processors, rows, row_bytes;
    BYTE entry[64];
} Header;
static struct {
    Header header;
    Row rows[2048];
} result;
#pragma pack(pop)
static Query power_query;
static DosError dos;
static BYTE *pages;
static DWORD row_count;
static void capture_case(DWORD input_kind, DWORD input_bytes, DWORD output_kind, DWORD output_bytes,
                         DWORD offset) {
    DWORD previous = 0;
    VirtualProtect(pages, 4096 * 4, PAGE_READWRITE, &previous);
    for (DWORD i = 0; i < 4096 * 4; i++)
        pages[i] = 0xa5;
    VirtualProtect(pages + 4096 * 2, 4096, PAGE_NOACCESS, &previous);
    VirtualProtect(pages + 4096 * 3, 4096, PAGE_READONLY, &previous);
    BYTE *input = input_kind == 0   ? 0
                  : input_kind == 1 ? (BYTE *)1
                  : input_kind == 2 ? pages + 512
                  : input_kind == 3 ? pages + 4096 * 2
                                    : pages + 4096 * 3;
    BYTE *output = output_kind == 0   ? 0
                   : output_kind == 1 ? (BYTE *)1
                   : output_kind == 2 ? pages + 128 + offset
                   : output_kind == 3 ? pages + 4096 * 2
                   : output_kind == 4 ? pages + 4096 * 3
                   : output_kind == 5 ? pages + 4096 - offset
                                      : pages + 4096 - offset;
    if (output_kind == 5)
        VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous);
    if (output_kind == 7)
        VirtualProtect(pages, 4096, PAGE_READWRITE | PAGE_GUARD, &previous);
    Row *row = &result.rows[row_count];
    row->id = row_count++;
    row->input_kind = input_kind;
    row->input_bytes = input_bytes;
    row->output_kind = output_kind;
    row->output_bytes = output_bytes;
    row->offset = offset;
    SetLastError(0x12345678);
    LONG status = power_query(11, input, input_bytes, output, output_bytes);
    row->status = (DWORD)status;
    row->dos_error = dos(status);
    row->last_error = GetLastError();
    MEMORY_BASIC_INFORMATION info;
    VirtualQuery(pages, &info, sizeof(info));
    row->guard = (info.Protect & PAGE_GUARD) != 0;
    VirtualProtect(pages, 4096 * 4, PAGE_READWRITE, &previous);
    BYTE *observed = (output_kind >= 5) ? pages + 4096 - 48 : pages + 128;
    for (DWORD i = 0; i < 96; i++)
        row->observed[i] = observed[i];
}
void mainCRTStartup(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC entry = GetProcAddress(ntdll, "NtPowerInformation");
    power_query = (Query)entry;
    dos = (DosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!power_query || !dos)
        ExitProcess(11);
    pages = (BYTE *)VirtualAlloc(0, 4096 * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages)
        ExitProcess(12);
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    const BYTE magic[8] = {'R', 'A', 'X', 'P', 'O', 'W', '1', 0};
    for (DWORD i = 0; i < 8; i++)
        result.header.magic[i] = magic[i];
    result.header.version = 1;
    result.header.pointer_bytes = sizeof(void *);
    result.header.processors = info.dwNumberOfProcessors;
    result.header.row_bytes = sizeof(Row);
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
    const DWORD sizes[] = {0,  1,  3,  4,  7,  8,  15, 16, 23,   24,
                           25, 47, 48, 49, 63, 64, 95, 96, 4096, 0xffffffff};
    for (DWORD output_kind = 0; output_kind <= 4; output_kind++)
        for (DWORD n = 0; n < sizeof(sizes) / 4; n++)
            capture_case(0, 0, output_kind, sizes[n], 0);
    for (DWORD input_kind = 0; input_kind < 5; input_kind++)
        for (DWORD input_bytes = 0; input_bytes < 3; input_bytes++)
            for (DWORD n = 0; n < sizeof(sizes) / 4; n++)
                capture_case(input_kind,
                             input_bytes == 0   ? 0
                             : input_bytes == 1 ? 1
                                                : 0xffffffff,
                             2, sizes[n], 0);
    for (DWORD offset = 0; offset < 8; offset++)
        for (DWORD n = 0; n < sizeof(sizes) / 4; n++)
            capture_case(0, 0, 2, sizes[n], offset);
    for (DWORD output_kind = 5; output_kind < 8; output_kind++)
        for (DWORD prefix = 0; prefix <= 64; prefix++)
            capture_case(0, 0, output_kind, info.dwNumberOfProcessors * 24, prefix);
    result.header.rows = row_count;
    DWORD length = sizeof(Header) + row_count * sizeof(Row), written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &result, length, &written, 0) ||
        written != length)
        ExitProcess(13);
    ExitProcess(0);
}
