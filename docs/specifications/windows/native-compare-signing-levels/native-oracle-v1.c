// Independent read-only native scalar comparison; binary stdout, no CRT.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

_Static_assert(sizeof(SE_SIGNING_LEVEL) == 1, "signing-level ABI width");
typedef LONG (NTAPI *Compare)(SE_SIGNING_LEVEL, SE_SIGNING_LEVEL);
// Deliberately wide machine argument carriers test truncation at the ABI edge.
typedef LONG (NTAPI *Carrier)(ULONG_PTR, ULONG_PTR);
typedef ULONG (NTAPI *DosError)(LONG);
#pragma pack(push, 1)
typedef struct {
    BYTE magic[8];
    DWORD version, machine, pointer_bytes, carrier_bits;
    DWORD last_error_before, last_error_after, matrix_count, carrier_count;
    BYTE entry_bytes[32];
} Header;
typedef struct { DWORD status, dos_error; } Pair;
typedef struct { ULONGLONG first, second; DWORD status, dos_error; } WidePair;
static struct { Header header; Pair matrix[65536]; WidePair carriers[256]; } result;
#pragma pack(pop)

static const ULONGLONG carriers[16] = {
    0, 1, 7, 14, 15, 16, 255, 256, 257, 65537,
    0xffffff00ULL, 0xffffffffULL, 0x100000000ULL,
    0x12345678abcdef00ULL, 0xffffffffffffff0fULL, 0xffffffffffffffffULL
};

void mainCRTStartup(void) {
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC entry = GetProcAddress(module, "NtCompareSigningLevels");
    Compare compare = (Compare)entry;
    Carrier wide = (Carrier)entry;
    DosError dos = (DosError)GetProcAddress(module, "RtlNtStatusToDosError");
    if (!entry || !dos) ExitProcess(11);
    const BYTE magic[8] = {'R','A','X','C','M','P','1',0};
    for (DWORD i = 0; i < 8; ++i) result.header.magic[i] = magic[i];
    result.header.version = 1;
#if defined(_M_ARM64)
    result.header.machine = 0xaa64;
#elif defined(_M_X64)
    result.header.machine = 0x8664;
#elif defined(_M_IX86)
    result.header.machine = 0x14c;
#else
#error unsupported native caller
#endif
    result.header.pointer_bytes = sizeof(void*);
    result.header.carrier_bits = sizeof(ULONG_PTR) * 8;
    result.header.matrix_count = 65536;
    result.header.carrier_count = 256;
    for (DWORD i = 0; i < 32; ++i)
        result.header.entry_bytes[i] = ((const BYTE*)entry)[i];
    SetLastError(0x12345678);
    result.header.last_error_before = GetLastError();
    for (DWORD first = 0; first < 256; ++first) {
        for (DWORD second = 0; second < 256; ++second) {
            DWORD index = first * 256 + second;
            LONG status = compare((SE_SIGNING_LEVEL)first, (SE_SIGNING_LEVEL)second);
            result.matrix[index].status = (DWORD)status;
            result.matrix[index].dos_error = dos(status);
        }
    }
    for (DWORD first = 0; first < 16; ++first) {
        for (DWORD second = 0; second < 16; ++second) {
            DWORD index = first * 16 + second;
            ULONG_PTR a = (ULONG_PTR)carriers[first], b = (ULONG_PTR)carriers[second];
            LONG status = wide(a, b);
            result.carriers[index].first = a;
            result.carriers[index].second = b;
            result.carriers[index].status = (DWORD)status;
            result.carriers[index].dos_error = dos(status);
        }
    }
    result.header.last_error_after = GetLastError();
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &result, sizeof(result), &written, 0)
        || written != sizeof(result)) ExitProcess(12);
    ExitProcess(0);
}
