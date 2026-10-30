#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* PHNT 53fbbdc5b5d2b08761db1c7b26bfa8c820924356, ntexapi.h.
 * Use the aggregate integer members of its two bit-field unions. */
typedef struct {
    ULONG Options;
    ULONG HVCIOptions;
    ULONGLONG Version;
    GUID PolicyGuid;
} POLICY_INFORMATION;
static_assert(sizeof(POLICY_INFORMATION) == 32, "policy size");
static_assert(offsetof(POLICY_INFORMATION, Options) == 0, "options offset");
static_assert(offsetof(POLICY_INFORMATION, HVCIOptions) == 4, "HVCI offset");
static_assert(offsetof(POLICY_INFORMATION, Version) == 8, "version offset");
static_assert(offsetof(POLICY_INFORMATION, PolicyGuid) == 16, "GUID offset");

typedef LONG (NTAPI *QueryFn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);
static QueryFn query;
static unsigned char *pages;
static unsigned records;

static void protect(void *address, SIZE_T size, DWORD flags) {
    DWORD previous;
    if (!VirtualProtect(address, size, flags, &previous)) ExitProcess(16);
}

static int identity(const char *kind, HMODULE module, const RTL_OSVERSIONINFOW *os) {
    wchar_t logical[1024], mapped[1024];
    DWORD logical_length = GetModuleFileNameW(module, logical, 1024);
    DWORD mapped_length = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
    if (!logical_length || logical_length >= 1024 || !mapped_length || mapped_length >= 1024) return 18;
    printf("{\"kind\":\"%s\",\"schema\":\"rax-native-code-integrity-policy-v1\","
           "\"pointer_bytes\":%zu,\"record_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],"
           "\"provider_utf16\":\"", kind, sizeof(void *), sizeof(POLICY_INFORMATION),
           os->dwMajorVersion, os->dwMinorVersion, os->dwBuildNumber);
    for (DWORD i = 0; i < logical_length; ++i) printf("%02x%02x", logical[i] & 255, logical[i] >> 8);
    printf("\",\"mapped_provider_utf16\":\"");
    for (DWORD i = 0; i < mapped_length; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\"}\n");
    return 0;
}

static int observe(unsigned output_role, unsigned returned_role, ULONG length, unsigned char poison) {
    unsigned output_offset = 0, returned_offset = 8192;
    unsigned char *output;
    ULONG *returned;
    LONG status = (LONG)0xDEADBEEF, exception = 0;
    MEMORY_BASIC_INFORMATION regions[4];
    const unsigned watched[] = {0, 4096, 8192, 12288};
    protect(pages, 65536, PAGE_READWRITE);
    memset(pages, poison, 65536);
    output = pages;
    switch (output_role) {
    case 1: output = NULL; break;
    case 2: output = (void *)(uintptr_t)1; break;
    case 3: output_offset = 1; output = pages + output_offset; break;
    case 4: output_offset = 4; output = pages + output_offset; break;
    case 5: protect(pages, 4096, PAGE_READONLY); break;
    case 6: protect(pages, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 7: protect(pages, 4096, PAGE_NOACCESS); break;
    case 8: case 9: case 10:
        output_offset = 4092;
        output = pages + output_offset;
        protect(pages + 4096, 4096, output_role == 8 ? PAGE_NOACCESS :
            output_role == 9 ? PAGE_READWRITE | PAGE_GUARD : PAGE_READONLY);
        break;
    case 11: protect(pages, 4096, PAGE_READONLY | PAGE_GUARD); break;
    case 12: output = (void *)(UINTPTR_MAX - 15); break;
    case 13: output_offset = 2; output = pages + output_offset; break;
    }
    returned = (ULONG *)(pages + returned_offset);
    switch (returned_role) {
    case 1: returned = NULL; break;
    case 2: returned = (ULONG *)(uintptr_t)1; break;
    case 3: returned_offset = 8193; returned = (ULONG *)(pages + returned_offset); break;
    case 4: protect(pages + 8192, 4096, PAGE_READONLY); break;
    case 5: protect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 6: protect(pages + 8192, 4096, PAGE_NOACCESS); break;
    case 7: case 8: case 9: case 10:
        returned_offset = output_offset + (returned_role == 7 ? 0 :
            returned_role == 8 ? 4 : returned_role == 9 ? 28 : 32);
        returned = (ULONG *)(pages + returned_offset);
        break;
    case 11:
        returned_offset = 12286; returned = (ULONG *)(pages + returned_offset);
        protect(pages + 12288, 4096, PAGE_NOACCESS);
        break;
    case 12: protect(pages + 8192, 4096, PAGE_READONLY | PAGE_GUARD); break;
    }
    __try { status = query(164, output, length, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
    for (unsigned i = 0; i < 4; ++i) {
        if (!VirtualQuery(pages + watched[i], &regions[i], sizeof(regions[i]))) return 5;
    }
    protect(pages, 65536, PAGE_READWRITE);
    printf("{\"kind\":\"case\",\"index\":%u,\"output\":%u,\"returned\":%u,\"length\":%lu,"
           "\"poison\":%u,\"status\":%lu,\"exception\":%lu,\"protections\":[%lu,%lu,%lu,%lu],"
           "\"bytes\":\"", records, output_role, returned_role, length, poison,
           (ULONG)status, (ULONG)exception, regions[0].Protect, regions[1].Protect,
           regions[2].Protect, regions[3].Protect);
    for (unsigned i = 0; i < 96; ++i) printf("%02x", pages[output_offset + i]);
    printf("\",\"returned_bytes\":\"");
    for (unsigned i = 0; i < 8; ++i) printf("%02x", pages[returned_offset + i]);
    printf("\"}\n");
    ++records;
    return 0;
}

int main(int argc, char **argv) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os = {sizeof(os)};
    const ULONG lengths[] = {0,1,4,8,16,24,28,31,32,33,36,64,4096,4097,65535,0xFFFFFFFF};
    setvbuf(stdout, NULL, _IONBF, 0);
    query = (QueryFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!version || !query || version(&os) < 0) return 10;
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) return identity("identity", ntdll, &os);
    if (argc != 1 || identity("host", ntdll, &os)) return 11;
    pages = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages) return 12;
    for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l) {
        for (unsigned output = 0; output < 14; ++output) {
            for (unsigned returned = 0; returned < 13; ++returned) {
                int result = observe(output, returned, lengths[l], 0xA5);
                if (result) return result;
            }
        }
    }
    for (unsigned i = 0; i < 4; ++i) {
        int result = observe(0, i & 1, 32, i & 2 ? 0x5A : 0xA5);
        if (result) return result;
    }
    if (!VirtualFree(pages, 0, MEM_RELEASE)) return 13;
    printf("{\"kind\":\"finished\",\"records\":%u}\n", records);
    return 0;
}
