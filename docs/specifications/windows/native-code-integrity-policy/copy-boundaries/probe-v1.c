#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *QueryFn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);

int main(int argc, char **argv) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    QueryFn query = (QueryFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os = {sizeof(os)};
    wchar_t mapped[1024];
    DWORD count = GetMappedFileNameW(GetCurrentProcess(), ntdll, mapped, 1024);
    const DWORD protections[] = {PAGE_NOACCESS, PAGE_READONLY,
        PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY | PAGE_GUARD};
    unsigned char *pages;
    unsigned records = 0;
    if (!query || !version || version(&os) < 0 || !count || count >= 1024) return 10;
    printf("{\"kind\":\"identity\",\"schema\":\"rax-native-policy-copy-boundaries-v1\","
           "\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],\"mapped_provider_utf16\":\"",
           sizeof(void *), os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber);
    for (DWORD i = 0; i < count; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\"}\n");
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) return 0;
    if (argc != 1) return 11;
    pages = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages) return 12;
    for (unsigned remaining = 1; remaining < 32; ++remaining) {
        for (unsigned role = 0; role < 4; ++role) {
            ULONG returned = 0xA5A5A5A5;
            LONG status = (LONG)0xDEADBEEF, exception = 0;
            DWORD previous;
            MEMORY_BASIC_INFORMATION region;
            unsigned char *output = pages + 4096 - remaining;
            if (!VirtualProtect(pages, 8192, PAGE_READWRITE, &previous)) return 13;
            memset(pages, 0xA5, 8192);
            if (!VirtualProtect(pages + 4096, 4096, protections[role], &previous)) return 14;
            __try { status = query(164, output, 32, &returned); }
            __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
            if (!VirtualQuery(pages + 4096, &region, sizeof(region))) return 15;
            if (!VirtualProtect(pages, 8192, PAGE_READWRITE, &previous)) return 16;
            printf("{\"kind\":\"case\",\"index\":%u,\"remaining\":%u,\"role\":%u,"
                   "\"status\":%lu,\"exception\":%lu,\"returned\":%lu,\"protection\":%lu,\"bytes\":\"",
                   records, remaining, role, (ULONG)status, (ULONG)exception, returned, region.Protect);
            for (unsigned i = 0; i < 48; ++i) printf("%02x", output[i]);
            printf("\"}\n");
            ++records;
        }
    }
    if (!VirtualFree(pages, 0, MEM_RELEASE)) return 17;
    printf("{\"kind\":\"finished\",\"records\":%u}\n", records);
    return 0;
}
