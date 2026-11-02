#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *QueryFn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);

int main(int argc, char **argv) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    QueryFn query = (QueryFn)GetProcAddress(ntdll, "NtWow64GetNativeSystemInformation");
    VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os = {sizeof(os)};
    wchar_t mapped[1024];
    DWORD count = GetMappedFileNameW(GetCurrentProcess(), ntdll, mapped, 1024);
    const ULONG lengths[] = {0,31,32,33,64,32,32,32,256};
    if (!query || !version || version(&os) < 0 || !count || count >= 1024) return 10;
    printf("{\"kind\":\"identity\",\"schema\":\"rax-native-policy-wow64-entry-v1\","
           "\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],\"mapped_provider_utf16\":\"",
           sizeof(void *), os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber);
    for (DWORD i = 0; i < count; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\"}\n");
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) return 0;
    if (argc != 1) return 11;
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        __declspec(align(8)) unsigned char output[256];
        ULONG returned = 0xA5A5A5A5;
        LONG status = (LONG)0xDEADBEEF, exception = 0;
        ULONG cls = i == 8 ? 0 : 164;
        void *destination = i == 6 ? NULL : output;
        ULONG *result = i == 5 ? NULL : i == 7 ? (ULONG *)(uintptr_t)1 : &returned;
        memset(output, 0xA5, sizeof(output));
        __try { status = query(cls, destination, lengths[i], result); }
        __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
        printf("{\"kind\":\"case\",\"index\":%u,\"class\":%lu,\"length\":%lu,"
               "\"status\":%lu,\"exception\":%lu,\"returned\":%lu,\"bytes\":\"",
               i, cls, lengths[i], (ULONG)status, (ULONG)exception, returned);
        for (unsigned j = 0; j < sizeof(output); ++j) printf("%02x", output[j]);
        printf("\"}\n");
    }
    printf("{\"kind\":\"finished\",\"records\":9}\n");
    return 0;
}
