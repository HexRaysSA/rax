#define _WIN32_WINNT 0x0a00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const SIZE_T page = 4096;
enum { width = 48 };

typedef ULONG (NTAPI *QueryProcess)(HANDLE, ULONG, void *, ULONG, ULONG *);

static void require(int valid, const char *operation)
{
    if (!valid) {
        fprintf(stderr, "%s (last error %lu)\n", operation, (unsigned long)GetLastError());
        ExitProcess(1);
    }
}

static void bytes(const unsigned char *address)
{
    putchar('"');
    for (size_t offset = 0; offset < width; ++offset)
        printf("%02x", (unsigned)address[offset]);
    putchar('"');
}

int main(void)
{
    USHORT machine = 0, native = 0;
    require(sizeof(void *) == 4, "Caller width");
    require(IsWow64Process2(GetCurrentProcess(), &machine, &native), "IsWow64Process2");
    require(machine == IMAGE_FILE_MACHINE_I386 && native == IMAGE_FILE_MACHINE_ARM64, "Process ISA");

    union { FARPROC address; QueryProcess query; } process;
    process.address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    require(process.address != NULL, "NtQueryInformationProcess");
    unsigned char *const base = VirtualAlloc(NULL, 2 * page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG *const returned = VirtualAlloc(NULL, page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    require(base != NULL && returned != NULL, "VirtualAlloc");
    ULONG start = process.query(GetCurrentProcess(), 37, base, width, returned);
    if (start != 0 || *returned != width) {
        fprintf(stderr, "Full query returned status %#lx and ReturnLength %lu\n",
                (unsigned long)start, (unsigned long)*returned);
        return 2;
    }
    fputs("{\"machine\":\"X86-on-ARM64\",\"full\":", stdout);
    bytes(base);
    fputs(",\"cases\":[", stdout);

    static const DWORD protections[] = {PAGE_NOACCESS, PAGE_READONLY, PAGE_READONLY | PAGE_GUARD,
                                        PAGE_READWRITE | PAGE_GUARD, PAGE_READWRITE};
    static const unsigned fitting[] = {1, 4, 7, 8, 9, 12, 15, 16, 17, 20, 23, 24, 31, 32, 40, 44, 47};
    int first = 1;
    unsigned char *const following = base + page;
    for (size_t p = 0; p < sizeof(protections) / sizeof(*protections); ++p) {
        for (size_t f = 0; f < sizeof(fitting) / sizeof(*fitting); ++f) {
            unsigned char *const output = following - fitting[f];
            memset(output, 0xa5, width);
            *returned = 0xd4d4d4d4;
            DWORD old = 0;
            require(VirtualProtect(following, page, protections[p], &old), "Protect destination");
            ULONG status = process.query(GetCurrentProcess(), 37, output, width, returned);
            MEMORY_BASIC_INFORMATION info;
            require(VirtualQuery(following, &info, sizeof(info)) == sizeof(info), "VirtualQuery");
            require(VirtualProtect(following, page, PAGE_READWRITE, &old), "Unprotect destination");
            if (!first) putchar(',');
            first = 0;
            printf("{\"protection\":%lu,\"fitting\":%u,\"status\":%lu,\"return_length\":%lu,"
                   "\"observed_protection\":%lu,\"observed\":",
                   (unsigned long)protections[p], fitting[f], (unsigned long)status,
                   (unsigned long)*returned, (unsigned long)info.Protect);
            bytes(output);
            putchar('}');
        }
    }
    puts("]}");
    require(VirtualFree(returned, 0, MEM_RELEASE), "Free length");
    require(VirtualFree(base, 0, MEM_RELEASE), "Free record");
    return 0;
}
