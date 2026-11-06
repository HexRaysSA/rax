// Current-process-only native AMD64 device-map observer. The NT prototype is
// retained in ../native-test-alert/primary/phnt-ntpsapi.h. No guest data enters
// these calls; every real handle and allocation is owned by this observer.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(_M_X64) || defined(_M_ARM64EC)
#error This observer requires ordinary AMD64 machine code.
#endif

typedef LONG (NTAPI *QueryProcess)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef BOOL (WINAPI *QueryMachine)(HANDLE, USHORT *, USHORT *);
typedef BOOL (WINAPI *QueryInformation)(HANDLE, int, void *, DWORD);
typedef struct {
    USHORT process_machine;
    USHORT reserved;
    ULONG attributes;
} MachineInformation;
static QueryProcess query;
static int comma;

static void hex(const unsigned char *bytes, size_t size) {
    putchar('"');
    for (size_t i = 0; i < size; ++i) printf("%02x", bytes[i]);
    putchar('"');
}

static void begin(void) {
    if (comma) putchar(',');
    comma = 1;
}

static void regular(const char *label, HANDLE process, ULONG length,
                    unsigned flags, int offset, int bad_output,
                    int bad_returned) {
    unsigned char *buffer = HeapAlloc(GetProcessHeap(), 0, 256);
    if (!buffer) ExitProcess(3);
    memset(buffer, 0xa5, 256);
    if (offset >= 0 && offset + 44 <= 256) memcpy(buffer + offset + 40, &flags, 4);
    unsigned char before[96];
    memcpy(before, buffer, sizeof(before));
    ULONG returned = 0xa5a5a5a5;
    void *output = bad_output ? (void *)(uintptr_t)1 :
                   offset < 0 ? NULL : buffer + offset;
    ULONG status = (ULONG)query(process, 23, output, length,
                               bad_returned ? (ULONG *)(uintptr_t)1 : &returned);
    begin();
    printf("{\"label\":\"%s\",\"length\":%lu,\"flags\":%u,"
           "\"output_offset\":%d,\"bad_output\":%s,\"bad_returned\":%s,"
           "\"status\":%lu,\"returned\":%lu,\"before\":",
           label, length, flags, offset, bad_output ? "true" : "false",
           bad_returned ? "true" : "false", status, returned);
    hex(before, sizeof(before));
    printf(",\"after\":"); hex(buffer, 96); putchar('}');
    HeapFree(GetProcessHeap(), 0, buffer);
}

static void boundary(ULONG length, unsigned available, ULONG protection,
                     ULONG page) {
    unsigned char *allocation = VirtualAlloc(NULL, 2 * page,
                                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocation) ExitProcess(4);
    unsigned char *second = allocation + page;
    unsigned char *output = second - available;
    memset(output, 0xa5, 96);
    memset(output + 40, 0, 4);
    unsigned char before[96];
    memcpy(before, output, sizeof(before));
    ULONG old, remaining, returned = 0xa5a5a5a5;
    if (!VirtualProtect(second, page, protection, &old)) ExitProcess(5);
    ULONG status = (ULONG)query(GetCurrentProcess(), 23, output, length, &returned);
    if (!VirtualProtect(second, page, PAGE_READWRITE, &remaining)) ExitProcess(6);
    begin();
    printf("{\"label\":\"boundary\",\"length\":%lu,\"available\":%u,"
           "\"protection\":%lu,\"remaining_protection\":%lu,"
           "\"status\":%lu,\"returned\":%lu,\"before\":",
           length, available, protection, remaining, status, returned);
    hex(before, sizeof(before));
    printf(",\"after\":"); hex(output, 96); putchar('}');
    if (!VirtualFree(allocation, 0, MEM_RELEASE)) ExitProcess(7);
}

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    query = (QueryProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    QueryMachine machine_query = (QueryMachine)GetProcAddress(kernel, "IsWow64Process2");
    QueryInformation information_query =
        (QueryInformation)GetProcAddress(kernel, "GetProcessInformation");
    USHORT machine = 0, native = 0;
    MachineInformation information = {0};
    if (!query || !machine_query || !information_query ||
        !machine_query(GetCurrentProcess(), &machine, &native) ||
        !information_query(GetCurrentProcess(), 9, &information, sizeof(information))) return 2;
    const unsigned char *image = (const unsigned char *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
    const IMAGE_NT_HEADERS64 *headers = (const IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    USHORT loaded_machine = headers->FileHeader.Machine;
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    printf("{\"pointer_bytes\":%zu,\"process_machine\":%u,\"native_machine\":%u,"
           "\"compiler_machine\":34404,\"loaded_machine\":%u,"
           "\"information_machine\":%u,\"machine_attributes\":%lu,\"observations\":[",
           sizeof(void *), machine, native, loaded_machine,
           information.process_machine, information.attributes);
    ULONG lengths[] = {36, 48};
    for (size_t i = 0; i < 2; ++i) {
        ULONG length = lengths[i];
        regular("valid", GetCurrentProcess(), length, 0, 0, 0, 0);
        regular("null-handle", NULL, length, 0, 0, 0, 0);
        regular("null-output", GetCurrentProcess(), length, 0, -1, 0, 0);
        regular("bad-output", GetCurrentProcess(), length, 0, 0, 1, 0);
        regular("bad-output-null-handle", NULL, length, 0, 0, 1, 0);
        regular("bad-returned", GetCurrentProcess(), length, 0, 0, 0, 1);
        regular("bad-returned-null-handle", NULL, length, 0, 0, 0, 1);
        for (int offset = 1; offset <= 4; ++offset)
            regular("offset", GetCurrentProcess(), length, 0, offset, 0, 0);
    }
    unsigned flags[] = {1, 2, 0xffffffff};
    for (size_t i = 0; i < 3; ++i) {
        regular("flags", GetCurrentProcess(), 48, flags[i], 0, 0, 0);
        regular("flags-null-handle", NULL, 48, flags[i], 0, 0, 0);
        regular("flags-bad-output", GetCurrentProcess(), 48, flags[i], 0, 1, 0);
    }
    ULONG rights[] = {0, 0x10, 0x400, 0x1000, 0x1400};
    for (size_t i = 0; i < 5; ++i) {
        HANDLE alias;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                             GetCurrentProcess(), &alias, rights[i], FALSE, 0)) return 8;
        char label[64];
        snprintf(label, sizeof(label), "access-basic-%lu", rights[i]);
        regular(label, alias, 36, 0, 0, 0, 0);
        snprintf(label, sizeof(label), "access-extended-%lu", rights[i]);
        regular(label, alias, 48, 1, 0, 0, 0);
        CloseHandle(alias);
    }
    ULONG protections[] = {PAGE_NOACCESS, PAGE_READONLY,
                           PAGE_READONLY | PAGE_GUARD, PAGE_READWRITE | PAGE_GUARD};
    for (size_t i = 0; i < 2; ++i)
        for (unsigned available = 0; available <= 48; ++available)
            for (size_t j = 0; j < 4; ++j)
                boundary(lengths[i], available, protections[j], system.dwPageSize);
    puts("]}");
    return (loaded_machine == IMAGE_FILE_MACHINE_AMD64 &&
            information.process_machine == IMAGE_FILE_MACHINE_AMD64) ? 0 : 9;
}
