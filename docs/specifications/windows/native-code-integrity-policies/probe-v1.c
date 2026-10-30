#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG (NTAPI *QueryFn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);
static QueryFn query;
static unsigned char *pages, *snapshot, *model;
static ULONG required, returned_page, arena, records;

static void protect(void *address, SIZE_T size, DWORD flags) {
    DWORD previous;
    if (!VirtualProtect(address, size, flags, &previous)) ExitProcess(16);
}

static int identity(const char *kind, HMODULE module, const RTL_OSVERSIONINFOW *os) {
    wchar_t logical[1024], mapped[1024];
    DWORD a = GetModuleFileNameW(module, logical, 1024);
    DWORD b = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
    if (!a || a >= 1024 || !b || b >= 1024) return 18;
    printf("{\"kind\":\"%s\",\"schema\":\"rax-native-code-integrity-policies-v1\","
           "\"pointer_bytes\":%zu,\"required\":%lu,\"arena\":%lu,\"returned_page\":%lu,"
           "\"kernel\":[%lu,%lu,%lu],\"provider_utf16\":\"", kind, sizeof(void *),
           required, arena, returned_page, os->dwMajorVersion, os->dwMinorVersion, os->dwBuildNumber);
    for (DWORD i = 0; i < a; ++i) printf("%02x%02x", logical[i] & 255, logical[i] >> 8);
    printf("\",\"mapped_provider_utf16\":\"");
    for (DWORD i = 0; i < b; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\"}\n");
    return 0;
}

static int observe(unsigned output_role, unsigned returned_role, ULONG length, unsigned char poison) {
    ULONG output_offset = 0, returned_offset = returned_page;
    unsigned char *output = pages;
    ULONG *returned;
    LONG status = (LONG)0xDEADBEEF, exception = 0;
    const ULONG last_page = (required - 1) & ~4095UL;
    const ULONG tail_page = (required + 4095) & ~4095UL;
    const ULONG watched[] = {0, 4096, last_page, tail_page, returned_page, returned_page + 4096};
    MEMORY_BASIC_INFORMATION regions[6];
    protect(pages, arena, PAGE_READWRITE);
    memset(pages, poison, arena);
    switch (output_role) {
    case 1: output = NULL; break;
    case 2: output = (void *)(uintptr_t)1; break;
    case 3: output_offset = 1; output = pages + 1; break;
    case 4: output_offset = 4; output = pages + 4; break;
    case 5: protect(pages, 4096, PAGE_READONLY); break;
    case 6: protect(pages, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 7: protect(pages, 4096, PAGE_NOACCESS); break;
    case 8: case 9: case 10:
        output_offset = 4092; output = pages + output_offset;
        protect(pages + 4096, 4096, output_role == 8 ? PAGE_NOACCESS :
                output_role == 9 ? PAGE_READWRITE | PAGE_GUARD : PAGE_READONLY);
        break;
    case 11: protect(pages, 4096, PAGE_READONLY | PAGE_GUARD); break;
    case 12: output = (void *)(UINTPTR_MAX - 15); break;
    case 13: output_offset = 2; output = pages + 2; break;
    case 14: case 15: case 16:
        protect(pages + last_page, 4096, output_role == 14 ? PAGE_NOACCESS :
                output_role == 15 ? PAGE_READWRITE | PAGE_GUARD : PAGE_READONLY);
        break;
    case 17: protect(pages + tail_page, 4096, PAGE_NOACCESS); break;
    }
    returned = (ULONG *)(pages + returned_offset);
    switch (returned_role) {
    case 1: returned = NULL; break;
    case 2: returned = (ULONG *)(uintptr_t)1; break;
    case 3: ++returned_offset; returned = (ULONG *)(pages + returned_offset); break;
    case 4: protect(pages + returned_page, 4096, PAGE_READONLY); break;
    case 5: protect(pages + returned_page, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 6: protect(pages + returned_page, 4096, PAGE_NOACCESS); break;
    case 7: case 8: case 9: case 10:
        returned_offset = output_offset + (returned_role == 7 ? 0 :
                returned_role == 8 ? 4 : returned_role == 9 ? required - 4 : required);
        returned = (ULONG *)(pages + returned_offset);
        break;
    case 11:
        returned_offset = returned_page + 4094;
        returned = (ULONG *)(pages + returned_offset);
        protect(pages + returned_page + 4096, 4096, PAGE_NOACCESS);
        break;
    case 12: protect(pages + returned_page, 4096, PAGE_READONLY | PAGE_GUARD); break;
    }
    __try { status = query(189, output, length, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
    for (unsigned i = 0; i < 6; ++i)
        if (!VirtualQuery(pages + watched[i], &regions[i], sizeof(regions[i]))) return 5;
    protect(pages, arena, PAGE_READWRITE);

    /* Lossless representation of the observed entire arena: initial poison,
       a prefix of the separately acquired native snapshot, and eight actual
       watched ReturnLength bytes. Verify every arena byte before recording.
       This assertion detects other writes or a non-prefix partial copy. */
    ULONG copied = 0;
    for (ULONG i = 0; i < required; ++i) {
        ULONG at = output_offset + i;
        if (at >= returned_offset && at < returned_offset + 8) continue;
        if (pages[at] != poison) copied = i + 1;
    }
    memset(model, poison, arena);
    memcpy(model + output_offset, snapshot, copied);
    memcpy(model + returned_offset, pages + returned_offset, 8);
    if (memcmp(model, pages, arena)) {
        ULONG at = 0; while (at < arena && model[at] == pages[at]) ++at;
        fprintf(stderr, "unrepresented store: case=%lu out=%u ret=%u len=%lu copied=%lu offset=%lu actual=%u represented=%u\n",
                records, output_role, returned_role, length, copied, at, pages[at], model[at]);
        return 21;
    }
    printf("{\"kind\":\"case\",\"index\":%lu,\"output\":%u,\"returned\":%u,\"length\":%lu,"
           "\"poison\":%u,\"status\":%lu,\"exception\":%lu,\"protections\":[",
           records, output_role, returned_role, length, poison, (ULONG)status, (ULONG)exception);
    for (unsigned i = 0; i < 6; ++i) printf("%s%lu", i ? "," : "", regions[i].Protect);
    printf("],\"copy_prefix\":%lu,\"arena_reconstruction_verified\":true,\"returned_bytes\":\"", copied);
    for (unsigned i = 0; i < 8; ++i) printf("%02x", pages[returned_offset + i]);
    printf("\"}\n");
    ++records;
    return 0;
}

int main(int argc, char **argv) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os = {sizeof(os)};
    SYSTEM_INFO system;
    setvbuf(stdout, NULL, _IONBF, 0);
    query = (QueryFn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!version || !query || version(&os) < 0) return 10;
    GetSystemInfo(&system);
    if (system.dwPageSize != 4096) return 19;
    if (argc == 2 && !strcmp(argv[1], "--identity")) return identity("identity", ntdll, &os);
    if (argc != 3 || strcmp(argv[1], "--run")) return 11;
    if ((ULONG)query(189, NULL, 0, &required) != 0xC0000004 || required < 4 || required > 16*1024*1024) return 20;
    snapshot = malloc(required);
    unsigned char *second = malloc(required);
    if (!snapshot || !second) return 12;
    for (unsigned i = 0; i < 4; ++i) {
        ULONG got = 0;
        memset(i ? second : snapshot, i & 1 ? 0x5A : 0xA5, required);
        if (query(189, i ? second : snapshot, required, &got) != 0 || got != required) return 22;
        if (i && memcmp(snapshot, second, required)) return 23;
    }
    FILE *binary = NULL;
    if (fopen_s(&binary, argv[2], "wb") || !binary) return 24;
    if (fwrite(snapshot, 1, required, binary) != required || fclose(binary)) return 25;
    returned_page = ((required + 4095) & ~4095UL) + 8192;
    arena = returned_page + 65536;
    pages = VirtualAlloc(NULL, arena + 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    model = malloc(arena);
    if (!pages || !model || identity("host", ntdll, &os)) return 12;
    protect(pages + arena, 4096, PAGE_NOACCESS);
    const ULONG lengths[] = {0,1,4,8,31,32,64,4096,required-1,required,required+1,required+4096,arena+1,0xFFFFFFFF};
    for (unsigned l = 0; l < sizeof(lengths)/sizeof(lengths[0]); ++l)
        for (unsigned output = 0; output < 18; ++output)
            for (unsigned returned = 0; returned < 13; ++returned) {
                int result = observe(output, returned, lengths[l], 0xA5);
                if (result) return result;
            }
    for (unsigned i = 0; i < 4; ++i) {
        int result = observe(0, i & 1, required, i & 2 ? 0x5A : 0xA5);
        if (result) return result;
    }
    if (!VirtualFree(pages, 0, MEM_RELEASE)) return 13;
    free(snapshot); free(second); free(model);
    printf("{\"kind\":\"finished\",\"records\":%lu}\n", records);
    return 0;
}
