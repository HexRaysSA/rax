#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LONG (NTAPI *QueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
_Static_assert(TokenStatistics == 10, "TokenStatistics selector");
_Static_assert(sizeof(TOKEN_STATISTICS) == 56, "TokenStatistics wire width");
static HANDLE handles[14];
__declspec(align(8)) static unsigned char samples[2][56];
static unsigned handle_role;
static unsigned boundary;
static const char *phase;
typedef LONG (NTAPI *GetStatusFn)(void);
typedef VOID (NTAPI *SetStatusFn)(LONG);
static GetStatusFn get_status;
static SetStatusFn set_status;
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);
static QueryFn query;
static unsigned char *pages, *model;
static ULONG required = 56, returned_page, arena, records;

static void protect(void *address, SIZE_T size, DWORD flags) {
    DWORD previous;
    if (!VirtualProtect(address, size, flags, &previous)) ExitProcess(16);
}

static int identity(const char *kind, HMODULE module, const RTL_OSVERSIONINFOW *os) {
    wchar_t logical[1024], mapped[1024];
    DWORD a = GetModuleFileNameW(module, logical, 1024);
    DWORD b = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
    if (!a || a >= 1024 || !b || b >= 1024) return 18;
    printf("{\"kind\":\"%s\",\"schema\":\"rax-native-token-statistics-v1\","
           "\"pointer_bytes\":%zu,\"required\":%lu,\"arena\":%lu,\"returned_page\":%lu,"
           "\"kernel\":[%lu,%lu,%lu],\"provider_utf16\":\"", kind, sizeof(void *),
           required, arena, returned_page, os->dwMajorVersion, os->dwMinorVersion, os->dwBuildNumber);
    for (DWORD i = 0; i < a; ++i) printf("%02x%02x", logical[i] & 255, logical[i] >> 8);
    printf("\",\"mapped_provider_utf16\":\"");
    for (DWORD i = 0; i < b; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\",\"layout_offsets\":[%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu]}\n",
           offsetof(TOKEN_STATISTICS, TokenId), offsetof(TOKEN_STATISTICS, AuthenticationId),
           offsetof(TOKEN_STATISTICS, ExpirationTime), offsetof(TOKEN_STATISTICS, TokenType),
           offsetof(TOKEN_STATISTICS, ImpersonationLevel), offsetof(TOKEN_STATISTICS, DynamicCharged),
           offsetof(TOKEN_STATISTICS, DynamicAvailable), offsetof(TOKEN_STATISTICS, GroupCount),
           offsetof(TOKEN_STATISTICS, PrivilegeCount), offsetof(TOKEN_STATISTICS, ModifiedId));
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
    case 8: case 9: case 10: case 18:
        output_offset = 4096 - (boundary ? boundary : 4); output = pages + output_offset;
        protect(pages + 4096, 4096, output_role == 8 ? PAGE_NOACCESS :
                output_role == 9 ? PAGE_READWRITE | PAGE_GUARD :
                output_role == 18 ? PAGE_READONLY | PAGE_GUARD : PAGE_READONLY);
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
    set_status((LONG)0xC0000034);
    SetLastError(0x12345678);
    __try { status = query(handles[handle_role], 10, output, length, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
    const DWORD last_error = GetLastError();
    const LONG last_status = get_status();
    for (unsigned i = 0; i < 6; ++i)
        if (!VirtualQuery(pages + watched[i], &regions[i], sizeof(regions[i]))) return 5;
    protect(pages, arena, PAGE_READWRITE);

    /* Lossless representation of the entire arena: poison, the actual 56-byte
       output window and eight actual ReturnLength bytes. This also preserves
       non-prefix partial stores without assuming a copy implementation. */
    ULONG copied = 0;
    for (ULONG i = 0; i < required; ++i) {
        ULONG at = output_offset + i;
        if (at >= returned_offset && at < returned_offset + 8) continue;
        if (pages[at] != poison) copied = i + 1;
    }
    memset(model, poison, arena);
    memcpy(model + output_offset, pages + output_offset, required);
    memcpy(model + returned_offset, pages + returned_offset, 8);
    if (memcmp(model, pages, arena)) {
        ULONG at = 0; while (at < arena && model[at] == pages[at]) ++at;
        fprintf(stderr, "unrepresented store: case=%lu out=%u ret=%u len=%lu copied=%lu offset=%lu actual=%u represented=%u\n",
                records, output_role, returned_role, length, copied, at, pages[at], model[at]);
        return 21;
    }
    printf("{\"kind\":\"case\",\"index\":%lu,\"output\":%u,\"returned\":%u,\"length\":%lu,"
           "\"poison\":%u,\"status\":%lu,\"exception\":%lu,\"handle\":%u,\"phase\":\"%s\","
           "\"last_error\":%lu,\"last_status\":%lu,\"boundary\":%u,\"protections\":[",
           records, output_role, returned_role, length, poison, (ULONG)status, (ULONG)exception,
           handle_role, phase, last_error, (ULONG)last_status, boundary);
    for (unsigned i = 0; i < 6; ++i) printf("%s%lu", i ? "," : "", regions[i].Protect);
    printf("],\"changed_output_extent\":%lu,\"arena_reconstruction_verified\":true,\"returned_bytes\":\"", copied);
    for (unsigned i = 0; i < 8; ++i) printf("%02x", pages[returned_offset + i]);
    printf("\",\"output_bytes\":\"");
    for (ULONG i = 0; i < required; ++i) printf("%02x", pages[output_offset + i]);
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
    query = (QueryFn)GetProcAddress(ntdll, "NtQueryInformationToken");
    get_status = (GetStatusFn)GetProcAddress(ntdll, "RtlGetLastNtStatus");
    set_status = (SetStatusFn)GetProcAddress(ntdll, "RtlSetLastWin32ErrorAndNtStatusFromNtStatus");
    if (!version || !query || !get_status || !set_status || version(&os) < 0) return 10;
    GetSystemInfo(&system);
    if (system.dwPageSize != 4096) return 19;
    if (argc == 2 && !strcmp(argv[1], "--identity")) return identity("identity", ntdll, &os);
    if (argc != 3 || strcmp(argv[1], "--run")) return 11;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &handles[0])) return 26;
    handles[1] = NULL;
    handles[2] = (HANDLE)(uintptr_t)0xDEADBEEF;
    handles[3] = GetCurrentProcess();
    handles[4] = GetCurrentThread();
    handles[5] = (HANDLE)(intptr_t)-4;
    handles[6] = (HANDLE)(intptr_t)-5;
    handles[7] = (HANDLE)(intptr_t)-6;
    if (!DuplicateHandle(GetCurrentProcess(), handles[0], GetCurrentProcess(), &handles[8], 0, FALSE, 0)) return 27;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY_SOURCE, &handles[9])) return 28;
    handles[10] = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!handles[10]) return 29;
    if (!DuplicateTokenEx(handles[0], TOKEN_QUERY, NULL, SecurityImpersonation, TokenImpersonation, &handles[11])) return 30;
    if (!DuplicateHandle(GetCurrentProcess(), handles[0], GetCurrentProcess(), &handles[12], TOKEN_QUERY, FALSE, 0)) return 31;
    if (!OpenProcessToken(GetCurrentProcess(), READ_CONTROL, &handles[13])) return 32;
    const unsigned subjects[] = {0, 11};
    for (unsigned subject = 0; subject < 2; ++subject) {
        __declspec(align(8)) unsigned char second[56];
        ULONG got = 0;
        if ((ULONG)query(handles[subjects[subject]], 10, NULL, 0, &got) != 0xC0000023 || got != required) return 20;
        for (unsigned i = 0; i < 4; ++i) {
            unsigned char *out = i ? second : samples[subject];
            memset(out, i & 1 ? 0x5A : 0xA5, required);
            got = 0;
            if (query(handles[subjects[subject]], 10, out, required, &got) != 0 || got != required) return 22;
            if (i && memcmp(samples[subject], second, required)) return 23;
        }
    }
    FILE *binary = NULL;
    if (fopen_s(&binary, argv[2], "wb") || !binary) return 24;
    if (fwrite(samples, 1, sizeof(samples), binary) != sizeof(samples) || fclose(binary)) return 25;
    returned_page = 12288;
    arena = returned_page + 65536;
    pages = VirtualAlloc(NULL, arena + 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    model = malloc(arena);
    if (!pages || !model || identity("host", ntdll, &os)) return 12;
    protect(pages + arena, 4096, PAGE_NOACCESS);
    phase = "matrix";
    const ULONG lengths[] = {0,1,4,8,55,56,57,63,64,4096,8192,arena+1,0xFFFFFFFF};
    for (unsigned subject = 0; subject < 2; ++subject) {
        handle_role = subjects[subject];
        for (unsigned l = 0; l < sizeof(lengths)/sizeof(lengths[0]); ++l)
            for (unsigned output = 0; output < 18; ++output)
                for (unsigned returned = 0; returned < 13; ++returned) {
                    int result = observe(output, returned, lengths[l], 0xA5);
                    if (result) return result;
                }
    }
    phase = "handles";
    const ULONG handle_lengths[] = {0,55,56,57};
    const unsigned outputs[] = {0,1,3,5,6}, returns[] = {0,1,2,5};
    for (handle_role = 0; handle_role < 14; ++handle_role)
        for (unsigned l = 0; l < 4; ++l)
            for (unsigned o = 0; o < 5; ++o)
                for (unsigned v = 0; v < 4; ++v) {
                    int result = observe(outputs[o], returns[v], handle_lengths[l], 0xA5);
                    if (result) return result;
                }
    phase = "controls";
    for (unsigned subject = 0; subject < 2; ++subject) {
        handle_role = subjects[subject];
        for (unsigned i = 0; i < 4; ++i) {
            int result = observe(0, i & 1, required, i & 2 ? 0x5A : 0xA5);
            if (result) return result;
        }
    }
    phase = "copy_boundaries";
    const unsigned protections[] = {8,9,10,18}, boundary_returns[] = {0,1,4,5,12};
    for (unsigned subject = 0; subject < 2; ++subject) {
        handle_role = subjects[subject];
        for (boundary = 1; boundary < required; ++boundary)
            for (unsigned p = 0; p < 4; ++p)
                for (unsigned v = 0; v < 5; ++v) {
                    int result = observe(protections[p], boundary_returns[v], required, 0xA5);
                    if (result) return result;
                }
    }
    if (!VirtualFree(pages, 0, MEM_RELEASE)) return 13;
    free(model);
    const unsigned owned[] = {0,8,9,10,11,12,13};
    for (unsigned i = 0; i < sizeof(owned)/sizeof(owned[0]); ++i)
        if (!CloseHandle(handles[owned[i]])) return 33;
    printf("{\"kind\":\"finished\",\"records\":%lu}\n", records);
    return 0;
}
