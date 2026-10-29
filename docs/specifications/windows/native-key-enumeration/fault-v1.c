#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef LONG(NTAPI *EnumKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *OpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef LONG(NTAPI *QueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static QueryObject query_object;
static EnumKey enumerate_key;
static OpenKey open_key;
static unsigned char *output_pages, *result_pages;
static SIZE_T page;
static int first_row = 1;
struct ChildRecord { wchar_t name[256]; DWORD units; FILETIME time; };
static struct ChildRecord records[2][1024];
static DWORD child_counts[2];

static int metadata(HKEY key, unsigned view, int verify) {
    DWORD count = 0, maximum = 0;
    if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &count, &maximum, NULL,
                        NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS ||
        count > 1024 || maximum > 255 || (verify && count != child_counts[view])) return 0;
    if (!verify) child_counts[view] = count;
    for (DWORD index = 0; index < count; ++index) {
        struct ChildRecord actual = {0}; actual.units = 256;
        if (RegEnumKeyExW(key, index, actual.name, &actual.units, NULL, NULL, NULL,
                          &actual.time) != ERROR_SUCCESS || actual.units > 255) return 0;
        struct ChildRecord *before = &records[view][index];
        if (verify) {
            if (before->units != actual.units ||
                memcmp(before->name, actual.name, actual.units * sizeof(wchar_t)) ||
                before->time.dwLowDateTime != actual.time.dwLowDateTime ||
                before->time.dwHighDateTime != actual.time.dwHighDateTime) return 0;
        } else *before = actual;
    }
    return 1;
}

static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}
static LONG invoke(HANDLE key, ULONG index, ULONG kind, void *out, ULONG length,
                   ULONG *returned, DWORD *exception) {
    __try { return enumerate_key(key, index, kind, out, length, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *exception = GetExceptionCode(); return (LONG)*exception;
    }
}
static int protect(void *p, SIZE_T length, DWORD flags) {
    DWORD old;
    return VirtualProtect(p, length, flags, &old) != 0;
}
static DWORD protection(void *p) {
    MEMORY_BASIC_INFORMATION info;
    return VirtualQuery(p, &info, sizeof info) == sizeof info ? info.Protect : 0;
}
static int row(unsigned view, unsigned handle_kind, HANDLE key, ULONG index,
               ULONG kind, unsigned scenario, ULONG length) {
    if (!protect(output_pages, page * 2, PAGE_READWRITE) ||
        !protect(result_pages, page * 2, PAGE_READWRITE)) return 0;
    memset(output_pages, 0xa5, page * 2);
    memset(result_pages, 0xcc, page * 2);
    void *out = output_pages + 64;
    ULONG *returned = (ULONG *)(result_pages + 64);
    SIZE_T out_watch = 32, result_watch = 48;
    DWORD output_flags = PAGE_READWRITE, result_flags = PAGE_READWRITE;
    switch (scenario) {
    case 1: out = output_pages + 65; break;
    case 2: out = output_pages + 68; break;
    case 3: out = NULL; break;
    case 4: out = (void *)(uintptr_t)1; break;
    case 5: out = output_pages + page; output_flags = PAGE_NOACCESS; break;
    case 6: out = output_pages + page; output_flags = PAGE_READONLY; break;
    case 7: out = output_pages + page; output_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 8: out = output_pages + page - 16; output_flags = PAGE_NOACCESS; break;
    case 9: out = output_pages + page - 16; output_flags = PAGE_READONLY; break;
    case 10: out = output_pages + page - 16; output_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 11: returned = (ULONG *)(result_pages + 65); break;
    case 12: returned = (ULONG *)(result_pages + 67); break;
    case 13: returned = NULL; break;
    case 14: returned = (ULONG *)(uintptr_t)1; break;
    case 15: returned = (ULONG *)(result_pages + page); result_flags = PAGE_NOACCESS; break;
    case 16: returned = (ULONG *)(result_pages + page); result_flags = PAGE_READONLY; break;
    case 17: returned = (ULONG *)(result_pages + page); result_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 18: returned = (ULONG *)(result_pages + page - 2); result_flags = PAGE_NOACCESS; break;
    case 19: returned = (ULONG *)(result_pages + page - 2); result_flags = PAGE_READONLY; break;
    case 20: returned = (ULONG *)(result_pages + page - 2); result_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 21: returned = (ULONG *)out; break;
    case 22: returned = (ULONG *)((unsigned char *)out + 8); break;
    case 23: returned = (ULONG *)((unsigned char *)out + 14); break;
    case 24: out = output_pages + 71; break;
    case 25: out = NULL; returned = NULL; break;
    case 26: out = output_pages + page + 1; output_flags = PAGE_NOACCESS; break;
    case 27: out = output_pages + page + 1; output_flags = PAGE_READONLY; break;
    case 28: out = output_pages + page + 1; output_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 29: out = output_pages + page - 1; output_flags = PAGE_NOACCESS; break;
    case 30: out = output_pages + page - 1; output_flags = PAGE_READONLY; break;
    case 31: out = output_pages + page - 1; output_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 32: out = output_pages + page - 4; output_flags = PAGE_NOACCESS; break;
    case 33: out = output_pages + page - 4; output_flags = PAGE_READONLY; break;
    case 34: out = output_pages + page - 4; output_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 35: out = output_pages + 65; returned = (ULONG *)(result_pages + page); result_flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 36: out = output_pages + 65; returned = NULL; break;
    case 37: out = output_pages + 65; returned = (ULONG *)(result_pages + page); result_flags = PAGE_NOACCESS; break;
    case 38: out = output_pages + 65; returned = (ULONG *)(result_pages + page - 2); result_flags = PAGE_NOACCESS; break;
    case 39: out = output_pages + 65; returned = (ULONG *)out; break;
    case 40: out = output_pages + 65; returned = (ULONG *)((unsigned char *)out + 14); break;
    default: break;
    }
    if (scenario >= 5 && scenario <= 10) out_watch = page - 64;
    if (scenario >= 15 && scenario <= 20) result_watch = page - 16;
    if (scenario >= 26 && scenario <= 34) out_watch = page - 64;
    if (scenario >= 35 && scenario <= 38 && scenario != 36) result_watch = page - 16;
    if (!protect(output_pages + page, page, output_flags) ||
        !protect(result_pages + page, page, result_flags)) return 0;
    DWORD exception = 0;
    LONG status = invoke(key, index, kind, out, length, returned, &exception);
    DWORD output_after = protection(output_pages + page);
    DWORD result_after = protection(result_pages + page);
    if (!output_after || !result_after ||
        !protect(output_pages, page * 2, PAGE_READWRITE) ||
        !protect(result_pages, page * 2, PAGE_READWRITE)) return 0;
    printf("%s{\"view\":%u,\"handle_kind\":%u,\"index\":%lu,\"class\":%lu,"
           "\"scenario\":%u,\"length\":%lu,\"status\":%lu,\"exception\":%lu,"
           "\"output_protection\":%lu,\"result_protection\":%lu,"
           "\"out_watch\":%zu,\"result_watch\":%zu,\"buffer_hex\":\"",
           first_row ? "" : ",", view, handle_kind, index, kind, scenario, length,
           (ULONG)status, exception, output_after, result_after, out_watch, result_watch);
    first_row = 0; hex(output_pages + out_watch, 384);
    printf("\",\"result_hex\":\""); hex(result_pages + result_watch, 32); printf("\"}");
    return 1;
}
static LONG open(HANDLE *out, ULONG access, unsigned view) {
    wchar_t text[] = L"\\Registry\\Machine";
    UNICODE_STRING name = {(USHORT)(sizeof text - 2), (USHORT)sizeof text, text};
    OBJECT_ATTRIBUTES attributes = {0};
    attributes.Length = (ULONG)sizeof attributes;
    attributes.ObjectName = &name; attributes.Attributes = 0x40;
    return open_key(out, access | view, &attributes, 0);
}
int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC function = GetProcAddress(ntdll, "NtEnumerateKey");
    if (!function || sizeof function != sizeof enumerate_key) return 10;
    memcpy(&enumerate_key, &function, sizeof enumerate_key);
    function = GetProcAddress(ntdll, "NtOpenKeyEx");
    if (!function || sizeof function != sizeof open_key) return 11;
    memcpy(&open_key, &function, sizeof open_key);
    function = GetProcAddress(ntdll, "NtQueryObject");
    if (!function || sizeof function != sizeof query_object) return 23;
    memcpy(&query_object, &function, sizeof query_object);
    SYSTEM_INFO info; GetSystemInfo(&info); page = info.dwPageSize;
    if (page < 4096 || page > 65536) return 12;
    output_pages = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    result_pages = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!output_pages || !result_pages) return 13;
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 14;
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!event) return 15;
    HANDLE keys[2][5] = {{0}};
    const ULONG access[] = {KEY_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, 0};
    printf("{\"pointer_bytes\":%zu,\"page_size\":%zu,\"handles_before\":%lu,\"opens\":[", sizeof(void *), page, before);
    for (unsigned view = 0; view < 2; ++view) {
        for (unsigned k = 0; k < 5; ++k) {
            ULONG flag = view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
            LONG status = open(&keys[view][k], access[k], flag);
            if (k == 4) {
                /* Record the direct zero-access open result independently;
                   duplicate a valid owned key to obtain a verified zero grant. */
                if (keys[view][k] && RegCloseKey((HKEY)keys[view][k]) != ERROR_SUCCESS) return 25;
                keys[view][k] = NULL;
                if (!DuplicateHandle(GetCurrentProcess(), keys[view][0], GetCurrentProcess(),
                                     &keys[view][k], 0, FALSE, 0)) return 26;
            } else if (status != 0 || !keys[view][k]) return 16;
            union { uint64_t align[7]; ULONG words[14]; } basic = {{0}};
            ULONG returned = 0;
            if (query_object(keys[view][k], 0, &basic, (ULONG)sizeof basic, &returned) != 0 ||
                returned != sizeof basic) return 24;
            printf("%s{\"view\":%lu,\"handle_kind\":%u,\"access\":%lu,\"status\":%lu,\"granted\":%lu}",
                   view || k ? "," : "", flag, k, access[k], (ULONG)status, basic.words[1]);
            if (basic.words[1] != access[k]) return 27;
        }
    }
    printf("],\"roots\":[");
    for (unsigned view = 0; view < 2; ++view) {
        if (!metadata((HKEY)keys[view][0], view, 0) || child_counts[view] == 0) return 28;
        printf("%s{\"view\":%u,\"names\":[", view ? "," : "", view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY);
        for (DWORD index = 0; index < child_counts[view]; ++index) {
            struct ChildRecord *child = &records[view][index];
            printf("%s{\"index\":%lu,\"name_hex\":\"", index ? "," : "", index);
            hex((const unsigned char *)child->name, child->units * 2);
            printf("\",\"last_write_hex\":\""); hex((const unsigned char *)&child->time, 8); printf("\"}");
        }
        printf("]}");
    }
    printf("],\"rows\":[");
    static const ULONG lengths[] = {0, 15, 16, 17, 26, 288};
    static const unsigned priorities[] = {0, 1, 3, 5, 6, 7, 8, 13, 17, 18, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38};
    for (unsigned v = 0; v < 2; ++v) {
        unsigned view = v == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
        for (unsigned scenario = 0; scenario <= 40; ++scenario)
            for (size_t l = 0; l < sizeof lengths / sizeof lengths[0]; ++l)
                if (!row(view, 0, keys[v][0], 0, 0, scenario, lengths[l])) return 17;
        for (unsigned k = 0; k < 9; ++k) {
            HANDLE handle = k < 5 ? keys[v][k] : k == 5 ? NULL : k == 6 ? event : k == 7 ? GetCurrentProcess() : GetCurrentThread();
            for (size_t p = 0; p < sizeof priorities / sizeof priorities[0]; ++p)
                for (unsigned invalid_class = 0; invalid_class < 2; ++invalid_class)
                    for (unsigned invalid_index = 0; invalid_index < 2; ++invalid_index)
                        for (unsigned l = 0; l < 3; ++l) {
                            ULONG length = l == 0 ? 0 : l == 1 ? 16 : 288;
                            if (!row(view, k, handle, invalid_index ? 0xffffffff : 0,
                                     invalid_class ? 3 : 0, priorities[p], length)) return 18;
                        }
        }
    }
    for (unsigned v = 0; v < 2; ++v)
        if (!metadata((HKEY)keys[v][0], v, 1)) return 29;
    for (unsigned v = 0; v < 2; ++v)
        for (unsigned k = 0; k < 5; ++k)
            if (RegCloseKey((HKEY)keys[v][k]) != ERROR_SUCCESS) return 19;
    if (!CloseHandle(event) || !VirtualFree(output_pages, 0, MEM_RELEASE) ||
        !VirtualFree(result_pages, 0, MEM_RELEASE)) return 20;
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 21;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after && !first_row ? 0 : 22;
}
