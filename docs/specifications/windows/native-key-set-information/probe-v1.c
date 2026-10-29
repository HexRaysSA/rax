/* Private native control: only KeySetHandleTagsInformation and invalid classes.
 * No registry value, key, write-time, virtualization, or layer mutation. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG(NTAPI *SetKey)(HANDLE, ULONG, PVOID, ULONG);
typedef LONG(NTAPI *QueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *OpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef LONG(NTAPI *QueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static SetKey set_key;
static QueryKey query_key;
static OpenKey open_key;
static QueryObject query_object;
static unsigned char *pages;
static SIZE_T page;
static int first = 1;

static LONG open(HANDLE *out, ULONG access, ULONG view) {
    wchar_t text[] = L"\\Registry\\Machine";
    UNICODE_STRING name = {(USHORT)(sizeof text - 2), (USHORT)sizeof text, text};
    OBJECT_ATTRIBUTES attributes = {0};
    attributes.Length = (ULONG)sizeof attributes;
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40;
    return open_key(out, access | view, &attributes, 0);
}
static LONG tags(HANDLE key, ULONG *value) {
    ULONG returned = 0;
    *value = 0xcccccccc;
    LONG status = query_key(key, 7, value, 4, &returned);
    if (status == 0 && returned != 4) return (LONG)0xc0000001;
    return status;
}
static LONG invoke(HANDLE key, ULONG kind, PVOID data, ULONG length, DWORD *exception) {
    __try { return set_key(key, kind, data, length); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *exception = GetExceptionCode();
        return (LONG)*exception;
    }
}
static int protect(void *p, SIZE_T size, DWORD flags) {
    DWORD old;
    return VirtualProtect(p, size, flags, &old) != 0;
}
static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}
static int row(ULONG view, unsigned handle_kind, HANDLE key, HANDLE reset,
               HANDLE observer, ULONG kind, unsigned scenario, ULONG length, ULONG value) {
    ULONG zero = 0, before = 0, after = 0;
    if (set_key(reset, 5, &zero, 4) != 0 || tags(observer, &before) != 0) return 0;
    if (!protect(pages, page * 2, PAGE_READWRITE)) return 0;
    memset(pages, 0xa5, page * 2);
    unsigned char *input = pages + 64;
    SIZE_T watch = 48;
    DWORD flags = PAGE_READWRITE;
    if (scenario <= 7) input += scenario;
    else switch (scenario) {
    case 8: input = NULL; break;
    case 9: input = (void *)(uintptr_t)1; break;
    case 10: input = pages + page; flags = PAGE_NOACCESS; break;
    case 11: input = pages + page; flags = PAGE_READONLY; break;
    case 12: input = pages + page; flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 13: input = pages + page - 1; flags = PAGE_NOACCESS; break;
    case 14: input = pages + page - 2; flags = PAGE_NOACCESS; break;
    case 15: input = pages + page - 3; flags = PAGE_NOACCESS; break;
    case 16: input = pages + page - 4; flags = PAGE_NOACCESS; break;
    case 17: input = pages + page - 1; flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 18: input = pages + page - 4; flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 19: input = pages + page + 1; flags = PAGE_READWRITE | PAGE_GUARD; break;
    case 20: input = pages + page + 1; flags = PAGE_NOACCESS; break;
    case 21: input = pages + page - 2; flags = PAGE_READONLY; break;
    default: return 0;
    }
    if (scenario >= 10) watch = page - 16;
    if (scenario != 8 && scenario != 9) memcpy(input, &value, 4);
    unsigned char original[32];
    memcpy(original, pages + watch, sizeof original);
    if (!protect(pages + page, page, flags)) return 0;
    DWORD exception = 0;
    LONG status = invoke(key, kind, input, length, &exception);
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(pages + page, &info, sizeof info) != sizeof info) return 0;
    if (!protect(pages, page * 2, PAGE_READWRITE)) return 0;
    LONG queried = tags(observer, &after);
    printf("%s{\"view\":%lu,\"handle_kind\":%u,\"class\":%lu,\"scenario\":%u,"
           "\"length\":%lu,\"value\":%lu,\"input_alignment\":%zu,\"status\":%lu,"
           "\"exception\":%lu,\"before_tags\":%lu,\"query_status\":%lu,\"after_tags\":%lu,"
           "\"input_protection\":%lu,\"before_hex\":\"",
           first ? "" : ",", view, handle_kind, kind, scenario, length, value,
           (size_t)((uintptr_t)input % 8), (ULONG)status, exception, before,
           (ULONG)queried, after, info.Protect);
    first = 0;
    hex(original, sizeof original);
    printf("\",\"after_hex\":\""); hex(pages + watch, sizeof original); printf("\"}");
    return queried == 0 && memcmp(original, pages + watch, sizeof original) == 0;
}
static void life_row(ULONG view, const char *action, LONG status,
                     HANDLE original, HANDLE duplicate, HANDLE independent, HANDLE zero) {
    ULONG values[4];
    LONG codes[4] = {tags(original, &values[0]), tags(duplicate, &values[1]),
                     tags(independent, &values[2]), tags(zero, &values[3])};
    printf("%s{\"view\":%lu,\"action\":\"%s\",\"status\":%lu,\"queries\":[",
           first ? "" : ",", view, action, (ULONG)status);
    first = 0;
    for (unsigned i = 0; i < 4; ++i)
        printf("%s{\"status\":%lu,\"tags\":%lu}", i ? "," : "", (ULONG)codes[i], values[i]);
    printf("]}");
}
static int lifetime(ULONG view) {
    HANDLE original = NULL, duplicate = NULL, independent = NULL, zero = NULL;
    if (open(&original, KEY_READ, view) != 0 || open(&independent, KEY_READ, view) != 0) return 0;
    if (!DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &duplicate,
                         0, FALSE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &zero, 0, FALSE, 0)) return 0;
    life_row(view, "fresh", 0, original, duplicate, independent, zero);
    const ULONG values[] = {0x100, 0x200, 1, 2, 3, 0xffffffff, 0};
    for (unsigned i = 0; i < sizeof values / sizeof values[0]; ++i) {
        ULONG value = values[i];
        LONG status = set_key(i % 2 ? duplicate : original, 5, &value, 4);
        char action[32];
        sprintf_s(action, sizeof action, "set-%lu", value);
        life_row(view, action, status, original, duplicate, independent, zero);
    }
    for (unsigned low = 1; low <= 3; ++low) {
        ULONG value = 0x100 * low;
        HANDLE tagged = (HANDLE)((uintptr_t)original | low);
        LONG status = set_key(tagged, 5, &value, 4);
        char action[32];
        sprintf_s(action, sizeof action, "low-bits-%u", low);
        life_row(view, action, status, tagged, duplicate, independent, zero);
    }
    ULONG value = 0x100;
    LONG status = set_key(zero, 5, &value, 4);
    life_row(view, "set-zero-grant", status, original, duplicate, independent, zero);
    if (RegCloseKey((HKEY)original) != ERROR_SUCCESS) return 0;
    original = NULL;
    value = 0x200;
    status = set_key(duplicate, 5, &value, 4);
    life_row(view, "set-after-original-close", status, original, duplicate, independent, zero);
    if (RegCloseKey((HKEY)duplicate) != ERROR_SUCCESS || RegCloseKey((HKEY)zero) != ERROR_SUCCESS ||
        RegCloseKey((HKEY)independent) != ERROR_SUCCESS) return 0;
    if (open(&original, KEY_READ, view) != 0) return 0;
    life_row(view, "fresh-after-last-close", 0, original, NULL, NULL, NULL);
    return RegCloseKey((HKEY)original) == ERROR_SUCCESS;
}
int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
#define LOAD(target, name) do { FARPROC f = GetProcAddress(ntdll, name); \
    if (!f || sizeof f != sizeof target) return 10; memcpy(&target, &f, sizeof target); } while (0)
    LOAD(set_key, "NtSetInformationKey");
    LOAD(query_key, "NtQueryKey");
    LOAD(open_key, "NtOpenKeyEx");
    LOAD(query_object, "NtQueryObject");
    SYSTEM_INFO system; GetSystemInfo(&system); page = system.dwPageSize;
    if (page != 4096) return 11;
    pages = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages) return 12;
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 13;
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!event) return 14;
    HANDLE keys[2][5] = {{0}};
    ULONG access[] = {KEY_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, 0};
    printf("{\"pointer_bytes\":%zu,\"page_size\":%zu,\"handles_before\":%lu,\"opens\":[", sizeof(void *), page, before);
    for (unsigned v = 0; v < 2; ++v) for (unsigned k = 0; k < 5; ++k) {
        ULONG view = v ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;
        LONG status = k < 4 ? open(&keys[v][k], access[k], view) : 0;
        if (k == 4 && !DuplicateHandle(GetCurrentProcess(), keys[v][0], GetCurrentProcess(),
                                       &keys[v][k], 0, FALSE, 0)) return 15;
        if (status != 0 || !keys[v][k]) return 16;
        union { uint64_t alignment[7]; ULONG words[14]; } basic = {{0}};
        ULONG returned = 0;
        if (query_object(keys[v][k], 0, &basic, (ULONG)sizeof basic, &returned) != 0 ||
            returned != sizeof basic || basic.words[1] != access[k]) return 17;
        printf("%s{\"view\":%lu,\"handle_kind\":%u,\"access\":%lu}", v || k ? "," : "", view, k, access[k]);
    }
    printf("],\"rows\":[");
    const ULONG values[] = {0, 1, 2, 3, 0x100, 0x200, 0x300, 0xffff, 0xffffffff, 0x10000, 0x10001, 0x12345678, 0x80000000, 0xffff0000, 0xffff00ff};
    const ULONG lengths[] = {0, 1, 3, 4, 5, 8, 16};
    const ULONG classes[] = {5, 7, 0xffffffff};
    for (unsigned v = 0; v < 2; ++v) {
        ULONG view = v ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;
        for (unsigned n = 0; n < sizeof values / sizeof values[0]; ++n)
            for (unsigned offset = 0; offset < 8; ++offset)
                for (unsigned length = 0; length < sizeof lengths / sizeof lengths[0]; ++length)
                    if (!row(view, 0, keys[v][0], keys[v][0], keys[v][0], 5, offset, lengths[length], values[n])) return 18;
        for (unsigned bit = 0; bit < 32; ++bit) {
            ULONG single = (ULONG)1 << bit;
            if (!row(view, 0, keys[v][0], keys[v][0], keys[v][0], 5, 0, 4, single) ||
                !row(view, 0, keys[v][0], keys[v][0], keys[v][0], 5, 0, 4, ~single)) return 25;
        }
        for (unsigned k = 0; k < 9; ++k) {
            HANDLE key = k < 5 ? keys[v][k] : k == 5 ? NULL : k == 6 ? event : k == 7 ? GetCurrentProcess() : GetCurrentThread();
            HANDLE observer = k < 4 ? key : keys[v][0];
            for (unsigned scenario = 0; scenario < 22; ++scenario)
                for (unsigned kind = 0; kind < 3; ++kind)
                    for (unsigned n = 0; n < 3; ++n) {
                        ULONG length = n == 0 ? 0 : n == 1 ? 4 : 8;
                        if (!row(view, k, key, k < 4 ? key : keys[v][0], observer, classes[kind], scenario, length, 0x100)) return 19;
                    }
        }
    }
    for (unsigned v = 0; v < 2; ++v) for (unsigned k = 0; k < 5; ++k)
        if (RegCloseKey((HKEY)keys[v][k]) != ERROR_SUCCESS) return 20;
    printf("],\"lifetime\":["); first = 1;
    if (!lifetime(KEY_WOW64_64KEY) || !lifetime(KEY_WOW64_32KEY)) return 21;
    if (!CloseHandle(event) || !VirtualFree(pages, 0, MEM_RELEASE)) return 22;
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 23;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after ? 0 : 24;
}
