/* Relative-open consequences of guest key-body tag replacement.
 * Only the probe's own handle tags change; registry contents remain read-only. */
#define main input_matrix_main
#include "probe-v1.c"
#undef main

static const wchar_t *subjects[] = {
    L"\\Registry\\Machine",
    L"\\Registry\\Machine",
    L"\\Registry\\Machine\\Software\\Microsoft\\Command Processor",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage",
    L"\\Registry\\Machine\\Software\\Microsoft\\AppModel\\Lookaside\\machine",
    L"\\Registry\\Machine\\Software\\Microsoft\\OLE",
    L"\\Registry\\Machine",
    L"\\Registry\\Machine"
};

static LONG named_open(HANDLE *out, HANDLE root, const wchar_t *text, ULONG access) {
    size_t n = wcslen(text);
    if (n > 32766) return (LONG)0xc000000d;
    UNICODE_STRING name = {(USHORT)(n * 2), (USHORT)(n * 2 + 2), (wchar_t *)text};
    OBJECT_ATTRIBUTES attributes = {0};
    attributes.Length = (ULONG)sizeof attributes;
    attributes.RootDirectory = root;
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40;
    return open_key(out, access, &attributes, 0);
}

static LONG canonical(HANDLE key, unsigned char *out, ULONG *length) {
    ULONG returned = 0;
    memset(out, 0xa5, 4096);
    LONG status = query_key(key, 3, out, 4096, &returned);
    if (status == 0) {
        ULONG size = 0;
        memcpy(&size, out, 4);
        if (size > 4092 || returned != size + 4) return (LONG)0xc0000001;
        *length = size + 4;
    } else {
        *length = 0;
    }
    return status;
}

static ULONG granted(HANDLE key) {
    union { uint64_t align[7]; ULONG words[14]; } basic = {{0}};
    ULONG returned = 0;
    if (query_object(key, 0, &basic, (ULONG)sizeof basic, &returned) != 0 ||
        returned != sizeof basic) return 0xffffffff;
    return basic.words[1];
}

static int hive_roots(void) {
    const wchar_t *paths[] = {
        L"\\Registry\\Machine", L"\\Registry\\User\\.Default", L"\\Registry\\User\\S-1-5-18"
    };
    printf("\"hives\":[");
    int comma = 0;
    for (unsigned subject = 0; subject < 3; ++subject)
    for (unsigned view = 0; view < 4; ++view) {
        HANDLE key = NULL;
        LONG status = named_open(&key, NULL, paths[subject], KEY_READ | (view << 8));
        ULONG value = 0;
        LONG query = 0;
        if (status == 0) {
            query = tags(key, &value);
            if (RegCloseKey((HKEY)key) != ERROR_SUCCESS) return 0;
        } else if (key) return 0;
        printf("%s{\"subject\":%u,\"view\":%u,\"status\":%lu,\"query\":%lu,\"tags\":%lu}",
               comma ? "," : "", subject, view << 8, (ULONG)status, (ULONG)query, value);
        comma = 1;
    }
    printf("]");
    return 1;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    LOAD(set_key, "NtSetInformationKey");
    LOAD(query_key, "NtQueryKey");
    LOAD(open_key, "NtOpenKeyEx");
    LOAD(query_object, "NtQueryObject");
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 30;
    ULONG values[182];
    unsigned count = 0;
    for (unsigned i = 0; i < 16; ++i) values[count++] = i << 8;
    for (unsigned i = 0; i < 16; ++i) {
        values[count++] = (ULONG)1 << i;
        values[count++] = ~((ULONG)1 << i) & 0xffff;
    }
    const ULONG mixed[] = {0xffff, 0xffffffff, 0x12345678, 0xffff0000, 0xffff00ff, 0x30000};
    for (unsigned i = 0; i < 6; ++i) values[count++] = mixed[i];
    const ULONG payloads[] = {0, 1, 2, 0x55, 0xaa, 0x1000, 0x7000, 0xf0ff};
    for (unsigned flags = 0; flags < 16; ++flags)
        for (unsigned i = 0; i < 8; ++i) values[count++] = (flags << 8) | payloads[i];
    if (count != 182) return 31;
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[", sizeof(void *), before);
    int comma = 0;
    for (unsigned subject = 0; subject < 8; ++subject)
    for (unsigned v = 0; v < 2; ++v)
    for (unsigned i = 0; i < count; ++i)
    for (unsigned request = 0; request < 4; ++request) {
        ULONG view = v ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;
        ULONG desired = request << 8, value = values[i];
        HANDLE root = NULL;
        LONG root_status = named_open(&root, NULL, subjects[subject], KEY_READ | view);
        printf("%s{\"subject\":%u,\"parent_view\":%lu,\"tag\":%lu,\"requested\":%lu,\"root_status\":%lu",
               comma ? "," : "", subject, view, value, desired, (ULONG)root_status);
        comma = 1;
        if (root_status != 0) {
            if (root) return 32;
            printf("}");
            continue;
        }
        unsigned char root_name[4096], root_after[4096], child_name[4096];
        ULONG rn = 0, ra = 0, cn = 0;
        if (canonical(root, root_name, &rn) != 0) return 33;
        ULONG root_access = granted(root), root_after_set = 0;
        LONG set_status = set_key(root, 5, &value, 4);
        if (set_status != 0 || tags(root, &root_after_set) != 0 ||
            root_after_set != (value & 0xffff)) return 34;
        const wchar_t *suffix = subject == 0 ? L"SOFTWARE\\Microsoft\\Command Processor" :
            subject == 6 ? L"SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage" :
            subject == 7 ? L"SOFTWARE\\Microsoft\\OLE" : L"";
        HANDLE child = NULL;
        LONG child_status = named_open(&child, root, suffix, KEY_READ | desired);
        ULONG root_after_open = 0, child_tags = 0, child_access = 0;
        ULONG root_after_write = 0, child_after_write = 0, write_value = 0, root_after_close = 0;
        LONG name_status = 0, write_status = 0;
        if (tags(root, &root_after_open) != 0) return 35;
        if (child_status == 0) {
            name_status = canonical(child, child_name, &cn);
            if (name_status != 0 || tags(child, &child_tags) != 0) return 36;
            child_access = granted(child);
            write_value = root_after_open ^ 0xffff;
            write_status = set_key(child, 5, &write_value, 4);
            if (write_status != 0 || tags(root, &root_after_write) != 0 ||
                tags(child, &child_after_write) != 0) return 37;
            if (RegCloseKey((HKEY)child) != ERROR_SUCCESS) return 38;
        } else {
            if (child) return 39;
            root_after_write = root_after_open;
        }
        if (tags(root, &root_after_close) != 0 || canonical(root, root_after, &ra) != 0 ||
            rn != ra || memcmp(root_name, root_after, rn) || root_access != granted(root)) return 40;
        printf(",\"set_status\":%lu,\"root_after_set\":%lu,\"open_status\":%lu,\"name_status\":%lu,"
               "\"root_access\":%lu,\"child_access\":%lu,\"root_after_open\":%lu,\"child_tags\":%lu,"
               "\"child_write_value\":%lu,\"child_write_status\":%lu,\"root_after_write\":%lu,"
               "\"child_after_write\":%lu,\"root_after_close\":%lu,\"root_name_hex\":\"",
               (ULONG)set_status, root_after_set, (ULONG)child_status, (ULONG)name_status,
               root_access, child_access, root_after_open, child_tags, write_value,
               (ULONG)write_status, root_after_write, child_after_write, root_after_close);
        hex(root_name, rn);
        printf("\",\"child_name_hex\":\"");
        hex(child_name, cn);
        printf("\"}");
        if (RegCloseKey((HKEY)root) != ERROR_SUCCESS) return 41;
    }
    printf("],");
    if (!hive_roots()) return 44;
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 42;
    printf(",\"handles_after\":%lu}\n", after);
    return before == after ? 0 : 43;
}
