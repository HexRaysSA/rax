#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef LONG(NTAPI *EnumKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *OpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
static EnumKey enumerate_key;
static OpenKey open_key;
static int first_row = 1;

static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}
static LONG invoke(HKEY key, ULONG index, ULONG kind, void *out, ULONG length,
                   ULONG *returned, DWORD *exception) {
    __try {
        return enumerate_key(key, index, kind, out, length, returned);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *exception = GetExceptionCode();
        return (LONG)*exception;
    }
}
static void row(unsigned root, unsigned view, HKEY key, ULONG index, ULONG kind,
                unsigned offset, ULONG length) {
    __declspec(align(16)) union { uint64_t aligned[48]; unsigned char bytes[384]; } buffer;
    if (((uintptr_t)buffer.bytes & 15) != 0) exit(21);
    memset(&buffer, 0xa5, sizeof buffer);
    ULONG returned = 0xcccccccc;
    DWORD exception = 0;
    LONG status = invoke(key, index, kind, buffer.bytes + offset, length,
                         &returned, &exception);
    printf("%s{\"root\":%u,\"view\":%u,\"index\":%lu,\"class\":%lu,"
           "\"offset\":%u,\"length\":%lu,\"status\":%lu,\"exception\":%lu,"
           "\"returned\":%lu,\"output_alignment\":%u,\"result_alignment\":%u,\"buffer_hex\":\"",
           first_row ? "" : ",", root, view, index, kind, offset, length,
           (ULONG)status, exception, returned,
           (unsigned)(((uintptr_t)buffer.bytes + offset) & 7),
           (unsigned)((uintptr_t)&returned & 7));
    first_row = 0;
    hex(buffer.bytes, sizeof buffer.bytes);
    printf("\"}");
}
int main(void) {
    static const wchar_t *paths[] = {
        L"", L"Software\\Microsoft\\Command Processor",
        L"Software\\Microsoft\\Command Processor\\KnownPackageManagers"
    };
    static const ULONG lengths[] = {
        0, 1, 7, 8, 12, 15, 16, 17, 18, 19, 20, 23, 24, 25, 28, 31, 32, 287, 288, 320
    };
    HKEY keys[3][2] = {{0}};
    DWORD counts[3][2] = {{0}};
    DWORD before = 0, after = 0;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC function = GetProcAddress(ntdll, "NtEnumerateKey");
    if (!function || sizeof function != sizeof enumerate_key) return 10;
    memcpy(&enumerate_key, &function, sizeof enumerate_key);
    function = GetProcAddress(ntdll, "NtOpenKeyEx");
    if (!function || sizeof function != sizeof open_key) return 18;
    memcpy(&open_key, &function, sizeof open_key);
    /* Initialize the process-local predefined HKLM cache before counting
       owned campaign handles; each returned warm-up key still closes. */
    for (unsigned view = 0; view < 2; ++view) {
        HKEY warm = NULL;
        REGSAM flag = view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software", 0, KEY_READ | flag, &warm)
            != ERROR_SUCCESS || !warm || RegCloseKey(warm) != ERROR_SUCCESS)
            return 20;
    }
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 11;
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"roots\":[",
           sizeof(void *), before);
    int first = 1;
    for (unsigned root = 0; root < 3; ++root) {
        for (unsigned view = 0; view < 2; ++view) {
            const REGSAM flag = view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
            HKEY key = NULL;
            LSTATUS status;
            if (root == 0) {
                wchar_t text[] = L"\\Registry\\Machine";
                UNICODE_STRING name = {(USHORT)(sizeof text - 2), (USHORT)sizeof text, text};
                OBJECT_ATTRIBUTES attributes = {0};
                attributes.Length = (ULONG)sizeof attributes;
                attributes.ObjectName = &name;
                attributes.Attributes = 0x40;
                HANDLE handle = NULL;
                if (open_key(&handle, KEY_READ | flag, &attributes, 0) != 0 || !handle)
                    return 19;
                key = (HKEY)handle;
                status = ERROR_SUCCESS;
            } else {
                status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[root], 0,
                                      KEY_READ | flag, &key);
            }
            printf("%s{\"root\":%u,\"view\":%lu,\"status\":%ld",
                   first ? "" : ",", root, flag, status);
            first = 0;
            if (status == ERROR_SUCCESS) {
                DWORD count = 0, maximum = 0;
                FILETIME time;
                if (!key || RegQueryInfoKeyW(key, NULL, NULL, NULL, &count, &maximum,
                    NULL, NULL, NULL, NULL, NULL, &time) != ERROR_SUCCESS ||
                    count > 1024 || maximum > 32767) return 12;
                keys[root][view] = key;
                counts[root][view] = count;
                printf(",\"children\":%lu,\"names\":[", count);
                for (DWORD index = 0; index < count; ++index) {
                    wchar_t name[32768];
                    DWORD units = 32768;
                    FILETIME child_time;
                    if (RegEnumKeyExW(key, index, name, &units, NULL, NULL, NULL,
                                      &child_time) != ERROR_SUCCESS || units >= 32768)
                        return 13;
                    printf("%s{\"index\":%lu,\"name_hex\":\"", index ? "," : "", index);
                    hex((const unsigned char *)name, (size_t)units * 2);
                    printf("\",\"last_write_hex\":\"");
                    hex((const unsigned char *)&child_time, sizeof child_time);
                    printf("\"}");
                }
                printf("]");
            } else if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) {
                return 14;
            }
            printf("}");
        }
    }
    printf("],\"rows\":[");
    for (unsigned root = 0; root < 3; ++root) {
        for (unsigned view = 0; view < 2; ++view) {
            HKEY key = keys[root][view];
            if (!key) continue;
            unsigned flag = view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
            for (ULONG index = 0; index <= counts[root][view] + 1; ++index) {
                for (unsigned offset = 0; offset < 8; ++offset) {
                    for (size_t l = 0; l < sizeof lengths / sizeof lengths[0]; ++l)
                        row(root, flag, key, index, 0, offset, lengths[l]);
                }
            }
            row(root, flag, key, 0xffffffff, 0, 0, 288);
            for (ULONG kind = 1; kind <= 11; ++kind)
                row(root, flag, key, 0, kind, 0, 288);
            if (RegCloseKey(key) != ERROR_SUCCESS) return 15;
        }
    }
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 16;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after && !first_row ? 0 : 17;
}
