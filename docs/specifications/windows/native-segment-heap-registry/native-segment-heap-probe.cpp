#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <initializer_list>
// Original query-only oracle for the exact next loader registry dependency.
// No registry writes/creates/deletes, privileges, or guest-supplied path.
using Open = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);
using Query = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
using EnumValue = LONG(NTAPI*)(HANDLE, ULONG, ULONG, void*, ULONG, ULONG*);
using Close = LONG(NTAPI*)(HANDLE);
static UNICODE_STRING name(const wchar_t* text) {
    UNICODE_STRING u{};
    u.Length = USHORT(wcslen(text) * sizeof(wchar_t));
    u.MaximumLength = u.Length + sizeof(wchar_t);
    u.Buffer = const_cast<wchar_t*>(text);
    return u;
}
static void bytes(const unsigned char* data, unsigned length) {
    for (unsigned i = 0; i < length; ++i) printf("%02X", data[i]);
}
int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    auto dll = GetModuleHandleW(L"ntdll.dll");
    auto open = reinterpret_cast<Open>(GetProcAddress(dll, "NtOpenKey"));
    auto query = reinterpret_cast<Query>(GetProcAddress(dll, "NtQueryKey"));
    auto enumerate = reinterpret_cast<EnumValue>(GetProcAddress(dll, "NtEnumerateValueKey"));
    auto close = reinterpret_cast<Close>(GetProcAddress(dll, "NtClose"));
    if (!open || !query || !enumerate || !close) return 1;
    auto path = name(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap");
    for (ULONG view : {0u, 0x100u, 0x200u}) {
        OBJECT_ATTRIBUTES attrs{};
        attrs.Length = sizeof(attrs);
        attrs.ObjectName = &path;
        attrs.Attributes = 0x240;
        HANDLE key = nullptr;
        LONG status = open(&key, 1 | view, &attrs);
        HKEY win32 = nullptr;
        LONG host = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Segment Heap", 0, 1 | view, &win32);
        printf("pointer=%zu view=%03lX native=%08lX win32=%ld\n", sizeof(void*), view, status, host);
        if (host == ERROR_SUCCESS) RegCloseKey(win32);
        if (status < 0) {
            if (ULONG(status) != 0xC0000034u && ULONG(status) != 0xC000003Au) return 2;
            if (host != ERROR_FILE_NOT_FOUND && host != ERROR_PATH_NOT_FOUND) return 3;
            continue;
        }
        if (host != ERROR_SUCCESS) return 4;
        for (ULONG kind : {2u, 3u}) {
            alignas(16) unsigned char data[1024];
            memset(data, 0xA5, sizeof(data));
            ULONG returned = 0xA5A5A5A5;
            LONG result = query(key, kind, data, sizeof(data), &returned);
            printf("query view=%03lX class=%lu status=%08lX returned=%lu bytes=", view, kind, result, returned);
            if (result < 0 || returned > sizeof(data)) return 5;
            bytes(data, returned);
            printf("\n");
        }
        std::vector<unsigned char> data(1'081'360, 0xA5);
        ULONG index = 0;
        for (; index < 4096; ++index) {
            ULONG returned = 0xA5A5A5A5;
            LONG result = enumerate(key, index, 1, data.data(), ULONG(data.size()), &returned);
            if (ULONG(result) == 0x8000001Au) {
                printf("end view=%03lX count=%lu status=%08lX returned=%08lX\n", view, index, result, returned);
                break;
            }
            if (result < 0 || returned > data.size() || returned < 20) return 6;
            ULONG header[5];
            memcpy(header, data.data(), sizeof(header));
            if (header[4] & 1 || header[4] > returned - 20 || header[2] > returned || header[3] > returned - header[2]) return 7;
            printf("value view=%03lX index=%lu status=%08lX returned=%lu name=", view, index, result, returned);
            bytes(data.data() + 20, header[4]);
            printf(" type=%lu data=", header[1]);
            bytes(data.data() + header[2], header[3]);
            printf("\n");
        }
        close(key);
        if (index == 4096) return 8;
    }
    return 0;
}
