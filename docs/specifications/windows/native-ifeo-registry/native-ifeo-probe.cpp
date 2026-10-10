#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
// Original read-only fixed IFEO namespace oracle. No registry mutation.
using Open = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);
using Query = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
using Enumerate = LONG(NTAPI*)(HANDLE, ULONG, ULONG, void*, ULONG, ULONG*);
using Close = LONG(NTAPI*)(HANDLE);
static UNICODE_STRING name(const wchar_t* text) {
    UNICODE_STRING value{};
    value.Length = USHORT(wcslen(text) * 2);
    value.MaximumLength = value.Length + 2;
    value.Buffer = const_cast<wchar_t*>(text);
    return value;
}
static void bytes(const unsigned char* data, unsigned length) {
    for (unsigned i = 0; i < length; ++i) printf("%02X", data[i]);
}
int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    auto module = GetModuleHandleW(L"ntdll.dll");
    auto open = reinterpret_cast<Open>(GetProcAddress(module, "NtOpenKey"));
    auto query = reinterpret_cast<Query>(GetProcAddress(module, "NtQueryKey"));
    auto enumerate = reinterpret_cast<Enumerate>(GetProcAddress(module, "NtEnumerateKey"));
    auto close = reinterpret_cast<Close>(GetProcAddress(module, "NtClose"));
    if (!open || !query || !enumerate || !close) return 1;
    auto rootname = name(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
    for (ULONG view : {0u, 0x100u, 0x200u}) {
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.ObjectName = &rootname;
        attributes.Attributes = 0x240;
        HANDLE root = nullptr;
        auto status = open(&root, 9 | view, &attributes);
        printf("pointer=%zu view=%03lX open=%08lX\n", sizeof(void*), view, status);
        if (status < 0) return 2;
        for (ULONG kind : {2u, 3u}) {
            alignas(16) unsigned char data[1024];
            memset(data, 0xA5, sizeof(data));
            ULONG returned = 0xA5A5A5A5;
            status = query(root, kind, data, sizeof(data), &returned);
            printf("root view=%03lX class=%lu status=%08lX returned=%lu bytes=", view, kind, status, returned);
            bytes(data, status >= 0 ? returned : 64);
            printf("\n");
            if (status < 0 || returned > sizeof(data)) return 3;
        }
        ULONG count = 0;
        for (; count < 1024; ++count) {
            alignas(16) unsigned char data[2048];
            memset(data, 0xA5, sizeof(data));
            ULONG returned = 0xA5A5A5A5;
            status = enumerate(root, count, 0, data, sizeof(data), &returned);
            if (ULONG(status) == 0x8000001Au) {
                printf("end view=%03lX count=%lu status=%08lX returned=%08lX\n", view, count, status, returned);
                break;
            }
            if (status < 0 || returned > sizeof(data) || returned < 16) return 4;
            ULONG namelen = 0;
            memcpy(&namelen, data + 12, 4);
            if ((namelen & 1) || namelen > returned - 16) return 5;
            printf("child view=%03lX index=%lu status=%08lX name=", view, count, status);
            bytes(data + 16, namelen);
            printf("\n");
            UNICODE_STRING childname{};
            childname.Length = USHORT(namelen);
            childname.MaximumLength = childname.Length;
            childname.Buffer = reinterpret_cast<wchar_t*>(data + 16);
            attributes.RootDirectory = root;
            attributes.ObjectName = &childname;
            HANDLE child = nullptr;
            status = open(&child, 9 | view, &attributes);
            printf("child-open view=%03lX index=%lu status=%08lX\n", view, count, status);
            if (status < 0) return 6;
            alignas(16) unsigned char info[1024];
            memset(info, 0xA5, sizeof(info));
            ULONG size = 0xA5A5A5A5;
            status = query(child, 2, info, sizeof(info), &size);
            printf("child-info view=%03lX index=%lu status=%08lX returned=%lu bytes=", view, count, status, size);
            bytes(info, status >= 0 ? size : 64);
            printf("\n");
            close(child);
            if (status < 0 || size > sizeof(info)) return 7;
        }
        if (count == 1024) return 8;
        for (auto text : {L"probe.exe", L"smoke.exe", L"whoami.exe", L"missing-rax-image.exe"}) {
            auto childname = name(text);
            attributes.RootDirectory = root;
            attributes.ObjectName = &childname;
            HANDLE child = nullptr;
            status = open(&child, 9 | view, &attributes);
            printf("image-open view=%03lX name=%ls status=%08lX\n", view, text, status);
            if (status >= 0) close(child);
        }
        close(root);
    }
    return 0;
}
