#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    union { LONG status; void *pointer; } result;
    uintptr_t information;
} NativeIosb;
typedef LONG (NTAPI *OpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef LONG (NTAPI *NotifyKey)(HANDLE, HANDLE, PVOID, PVOID, NativeIosb *, ULONG,
                              BOOLEAN, PVOID, ULONG, BOOLEAN);
typedef LONG (NTAPI *WaitOne)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG (NTAPI *Close)(HANDLE);
static OpenKey open_key;
static NotifyKey notify_key;
static WaitOne wait_one;
static Close close_handle;

#define LOAD(name, symbol) do { \
    FARPROC p = GetProcAddress(ntdll, symbol); \
    if (!p) return 1; \
    memcpy(&name, &p, sizeof name); \
} while (0)

static LONG open(HANDLE *result) {
    wchar_t text[] = L"\\Registry\\Machine\\Software\\Microsoft\\OLE";
    UNICODE_STRING name = {(USHORT)(sizeof text - 2), (USHORT)sizeof text, text};
    OBJECT_ATTRIBUTES attributes = {0};
    attributes.Length = (ULONG)sizeof attributes;
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40;
    return open_key(result, KEY_READ, &attributes, 0);
}
static void hex(const void *data, size_t length) {
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; ++i) printf("%02x", bytes[i]);
}
static LONG wait_key(HANDLE key) {
    LARGE_INTEGER timeout;
    timeout.QuadPart = 0;
    return wait_one(key, FALSE, &timeout);
}

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    LOAD(open_key, "NtOpenKeyEx");
    LOAD(notify_key, "NtNotifyChangeKey");
    LOAD(wait_one, "NtWaitForSingleObject");
    LOAD(close_handle, "NtClose");
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 2;
    const ULONG filters[] = {1, 0x10000001, 0, 0xffffffff};
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[", sizeof(void *), before);
    int comma = 0;
    for (unsigned f = 0; f < 4; ++f)
    for (unsigned style = 0; style < 4; ++style)
    for (unsigned supplied = 0; supplied < 2; ++supplied) {
        HANDLE key = NULL, duplicate = NULL, independent = NULL;
        LONG opened = open(&key);
        if (opened != 0 || !key) return 3;
        if ((style & 1) && !DuplicateHandle(GetCurrentProcess(), key, GetCurrentProcess(),
                                          &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) return 4;
        if ((style & 2) && open(&independent) != 0) return 5;
        HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL);
        if (!event) return 6;
        /* Keep user storage allocated until process exit: cancellation may
         * publish asynchronously after the last key handle closes. */
        NativeIosb *io = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!io) return 7;
        memset(io, 0xcc, sizeof *io);
        LONG wait_before = wait_key(key);
        LONG status = notify_key(key, supplied ? event : NULL, NULL, NULL, io,
                                 filters[f], FALSE, NULL, 0, TRUE);
        unsigned char armed[sizeof *io], first[sizeof *io], last[sizeof *io];
        memcpy(armed, io, sizeof armed);
        DWORD event_armed = WaitForSingleObject(event, 0);
        LONG wait_armed = wait_key(key);
        LONG independent_close = independent ? close_handle(independent) : 0;
        DWORD event_independent = WaitForSingleObject(event, 0);
        LONG original_close = close_handle(key);
        memcpy(first, io, sizeof first);
        DWORD event_original = WaitForSingleObject(event, 0);
        LONG duplicate_close = duplicate ? close_handle(duplicate) : 0;
        DWORD event_final = WaitForSingleObject(event, supplied && status == 0x103 ? 5000 : 0);
        memcpy(last, io, sizeof last);
        printf("%s{\"filter\":%lu,\"style\":%u,\"event_supplied\":%u,\"open_status\":%lu,"
               "\"status\":%lu,\"wait_before\":%lu,\"wait_armed\":%lu,\"event_armed\":%lu,"
               "\"independent_close\":%lu,\"event_after_independent_close\":%lu,"
               "\"original_close\":%lu,\"event_after_original_close\":%lu,"
               "\"duplicate_close\":%lu,\"event_final\":%lu,\"iosb_armed\":\"",
               comma ? "," : "", filters[f], style, supplied, (ULONG)opened, (ULONG)status,
               (ULONG)wait_before, (ULONG)wait_armed, event_armed, (ULONG)independent_close,
               event_independent, (ULONG)original_close, event_original,
               (ULONG)duplicate_close, event_final);
        comma = 1;
        hex(armed, sizeof armed); printf("\",\"iosb_after_original_close\":\"");
        hex(first, sizeof first); printf("\",\"iosb_final\":\"");
        hex(last, sizeof last); printf("\"}");
        if (!CloseHandle(event)) return 8;
    }
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 9;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after ? 0 : 10;
}
