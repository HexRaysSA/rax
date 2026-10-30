#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef LONG (NTAPI *OpenEventFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef LONG (NTAPI *OpenDirectoryFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef LONG (NTAPI *QueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *StateFn)(HANDLE, PLONG);
typedef LONG (NTAPI *WaitFn)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef LONG (NTAPI *CloseFn)(HANDLE);
typedef LONG (NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);

static OpenEventFn open_event;
static OpenDirectoryFn open_directory;
static QueryFn query_object, query_event;
static StateFn set_event;
static WaitFn wait_event;
static CloseFn close_object;
static unsigned char *pages;
static HANDLE creator, directory, semaphore;
static wchar_t leaf[128], absolute[512], parent[512], semaphore_leaf[128];
static unsigned records;

static void protect(void *address, SIZE_T size, DWORD flags) {
    DWORD previous;
    if (!VirtualProtect(address, size, flags, &previous)) ExitProcess(16);
}

static int identity(const char *kind, HMODULE module, const RTL_OSVERSIONINFOW *os, DWORD before) {
    wchar_t logical[1024], mapped[1024];
    DWORD logical_length = GetModuleFileNameW(module, logical, 1024);
    DWORD mapped_length = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
    if (!logical_length || logical_length >= 1024 || !mapped_length || mapped_length >= 1024) return 18;
    printf("{\"kind\":\"%s\",\"schema\":\"rax-native-open-event-v1\",\"pointer_bytes\":%zu,"
           "\"kernel\":[%lu,%lu,%lu],\"handles_before\":%lu,\"provider_utf16\":\"",
           kind, sizeof(void *), os->dwMajorVersion, os->dwMinorVersion, os->dwBuildNumber, before);
    for (DWORD i = 0; i < logical_length; ++i) printf("%02x%02x", logical[i] & 255, logical[i] >> 8);
    printf("\",\"mapped_provider_utf16\":\"");
    for (DWORD i = 0; i < mapped_length; ++i) printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
    printf("\",\"parent_utf16\":\"");
    for (size_t i = 0; i < wcslen(parent); ++i) printf("%02x%02x", parent[i] & 255, parent[i] >> 8);
    printf("\",\"name_utf16\":\"");
    for (size_t i = 0; i < wcslen(absolute); ++i) printf("%02x%02x", absolute[i] & 255, absolute[i] >> 8);
    printf("\"}\n");
    return 0;
}

static UNICODE_STRING counted(wchar_t *text) {
    UNICODE_STRING result;
    result.Length = (USHORT)(wcslen(text) * sizeof(wchar_t));
    result.MaximumLength = result.Length;
    result.Buffer = text;
    return result;
}

static OBJECT_ATTRIBUTES attributes(UNICODE_STRING *name, HANDLE root) {
    OBJECT_ATTRIBUTES result;
    memset(&result, 0, sizeof(result));
    result.Length = sizeof(result);
    result.ObjectName = name;
    result.RootDirectory = root;
    result.Attributes = 0x40;
    return result;
}

static int observe(const char *phase, unsigned index, unsigned output_role,
                   unsigned attribute_role, ULONG access, ULONG flags,
                   const wchar_t *requested, HANDLE root) {
    OBJECT_ATTRIBUTES value;
    OBJECT_ATTRIBUTES *attrs;
    UNICODE_STRING name;
    UNICODE_STRING *name_pointer;
    HANDLE *out;
    HANDLE opened = NULL;
    unsigned offset = 0;
    unsigned char bytes[16];
    LONG status = (LONG)0xDEADBEEF, exception = 0;
    LONG event[2] = {-99, -99};
    LONG queried = (LONG)0xDEADBEEF;
    ULONG grant = 0, handle_attributes = 0;
    unsigned char basic[128] = {0};
    MEMORY_BASIC_INFORMATION output_page, attribute_page, name_page, buffer_page;
    protect(pages, 65536, PAGE_READWRITE);
    memset(pages, 0xA5, 65536);
    wcscpy_s((wchar_t *)(pages + 16384), 8192, requested);
    name = counted((wchar_t *)(pages + 16384));
    name_pointer = (UNICODE_STRING *)(pages + 8192);
    memcpy(name_pointer, &name, sizeof(name));
    value = attributes(name_pointer, root);
    value.Attributes = flags;
    attrs = (OBJECT_ATTRIBUTES *)(pages + 4096);
    memcpy(attrs, &value, sizeof(value));
    out = (HANDLE *)pages;
    switch (attribute_role) {
    case 1: attrs = NULL; break;
    case 2: attrs = (OBJECT_ATTRIBUTES *)(uintptr_t)1; break;
    case 3: attrs->Length = 0; break;
    case 4: attrs->Length = sizeof(value) + 4; break;
    case 5: attrs = (OBJECT_ATTRIBUTES *)(pages + 4097); memcpy(attrs, &value, sizeof(value)); break;
    case 6: attrs = (OBJECT_ATTRIBUTES *)(pages + 4100); memcpy(attrs, &value, sizeof(value)); break;
    case 7: attrs->ObjectName = NULL; attrs->RootDirectory = NULL; break;
    case 8: attrs->ObjectName = NULL; break;
    case 9: name_pointer->Length = 0; break;
    case 10: name_pointer->Length = 0; attrs->RootDirectory = NULL; break;
    case 11: name_pointer->Length = 3; break;
    case 12: name_pointer->Buffer = (wchar_t *)(pages + 16385); name_pointer->Length = 2; break;
    case 13: attrs->ObjectName = (UNICODE_STRING *)(uintptr_t)1; break;
    case 14: name_pointer->Buffer = (wchar_t *)(uintptr_t)1; break;
    case 15:
        wcscpy_s((wchar_t *)(pages + 16384), 8192, absolute);
        name_pointer->Length = (USHORT)(wcslen(absolute) * 2);
        attrs->RootDirectory = (HANDLE)(uintptr_t)0x1234;
        break;
    case 16: attrs->RootDirectory = (HANDLE)(uintptr_t)0x1234; break;
    case 17: attrs->RootDirectory = creator; break;
    case 18:
        wcscpy_s((wchar_t *)(pages + 16384), 8192, absolute);
        name_pointer->Length = (USHORT)(wcslen(absolute) * 2);
        break;
    case 19: attrs->Attributes = 0x80000000; break;
    case 20: attrs->Attributes = 0x80000000; attrs->ObjectName = (UNICODE_STRING *)(uintptr_t)1; break;
    case 21: protect(pages + 4096, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 22: protect(pages + 4096, 4096, PAGE_NOACCESS); break;
    case 23: protect(pages + 4096, 4096, PAGE_READONLY); break;
    case 24: protect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 25: protect(pages + 16384, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 26: attrs->SecurityDescriptor = (void *)(uintptr_t)1; break;
    case 27: attrs->SecurityQualityOfService = (void *)(uintptr_t)1; break;
    case 28: attrs->RootDirectory = GetCurrentProcess(); break;
    case 29: name_pointer->Length = 65534; break;
    case 30: name_pointer->MaximumLength = 0; break;
    case 31: name_pointer->Length = 0; name_pointer->Buffer = (wchar_t *)(uintptr_t)1; break;
    case 32: attrs->Attributes = 0x20; attrs->ObjectName = (UNICODE_STRING *)(uintptr_t)1; break;
    case 33: attrs->Attributes = 0x20; protect(pages + 16384, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 34: name_pointer->Length = 3; name_pointer->Buffer = (wchar_t *)(uintptr_t)1; break;
    case 35: name_pointer->Length = 65534; name_pointer->Buffer = (wchar_t *)(uintptr_t)1; break;
    case 36: name_pointer->Length = 65535; name_pointer->Buffer = (wchar_t *)(uintptr_t)1; break;
    case 37: name_pointer->Length = 3; protect(pages + 16384, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 38: name_pointer->Length = 65534; protect(pages + 16384, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 39: name_pointer->Length = 3; protect(pages + 16384, 4096, PAGE_NOACCESS); break;
    case 40: case 41: case 42:
        name_pointer->Length = attribute_role == 40 ? 3 : attribute_role == 41 ? 2 : 4;
        name_pointer->Buffer = (wchar_t *)(pages + 20478);
        protect(pages + 20480, 4096, PAGE_NOACCESS);
        break;
    }
    switch (output_role) {
    case 1: out = NULL; break;
    case 2: out = (HANDLE *)(uintptr_t)1; break;
    case 3: offset = 1; out = (HANDLE *)(pages + offset); break;
    case 4: offset = 4; out = (HANDLE *)(pages + offset); break;
    case 5: protect(pages, 4096, PAGE_READONLY); break;
    case 6: protect(pages, 4096, PAGE_READWRITE | PAGE_GUARD); break;
    case 7: case 8: case 9:
        offset = 12284; out = (HANDLE *)(pages + offset);
        protect(pages + 12288, 4096,
            output_role == 7 ? PAGE_NOACCESS : output_role == 8 ? PAGE_READWRITE | PAGE_GUARD : PAGE_READONLY);
        break;
    }
    __try { status = open_event(out, access, attrs); }
    __except (EXCEPTION_EXECUTE_HANDLER) { exception = (LONG)GetExceptionCode(); }
    if (!VirtualQuery(pages + offset, &output_page, sizeof(output_page)) ||
        !VirtualQuery(pages + 4096, &attribute_page, sizeof(attribute_page)) ||
        !VirtualQuery(pages + 8192, &name_page, sizeof(name_page)) ||
        !VirtualQuery(pages + 16384, &buffer_page, sizeof(buffer_page))) return 5;
    protect(pages, 65536, PAGE_READWRITE);
    memcpy(bytes, pages + offset, sizeof(bytes));
    if (!exception && status >= 0) {
        if ((unsigned char *)out < pages || (unsigned char *)out > pages + 65536 - sizeof(HANDLE)) return 2;
        memcpy(&opened, out, sizeof(opened));
        if (!opened || query_object(opened, 0, basic, sizeof(PUBLIC_OBJECT_BASIC_INFORMATION), NULL) < 0) return 3;
        memcpy(&handle_attributes, basic, 4);
        memcpy(&grant, basic + 4, 4);
        queried = query_event(opened, 0, event, sizeof(event), NULL);
        memset(bytes, 0x42, sizeof(HANDLE));
        if (close_object(opened) < 0) return 4;
    }
    printf("{\"kind\":\"case\",\"phase\":\"%s\",\"index\":%u,\"output\":%u,\"attribute\":%u,"
           "\"access\":%lu,\"flags\":%lu,\"status\":%lu,\"exception\":%lu,\"grant\":%lu,\"handle_attributes\":%lu,"
           "\"query\":%lu,\"event_type\":%ld,\"event_state\":%ld,\"protections\":[%lu,%lu,%lu,%lu],\"bytes\":\"",
           phase, index, output_role, attribute_role, access, flags, (ULONG)status, (ULONG)exception,
           grant, handle_attributes, (ULONG)queried, event[0], event[1],
           output_page.Protect, attribute_page.Protect, name_page.Protect, buffer_page.Protect);
    for (unsigned i = 0; i < sizeof(bytes); ++i) printf("%02x", bytes[i]);
    printf("\"}\n");
    ++records;
    return 0;
}

int main(int argc, char **argv) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    RTL_OSVERSIONINFOW os = {sizeof(os)};
    DWORD before, after;
    unsigned char named[2048];
    UNICODE_STRING *native_name = (UNICODE_STRING *)named;
    UNICODE_STRING parent_name;
    OBJECT_ATTRIBUTES parent_attrs;
    wchar_t win32_name[160], semaphore_name[160], missing[256];
    const ULONG access[] = {0,1,2,3,4,0x100000,0xF0000,0x1F0003,0x2000000,0x80000000,
        0x40000000,0x20000000,0x10000000,0x1000000,0x1F0007,0xFFFFFFFF,0x20000000|4};
    const ULONG flags[] = {0,1,2,4,8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x80000000};
    setvbuf(stdout, NULL, _IONBF, 0);
    open_event = (OpenEventFn)GetProcAddress(ntdll, "NtOpenEvent");
    open_directory = (OpenDirectoryFn)GetProcAddress(ntdll, "NtOpenDirectoryObject");
    query_object = (QueryFn)GetProcAddress(ntdll, "NtQueryObject");
    query_event = (QueryFn)GetProcAddress(ntdll, "NtQueryEvent");
    set_event = (StateFn)GetProcAddress(ntdll, "NtSetEvent");
    wait_event = (WaitFn)GetProcAddress(ntdll, "NtWaitForSingleObject");
    close_object = (CloseFn)GetProcAddress(ntdll, "NtClose");
    if (!version || !open_event || !open_directory || !query_object || !query_event ||
        !set_event || !wait_event || !close_object || version(&os) < 0) return 10;
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) {
        if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 11;
        return identity("identity", ntdll, &os, before);
    }
    if (argc != 1) return 19;
    pages = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages || !GetProcessHandleCount(GetCurrentProcess(), &before)) return 11;
    swprintf_s(leaf, 128, L"RaxOpenEventProbeV1-%lu", GetCurrentProcessId());
    swprintf_s(win32_name, 160, L"Local\\%ls", leaf);
    creator = CreateEventW(NULL, TRUE, FALSE, win32_name);
    if (!creator || GetLastError() == ERROR_ALREADY_EXISTS) return 12;
    if (query_object(creator, 1, named, sizeof(named), NULL) < 0 || native_name->Length >= sizeof(absolute)) return 13;
    memcpy(absolute, native_name->Buffer, native_name->Length);
    absolute[native_name->Length / 2] = 0;
    wcscpy_s(parent, 512, absolute);
    *wcsrchr(parent, L'\\') = 0;
    parent_name = counted(parent);
    parent_attrs = attributes(&parent_name, NULL);
    if (open_directory(&directory, 0xF, &parent_attrs) < 0) return 14;
    swprintf_s(semaphore_leaf, 128, L"%ls-sem", leaf);
    swprintf_s(semaphore_name, 160, L"Local\\%ls", semaphore_leaf);
    semaphore = CreateSemaphoreW(NULL, 0, 2, semaphore_name);
    if (!semaphore || GetLastError() == ERROR_ALREADY_EXISTS) return 15;
    if (identity("host", ntdll, &os, before)) return 18;
    swprintf_s(missing, 256, L"%ls-missing", leaf);
    for (unsigned i = 0; i < sizeof(access)/sizeof(access[0]); ++i) {
        if (observe("access", i, 0, 0, access[i], 0x40, leaf, directory) ||
            observe("access-missing", i, 0, 0, access[i], 0x40, missing, directory) ||
            observe("access-type", i, 0, 0, access[i], 0x40, semaphore_leaf, directory)) return 20;
    }
    for (unsigned i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i)
        if (observe("flags", i, 0, 0, 0x100000, flags[i], leaf, directory)) return 21;
    for (unsigned out = 0; out < 10; ++out)
        for (unsigned attr = 0; attr < 43; ++attr)
            if (observe("fault", out * 43 + attr, out, attr, 0x100000, 0x40, leaf, directory)) return 22;
    if (observe("name",0,0,0,0x100000,0x40,absolute,NULL) ||
        observe("name",1,0,0,0x100000,0x40,missing,directory) ||
        observe("name",2,0,0,0x100000,0x40,L"missing\\leaf",directory) ||
        observe("name",3,0,0,0x100000,0x40,semaphore_leaf,directory) ||
        observe("name",4,0,0,0x100000,0x40,leaf,NULL) ||
        observe("name",5,0,0,0x100000,0x40,L"HookSwitchHookEnabledEvent",directory)) return 23;
    for (unsigned mode = 0; mode < 4; ++mode) {
        if (close_object(creator) < 0) return 26;
        creator = CreateEventW(NULL, mode & 1, mode >> 1, win32_name);
        if (!creator || GetLastError() == ERROR_ALREADY_EXISTS) return 27;
        if (observe("kind", mode, 0, 0, 0x1F0003, 0x40, leaf, directory)) return 28;
    }
    if (close_object(semaphore) < 0 || close_object(directory) < 0 || close_object(creator) < 0) return 24;
    VirtualFree(pages, 0, MEM_RELEASE);
    if (!GetProcessHandleCount(GetCurrentProcess(), &after) || before != after) return 25;
    printf("{\"kind\":\"finished\",\"records\":%u,\"handles_after\":%lu}\n", records, after);
    return 0;
}
