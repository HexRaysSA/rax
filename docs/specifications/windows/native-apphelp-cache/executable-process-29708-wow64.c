#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG (WINAPI *AppHelpControl)(ULONG, void *);

enum {
    packet_bytes = 204,
    name_offset = 0x1c,
    name_pointer = 0x20,
    driver_status = 0xc0,
    output_pointer = 0xc4,
    output_capacity = 0xc8,
    capacity = 4096,
};

static DWORD output[capacity / sizeof(DWORD)];
static DWORD packet[packet_bytes / sizeof(DWORD)];

static void write_all(const void *bytes, DWORD length) {
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes, length, &written, NULL)
        || written != length)
        ExitProcess(21);
}

static void query(AppHelpControl control, const WCHAR *path, DWORD flags, DWORD id, size_t handle_offset) {
    const DWORD len = (DWORD)lstrlenW(path) * sizeof(WCHAR);
    for (unsigned i = 0; i != ARRAYSIZE(packet); ++i)
        packet[i] = 0;
    for (unsigned i = 0; i != ARRAYSIZE(output); ++i)
        output[i] = 0xa5a5a5a5;
    packet[0] = 0x1f;
    packet[1] = flags;
    packet[name_offset / sizeof(DWORD)] = ((len + sizeof(WCHAR)) << 16) | len;
    packet[name_pointer / sizeof(DWORD)] = (DWORD)(ULONG_PTR)path;
    packet[output_pointer / sizeof(DWORD)] = (DWORD)(ULONG_PTR)output;
    packet[output_capacity / sizeof(DWORD)] = sizeof(output);
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        ExitProcess(25);
    packet[handle_offset / sizeof(DWORD)] = (DWORD)(ULONG_PTR)file;
    const DWORD status = (DWORD)control(11, packet);
    if (!CloseHandle(file))
        ExitProcess(26);
    const DWORD header[] = {id, flags, status, len,
                            packet[driver_status / sizeof(DWORD)],
                            packet[output_capacity / sizeof(DWORD)]};
    write_all(header, sizeof(header));
    write_all(path, len);
    write_all(output, 128);
}

static void stock_cmd(WCHAR *directory, UINT len) {
    static const WCHAR suffix[] = L"\\cmd.exe";
    if (!len || len > MAX_PATH - ARRAYSIZE(suffix))
        ExitProcess(22);
    for (unsigned i = 0; i != ARRAYSIZE(suffix); ++i)
        directory[len+i] = suffix[i];
}

void entry(void) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        ExitProcess(23);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
    const AppHelpControl control = (AppHelpControl)GetProcAddress(ntdll, "NtApphelpCacheControl");
#pragma clang diagnostic pop
    if (!control)
        ExitProcess(24);
    WCHAR wow[MAX_PATH];
    WCHAR system[MAX_PATH];
    stock_cmd(wow, GetSystemWow64DirectoryW(wow, ARRAYSIZE(wow)));
    stock_cmd(system, GetSystemDirectoryW(system, ARRAYSIZE(system)));
    query(control, wow, 0x30, 1, 0x10);
    query(control, wow, 0x10, 2, 0x10);
    query(control, system, 0x30, 3, 0x10);
    query(control, system, 0x10, 4, 0x10);
    ExitProcess(0);
}
