#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG (NTAPI *UnmapEx)(HANDLE, PVOID, ULONG);
typedef LONG (NTAPI *Unmap)(HANDLE, PVOID);
static UnmapEx unmap_ex;
static Unmap unmap;

static void emit(DWORD case_id, DWORD flags, DWORD status, DWORD before, DWORD after,
                 DWORD alias, DWORD repeat) {
    const char digits[] = "0123456789abcdef";
    DWORD values[] = {case_id, flags, status, before, after, alias, repeat};
    char line[8 * 7 + 7];
    DWORD len = 0;
    DWORD written = 0;
    for (unsigned value = 0; value != sizeof(values) / sizeof(values[0]); ++value) {
        for (int bit = 28; bit >= 0; bit -= 4)
            line[len++] = digits[(values[value] >> bit) & 15];
        line[len++] = value == 6 ? '\n' : ' ';
    }
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, len, &written, 0) || written != len)
        ExitProcess(22);
}

static DWORD state(void *address) {
    MEMORY_BASIC_INFORMATION region;
    if (!VirtualQuery(address, &region, sizeof(region)))
        ExitProcess(21);
    return region.State;
}

static void mapped(DWORD mode, ULONG flags, HANDLE section, HANDLE process) {
    BYTE *view = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 65536);
    BYTE *alias = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 65536);
    if (!view || !alias)
        ExitProcess(20);
    view[4097] = 0x71;
    DWORD before = state(view);
    SIZE_T offset = mode % 2 ? 4097 : 0;
    switch (mode) {
    case 8: offset = 4096; break;
    case 9: offset = 1; break;
    case 10: offset = 8192; break;
    case 11: offset = 65535; break;
    }
    void *address = view + offset;
    LONG status = unmap_ex(process, address, flags);
    DWORD after = state(view);
    DWORD mirror = alias[4097];
    LONG repeat = 0xffffffff;
    if (!status)
        repeat = unmap_ex(process, address, flags);
    if (after == MEM_COMMIT && unmap(GetCurrentProcess(), view))
        ExitProcess(24);
    if (unmap(GetCurrentProcess(), alias))
        ExitProcess(25);
    emit(mode, flags, status, before, after, mirror, repeat);
}

void entry(void) {
    HMODULE dll = GetModuleHandleW(L"ntdll.dll");
    unmap_ex = (UnmapEx)GetProcAddress(dll, "NtUnmapViewOfSectionEx");
    unmap = (Unmap)GetProcAddress(dll, "NtUnmapViewOfSection");
    if (!unmap_ex || !unmap)
        ExitProcess(23);
    HANDLE process = GetCurrentProcess();
    HANDLE allowed = OpenProcess(PROCESS_VM_OPERATION, FALSE, GetCurrentProcessId());
    HANDLE denied = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    HANDLE wrong = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 65536, NULL);
    BYTE *private = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!section || !private || !allowed || !denied || !wrong)
        ExitProcess(26);
    ULONG flags[] = {0, 1, 2, 3, 4, 0x80000000};
    for (unsigned i = 0; i != sizeof(flags) / sizeof(flags[0]); ++i) {
        ULONG flag = flags[i];
        mapped(0, flag, section, process);
        mapped(1, flag, section, process);
        mapped(2, flag, section, allowed);
        mapped(3, flag, section, denied);
        mapped(4, flag, section, wrong);
        mapped(5, flag, section, NULL);
        DWORD status = unmap_ex(process, private + 4097, flag);
        emit(6, flag, status, MEM_COMMIT, state(private), private[4097], 0xffffffff);
        emit(7, flag, unmap_ex(process, NULL, flag), 0, 0, 0, 0xffffffff);
        for (DWORD place = 8; place <= 11; ++place)
            mapped(place, flag, section, process);
        emit(12, flag, unmap_ex(process, private, flag), MEM_COMMIT, state(private), private[0], 0xffffffff);
        emit(13, flag, unmap_ex(process, private + 4096, flag), MEM_COMMIT, state(private), private[4096], 0xffffffff);
        emit(14, flag, unmap_ex(process, (void *)1, flag), 0, 0, 0, 0xffffffff);
        emit(15, flag, unmap_ex(process, (void *)65536, flag), 0, 0, 0, 0xffffffff);
    }
    if (!VirtualFree(private, 0, MEM_RELEASE) || !CloseHandle(section) ||
        !CloseHandle(allowed) || !CloseHandle(denied) || !CloseHandle(wrong))
        ExitProcess(27);
    ExitProcess(0);
}
