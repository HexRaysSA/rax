#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static unsigned ordinal;

static void *argument(unsigned char *memory, unsigned role, unsigned offset) {
    switch (role) {
    case 1:
        return nullptr;
    case 2:
        return reinterpret_cast<void *>(1);
    case 3:
        return memory + offset + 1;
    case 4:
        return memory + 4096 + offset;
    case 5:
        return memory + 8192 + offset;
    case 6:
    case 7:
        return memory + 12288 + offset;
    case 8:
        return memory + 4094;
    case 9:
        return memory + 4092;
    default:
        return memory + offset;
    }
}

static void bytes(const unsigned char *memory, const void *pointer,
                  unsigned fallback) {
    const auto base = reinterpret_cast<uintptr_t>(memory);
    const auto address = reinterpret_cast<uintptr_t>(pointer);
    const auto selected = address >= base && address <= base + 16384 - 16
                              ? static_cast<const unsigned char *>(pointer)
                              : memory + fallback;
    for (unsigned i = 0; i < 16; ++i)
        std::printf("%02x", selected[i]);
}

static bool observe(const char *family, unsigned handle_kind, HANDLE handle,
                    ULONG access, bool opened, unsigned output_role,
                    unsigned return_role, ULONG length, int alias = -1) {
    auto memory = static_cast<unsigned char *>(
        VirtualAlloc(nullptr, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!memory)
        return false;
    std::memset(memory, 0xa5, 16384);
    DWORD old = 0;
    const DWORD guard =
        (output_role == 7 || return_role == 7 ? PAGE_READONLY
                                              : PAGE_READWRITE) |
        PAGE_GUARD;
    if (!VirtualProtect(memory + 4096, 4096, PAGE_READONLY, &old) ||
        !VirtualProtect(memory + 8192, 4096, PAGE_NOACCESS, &old) ||
        !VirtualProtect(memory + 12288, 4096, guard, &old))
        return false;
    void *output = argument(memory, output_role, 256);
    auto returned = static_cast<ULONG *>(argument(memory, return_role, 512));
    if (alias >= 0)
        returned = reinterpret_cast<ULONG *>(memory + 256 + alias);
    LONG status = 0;
    DWORD exception = 0;
    __try {
        status = query(handle, 34, output, length, returned);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode();
    }
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(memory + 12288, &region, sizeof(region)) !=
            sizeof(region) ||
        !VirtualProtect(memory, 16384, PAGE_READWRITE, &old))
        return false;
    std::printf(
        "{\"kind\":\"case\",\"ordinal\":%u,\"family\":\"%s\","
        "\"handle_kind\":%u,\"access\":%lu,\"opened\":%s,"
        "\"output_role\":%u,\"return_role\":%u,\"length\":%lu,\"alias\":%d,"
        "\"status\":%lu,\"exception\":%lu,\"guard_protection\":%lu,\"output\":"
        "\"",
        ordinal++, family, handle_kind, access, opened ? "true" : "false",
        output_role, return_role, length, alias, static_cast<DWORD>(status),
        exception, region.Protect);
    bytes(memory, output, 256);
    std::printf("\",\"returned\":\"");
    bytes(memory, returned, 512);
    std::printf("\"}\n");
    return VirtualFree(memory, 0, MEM_RELEASE) != 0;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    query = reinterpret_cast<Query>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
    const auto version =
        reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    USHORT process_machine = 0, native_machine = 0;
    const auto image =
        reinterpret_cast<const unsigned char *>(GetModuleHandleW(nullptr));
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(image);
    if (!query || !version || version(&info) < 0 ||
        dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 4096 ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 2;
    const auto pe =
        reinterpret_cast<const IMAGE_NT_HEADERS *>(image + dos->e_lfanew);
    if (pe->Signature != IMAGE_NT_SIGNATURE)
        return 3;
    DWORD dep_flags = 0xa5a5a5a5;
    BOOL permanent = FALSE;
    SetLastError(0);
    const bool dep_ok =
        GetProcessDEPPolicy(GetCurrentProcess(), &dep_flags, &permanent) != 0;
    const DWORD dep_error = GetLastError();
    std::printf(
        "{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
        "\"native_machine\":%u,\"pointer_bytes\":%zu,\"nx_compat\":%s,"
        "\"system_dep_policy\":%u,\"dep_query_ok\":%s,\"dep_error\":%lu,"
        "\"dep_flags\":%lu,\"dep_permanent\":%s}\n",
        info.dwBuildNumber, process_machine, native_machine, sizeof(void *),
        pe->OptionalHeader.DllCharacteristics &
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            ? "true"
            : "false",
        static_cast<unsigned>(GetSystemDEPPolicy()), dep_ok ? "true" : "false",
        dep_error, dep_flags, permanent ? "true" : "false");
    const auto self = GetCurrentProcess();
    for (ULONG length : {0ul, 1ul, 3ul, 4ul, 5ul, 8ul, 16ul})
        if (!observe("length", 0, self, 0, true, 0, 0, length))
            return 4;
    for (unsigned output = 0; output < 10; ++output)
        for (unsigned returned = 0; returned < 10; ++returned)
            if (!observe("buffer", 0, self, 0, true, output, returned, 4))
                return 5;
    const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event)
        return 6;
    const HANDLE handles[] = {self, nullptr, reinterpret_cast<HANDLE>(1),
                              GetCurrentThread(), event};
    for (unsigned kind = 0; kind < 5; ++kind)
        for (ULONG length : {3ul, 4ul})
            for (unsigned output = 0; output < 4; ++output)
                for (unsigned returned = 0; returned < 3; ++returned)
                    if (!observe("handle", kind, handles[kind], 0, true, output,
                                 returned, length))
                        return 7;
    if (!CloseHandle(event))
        return 8;
    for (ULONG access :
         {0ul, 8ul, 0x20ul, 0x400ul, 0x1000ul, 0x1400ul, 0x1ffffful}) {
        const auto handle = OpenProcess(access, FALSE, GetCurrentProcessId());
        if (!observe("rights", 5, handle, access, handle != nullptr, 0, 0, 4))
            return 9;
        if (handle && !CloseHandle(handle))
            return 10;
    }
    for (int alias = 0; alias <= 4; ++alias)
        if (!observe("alias", 0, self, 0, true, 0, 0, 4, alias))
            return 11;
    std::printf("{\"kind\":\"complete\",\"cases\":%u}\n", ordinal);
    return 0;
}
