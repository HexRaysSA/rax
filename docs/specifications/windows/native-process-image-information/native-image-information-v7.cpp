#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static Query query_object;
static uintptr_t reference_entry;
static unsigned ordinal;
struct ImageInformation {
    void *TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    USHORT SubSystemMinorVersion;
    USHORT SubSystemMajorVersion;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    UCHAR ImageFlags;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
};
static constexpr ULONG QUERY_BYTES =
    static_cast<ULONG>(sizeof(ImageInformation));
static_assert(sizeof(ImageInformation) == (sizeof(void *) == 8 ? 64 : 48));
static_assert(offsetof(ImageInformation, Machine) ==
              (sizeof(void *) == 8 ? 48 : 32));
static constexpr ULONG lengths[] = {0,  1,  3,  4,  8,  16, 47,
                                    48, 49, 63, 64, 65, 96, 0xffffffff};

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
    case 10:
        return memory + 4036;
    case 11:
        return memory + 4032;
    case 12:
        return memory + 4048;
    case 13:
        return memory + 4080;
    case 16:
        return memory + 4088;
    case 14:
        return reinterpret_cast<void *>(~uintptr_t(3));
    case 15:
        return reinterpret_cast<void *>(~uintptr_t(7));
    default:
        return memory + offset;
    }
}

// Normalize only the pointer/padding positions in the declared output record.
// Those positions remain opaque even on failure; every other scratch byte is
// retained. Integer differences avoid wrapping an invalid upper destination.
static bool redacted(uintptr_t address, uintptr_t output) {
    if (address < output)
        return false;
    const auto offset = address - output;
    return offset < sizeof(void *) ||
           (sizeof(void *) == 8 && offset >= 12 && offset < 16);
}

static void projection(const unsigned char *memory, const void *pointer,
                       const void *output, unsigned fallback, unsigned count,
                       bool mask) {
    const auto base = reinterpret_cast<uintptr_t>(memory);
    const auto address = reinterpret_cast<uintptr_t>(pointer);
    const auto selected = address >= base && address <= base + 16384 - count
                              ? static_cast<const unsigned char *>(pointer)
                              : memory + fallback;
    for (unsigned i = 0; i < count; ++i) {
        const bool hide = redacted(reinterpret_cast<uintptr_t>(selected + i),
                                   reinterpret_cast<uintptr_t>(output));
        if (mask)
            std::printf("%c", hide ? '1' : '0');
        else
            std::printf("%02x", hide ? 0u : static_cast<unsigned>(selected[i]));
    }
}

static bool observe(const char *family, unsigned handle_kind, HANDLE handle,
                    ULONG access, bool opened, unsigned output_role,
                    unsigned return_role, ULONG length, int alias = -1,
                    ULONG info_class = 37) {
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
    ULONG granted = 0;
    const bool queried_grant = handle_kind == 5 && opened;
    if (queried_grant) {
        alignas(16) unsigned char object[128]{};
        ULONG object_returned = 0;
        const auto object_status =
            query_object(handle, 0, object, 56, &object_returned);
        if (object_status < 0) {
            std::printf("{\"kind\":\"handle_grant_failure\",\"requested\":%lu,"
                        "\"input_bytes\":56,\"returned\":%lu,\"status\":%lu}\n",
                        access, object_returned,
                        static_cast<DWORD>(object_status));
            return false;
        }
        std::memcpy(&granted, object + 4, sizeof(granted));
    }
    LONG status = 0;
    DWORD exception = 0;
    __try {
        status = query(handle, info_class, output, length, returned);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode();
    }
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(memory + 12288, &region, sizeof(region)) !=
            sizeof(region) ||
        !VirtualProtect(memory, 16384, PAGE_READWRITE, &old))
        return false;
    const auto base = reinterpret_cast<uintptr_t>(memory);
    const auto address = reinterpret_cast<uintptr_t>(output);
    const auto selected =
        address >= base && address <= base + 16384 - sizeof(uintptr_t)
            ? static_cast<const unsigned char *>(output)
            : memory + 256;
    unsigned pointer_valid = 0, pointer_changed = 0, pointer_matches = 0;
    const auto reference =
        reinterpret_cast<const unsigned char *>(&reference_entry);
    for (unsigned i = 0; i < sizeof(uintptr_t); ++i) {
        if (reference[i] != 0xa5)
            pointer_valid |= 1u << i;
        if (selected[i] != 0xa5)
            pointer_changed |= 1u << i;
        if (selected[i] == reference[i])
            pointer_matches |= 1u << i;
    }
    std::printf(
        "{\"kind\":\"case\",\"ordinal\":%u,\"query_class\":%lu,\"family\":\"%"
        "s\","
        "\"handle_kind\":%u,\"access\":%lu,\"opened\":%s,"
        "\"output_role\":%u,\"return_role\":%u,\"length\":%lu,\"alias\":%d,"
        "\"status\":%lu,\"exception\":%lu,\"guard_protection\":%lu,\"output\":"
        "\"",
        ordinal++, info_class, family, handle_kind, access,
        opened ? "true" : "false", output_role, return_role, length, alias,
        static_cast<DWORD>(status), exception, region.Protect);
    projection(memory, output, output, 256, 80, false);
    std::printf("\",\"output_mask\":\"");
    projection(memory, output, output, 256, 80, true);
    std::printf("\",\"returned\":\"");
    projection(memory, returned, output, 512, 16, false);
    std::printf("\",\"returned_mask\":\"");
    projection(memory, returned, output, 512, 16, true);
    std::printf("\",\"pointer_valid_mask\":%u,\"pointer_changed_mask\":%u,"
                "\"pointer_match_mask\":%u,\"granted_access\":",
                pointer_valid, pointer_changed, pointer_matches);
    if (queried_grant)
        std::printf("%lu", granted);
    else
        std::printf("null");
    std::printf("}\n");
    return VirtualFree(memory, 0, MEM_RELEASE) != 0;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3)
        return 16;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    query = reinterpret_cast<Query>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
    const auto version =
        reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
    query_object =
        reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryObject"));
    if (!query_object)
        return 18;
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    USHORT process_machine = 0, native_machine = 0;
    const auto module_bytes =
        reinterpret_cast<const unsigned char *>(GetModuleHandleW(nullptr));
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(module_bytes);
    if (!query || !version || version(&info) < 0 ||
        dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 4096 ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 2;
    const auto pe = reinterpret_cast<const IMAGE_NT_HEADERS *>(module_bytes +
                                                               dos->e_lfanew);
    if (pe->Signature != IMAGE_NT_SIGNATURE)
        return 3;
    ImageInformation image{};
    ULONG image_returned = 0;
    const LONG image_status =
        query(GetCurrentProcess(), 37, &image, QUERY_BYTES, &image_returned);
    const auto &optional = pe->OptionalHeader;
    const auto transfer = reinterpret_cast<uintptr_t>(image.TransferAddress);
    reference_entry = transfer;
    const auto preferred =
        static_cast<uintptr_t>(std::strtoull(argv[1], nullptr, 16));
    const auto loaded = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const bool preferred_rva_known =
        transfer >= preferred && transfer - preferred < optional.SizeOfImage;
    const bool loaded_rva_known =
        transfer >= loaded && transfer - loaded < optional.SizeOfImage;
    wchar_t name[4096];
    const auto path_length = GetModuleFileNameW(nullptr, name, 4096);
    if (!path_length || path_length >= 4096)
        return 14;
    const auto file =
        CreateFileW(name, FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    LARGE_INTEGER file_size{};
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &file_size) ||
        !CloseHandle(file))
        return 15;
    std::printf(
        "{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
        "\"native_machine\":%u,\"pointer_bytes\":%zu,\"query_class\":37,"
        "\"record_bytes\":%lu}\n",
        info.dwBuildNumber, static_cast<unsigned>(process_machine),
        static_cast<unsigned>(native_machine), sizeof(void *), QUERY_BYTES);
    std::printf(
        "{\"kind\":\"image\",\"status\":%lu,\"returned\":%lu,"
        "\"preferred_entry_matches\":%s,\"loaded_entry_matches\":%s,"
        "\"mapped_header_matches_loaded\":%s,\"mapped_header_matches_"
        "preferred\":%s,"
        "\"preferred_rva_known\":%s,\"preferred_rva\":%llu,"
        "\"loaded_rva_known\":%s,\"loaded_rva\":%llu,"
        "\"file_bytes\":%llu,\"pe\":[%u,%lu,%lu,%llu,%llu,%u,%u,%u,%u,%u,%u,%u,"
        "%lu,%lu],"
        "\"section\":[%lu,%llu,%llu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%lu]"
        "}\n",
        static_cast<DWORD>(image_status), image_returned,
        transfer == preferred + optional.AddressOfEntryPoint ? "true" : "false",
        transfer == loaded + optional.AddressOfEntryPoint ? "true" : "false",
        static_cast<uintptr_t>(optional.ImageBase) == loaded ? "true" : "false",
        static_cast<uintptr_t>(optional.ImageBase) == preferred ? "true"
                                                                : "false",
        preferred_rva_known ? "true" : "false",
        preferred_rva_known
            ? static_cast<unsigned long long>(transfer - preferred)
            : 0ull,
        loaded_rva_known ? "true" : "false",
        loaded_rva_known ? static_cast<unsigned long long>(transfer - loaded)
                         : 0ull,
        static_cast<unsigned long long>(file_size.QuadPart),
        static_cast<unsigned>(pe->FileHeader.Machine),
        optional.AddressOfEntryPoint, optional.SizeOfImage,
        static_cast<unsigned long long>(optional.SizeOfStackReserve),
        static_cast<unsigned long long>(optional.SizeOfStackCommit),
        static_cast<unsigned>(optional.Subsystem),
        static_cast<unsigned>(optional.MinorSubsystemVersion),
        static_cast<unsigned>(optional.MajorSubsystemVersion),
        static_cast<unsigned>(optional.MajorOperatingSystemVersion),
        static_cast<unsigned>(optional.MinorOperatingSystemVersion),
        static_cast<unsigned>(pe->FileHeader.Characteristics),
        static_cast<unsigned>(optional.DllCharacteristics),
        optional.LoaderFlags, optional.CheckSum, image.ZeroBits,
        static_cast<unsigned long long>(image.MaximumStackSize),
        static_cast<unsigned long long>(image.CommittedStackSize),
        image.SubSystemType, static_cast<unsigned>(image.SubSystemMinorVersion),
        static_cast<unsigned>(image.SubSystemMajorVersion),
        static_cast<unsigned>(image.MajorOperatingSystemVersion),
        static_cast<unsigned>(image.MinorOperatingSystemVersion),
        static_cast<unsigned>(image.ImageCharacteristics),
        static_cast<unsigned>(image.DllCharacteristics),
        static_cast<unsigned>(image.Machine),
        static_cast<unsigned>(image.ImageContainsCode),
        static_cast<unsigned>(image.ImageFlags), image.LoaderFlags,
        image.ImageFileSize, image.CheckSum);
    if (argc == 3) {
        if (std::strcmp(argv[2], "metadata") != 0)
            return 17;
        std::printf("{\"kind\":\"complete\",\"cases\":0}\n");
        return 0;
    }
    const auto self = GetCurrentProcess();
    for (ULONG length : lengths)
        if (!observe("length", 0, self, 0, true, 0, 0, length))
            return 4;
    for (unsigned output :
         {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 16u})
        for (unsigned returned = 0; returned < 14; ++returned)
            if (!observe("buffer", 0, self, 0, true, output, returned,
                         QUERY_BYTES))
                return 5;
    const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event)
        return 6;
    const HANDLE handles[] = {self, nullptr, reinterpret_cast<HANDLE>(1),
                              GetCurrentThread(), event};
    for (unsigned kind = 0; kind < 5; ++kind)
        for (ULONG length : {QUERY_BYTES - 1, QUERY_BYTES})
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
        if (!observe("rights", 5, handle, access, handle != nullptr, 0, 0,
                     QUERY_BYTES))
            return 9;
        if (handle && !CloseHandle(handle))
            return 10;
    }
    for (int alias = 0; alias <= static_cast<int>(QUERY_BYTES); ++alias)
        if (!observe("alias", 0, self, 0, true, 0, 0, QUERY_BYTES, alias))
            return 11;
    for (ULONG length : lengths)
        for (unsigned returned = 0; returned < 14; ++returned)
            if (!observe("null-length", 0, self, 0, true, 1, returned, length))
                return 12;
    for (unsigned kind : {0u, 2u})
        for (ULONG length : {0ul, 1ul, QUERY_BYTES - 1, QUERY_BYTES,
                             QUERY_BYTES + 1, 0xfffffffful})
            for (unsigned output : {14u, 15u})
                for (unsigned returned_role : {0u, 1u, 6u, 7u})
                    if (!observe("upper-image", kind, handles[kind], 0, true,
                                 output, returned_role, length))
                        return 13;
    std::printf("{\"kind\":\"complete\",\"cases\":%u}\n", ordinal);
    return 0;
}
