#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <intrin.h>
#include <windows.h>

#if !defined(_M_IX86)
#error Native x86 WoW64 control required.
#endif

namespace {
struct Information {
    std::uint32_t page_size, cpu_flags, execute_flags, unknown;
    std::uint64_t section_handle, work_list;
    std::uint16_t native_machine, emulated_machine;
};
static_assert(sizeof(Information) == 40);
template <typename T> bool read(std::uintptr_t address, T &value) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(),
                             reinterpret_cast<const void *>(address), &value,
                             sizeof(value), &copied) &&
           copied == sizeof(value);
}
using QuerySection = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using QueryObject = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Read64 = LONG(NTAPI *)(HANDLE, std::uint64_t, void *, std::uint64_t,
                             std::uint64_t *);
using MappedFile = DWORD(WINAPI *)(HANDLE, void *, wchar_t *, DWORD);
struct SectionBasic {
    void *base;
    ULONG attributes;
    LARGE_INTEGER size;
};
} // namespace

int main() {
    const std::uintptr_t teb = __readfsdword(0x18);
    std::int32_t offset = 0;
    if (!read(teb + 0xfdc, offset) || offset >= 0)
        return 10;
    const std::uintptr_t native_teb = teb + offset;
    std::uint32_t pointer = 0;
    Information info = {};
    if (!read(native_teb + 0x14d0, pointer) || !pointer || !read(pointer, info))
        return 11;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto query_section =
        reinterpret_cast<QuerySection>(GetProcAddress(ntdll, "NtQuerySection"));
    const auto query_object =
        reinterpret_cast<QueryObject>(GetProcAddress(ntdll, "NtQueryObject"));
    const auto read64 = reinterpret_cast<Read64>(
        GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64"));
    const auto mapped_file = reinterpret_cast<MappedFile>(
        GetProcAddress(kernel32, "K32GetMappedFileNameW"));
    if (!query_section || !query_object)
        return 12;

    MEMORY_BASIC_INFORMATION region = {};
    const bool mapped =
        info.unknown && VirtualQuery(reinterpret_cast<void *>(info.unknown),
                                     &region, sizeof(region)) == sizeof(region);
    wchar_t filename[1024] = {};
    bool file_known = false;
    if (mapped && mapped_file)
        file_known = mapped_file(GetCurrentProcess(),
                                 reinterpret_cast<void *>(info.unknown),
                                 filename, 1024) > 0;
    const wchar_t *basename = std::wcsrchr(filename, L'\\');
    basename = basename ? basename + 1 : filename;
    bool ascii = true;
    for (const wchar_t *at = basename; *at; ++at)
        ascii = ascii &&
                ((*at >= L'A' && *at <= L'Z') || (*at >= L'a' && *at <= L'z') ||
                 (*at >= L'0' && *at <= L'9') || *at == L'.' || *at == L'-' ||
                 *at == L'_');
    char narrow[256] = {};
    if (file_known && ascii) {
        unsigned index = 0;
        while (basename[index] && index < 255) {
            narrow[index] = static_cast<char>(basename[index]);
            ++index;
        }
    }
    const auto relative =
        mapped ? static_cast<std::uint64_t>(
                     info.unknown -
                     reinterpret_cast<std::uintptr_t>(region.AllocationBase))
               : 0;
    std::printf(
        "{\"kind\":\"unknown_word\",\"nonnull\":%s,\"mapped\":%s,\"state\":%lu,"
        "\"protect\":%lu,\"type\":%lu,\"region_bytes\":%llu,\"allocation_"
        "offset\":%llu,\"module_basename\":\"%s\",\"equals_ntdll_base\":%s}\n",
        info.unknown ? "true" : "false", mapped ? "true" : "false",
        region.State, region.Protect, region.Type,
        static_cast<unsigned long long>(region.RegionSize),
        static_cast<unsigned long long>(relative), narrow,
        info.unknown == reinterpret_cast<std::uintptr_t>(ntdll) ? "true"
                                                                : "false");

    if (info.section_handle) {
        SectionBasic basic = {};
        ULONG returned = 0;
        const HANDLE section = reinterpret_cast<HANDLE>(
            static_cast<std::uintptr_t>(info.section_handle));
        const LONG status =
            query_section(section, 0, &basic, sizeof(basic), &returned);
        std::uint32_t object[14] = {};
        ULONG object_returned = 0;
        const LONG object_status =
            query_object(section, 0, object, sizeof(object), &object_returned);
        std::printf(
            "{\"kind\":\"section\",\"query_status\":%lu,\"return_bytes\":%lu,"
            "\"maximum_bytes\":%llu,\"attributes\":%lu,\"base_nonnull\":%s,"
            "\"object_status\":%lu,\"object_return_bytes\":%lu,\"object_"
            "attributes\":%lu,\"granted_access\":%lu}\n",
            static_cast<ULONG>(status), returned,
            static_cast<unsigned long long>(basic.size.QuadPart),
            basic.attributes, basic.base ? "true" : "false",
            static_cast<ULONG>(object_status), object_returned,
            static_cast<ULONG>(object[0]), static_cast<ULONG>(object[1]));
    }
    if (info.work_list) {
        std::uint32_t header[12] = {};
        std::uint64_t copied = 0;
        LONG status = static_cast<LONG>(0xc0000002);
        if (info.work_list <= 0xffffffff) {
            SIZE_T read_bytes = 0;
            const bool success =
                ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<void *>(
                        static_cast<std::uintptr_t>(info.work_list)),
                    header, sizeof(header), &read_bytes) != FALSE;
            copied = read_bytes;
            status = success ? 0 : static_cast<LONG>(0xc0000005);
        } else if (read64) {
            status = read64(GetCurrentProcess(), info.work_list, header,
                            sizeof(header), &copied);
        }
        std::printf(
            "{\"kind\":\"work_list\",\"read64_available\":%s,\"address_above_"
            "32bit\":%s,\"status\":%lu,\"copied_bytes\":%llu,\"free_first\":%"
            "lu,\"free_counter\":%lu,\"work_first\":%lu,\"work_counter\":%lu,"
            "\"reserved_nonzero\":%s}\n",
            read64 ? "true" : "false",
            info.work_list > 0xffffffff ? "true" : "false",
            static_cast<ULONG>(status), static_cast<unsigned long long>(copied),
            static_cast<ULONG>(header[0]), static_cast<ULONG>(header[1]),
            static_cast<ULONG>(header[2]), static_cast<ULONG>(header[3]),
            (header[4] || header[5] || header[6] || header[7] || header[8] ||
             header[9] || header[10] || header[11])
                ? "true"
                : "false");
    }
    return 0;
}
