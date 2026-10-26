// Read-only startup information from this process's two WoW64 TEB views.
#define WIN32_LEAN_AND_MEAN
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <intrin.h>
#include <windows.h>

#if !defined(_M_IX86)
#error This control observes the native 32-bit WoW64 process view.
#endif

namespace {
struct Information {
    std::uint32_t page_size, cpu_flags, execute_flags, unknown;
    std::uint64_t section_handle, work_list;
    std::uint16_t native_machine, emulated_machine;
};
static_assert(sizeof(Information) == 40);
static_assert(offsetof(Information, section_handle) == 16);
static_assert(offsetof(Information, native_machine) == 32);
std::uint32_t main_information;
std::uint32_t main_words[4];

template <typename T> bool read(std::uintptr_t address, T &value) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(),
                             reinterpret_cast<const void *>(address), &value,
                             sizeof(value), &copied) &&
           copied == sizeof(value);
}

bool observe(const char *sample, bool primary) {
    const std::uintptr_t teb = __readfsdword(0x18);
    std::uint32_t self = 0, peb = 0, slot32 = 0;
    std::int32_t displacement = 0;
    if (!read(teb + 0x18, self) || !read(teb + 0x30, peb) ||
        !read(teb + 0xfdc, displacement) || !read(teb + 0xe38, slot32))
        return false;

    const std::uintptr_t native_teb =
        displacement < 0 ? teb + displacement : teb;
    std::uint32_t candidate_self = 0;
    if (!read(native_teb + 0x18, candidate_self))
        return false;
    const bool native32 = candidate_self == native_teb;
    std::uint32_t information = 0;
    if (!read(native_teb + (native32 ? 0xe38 : 0x14d0), information) ||
        !information)
        return false;
    Information extended = {};
    if (!read(information, extended))
        return false;
    const std::uint32_t words[4] = {extended.page_size, extended.cpu_flags,
                                    extended.execute_flags, extended.unknown};

    std::uint64_t native_self = 0, native32_link = 0;
    std::int32_t reverse_displacement = 0;
    bool native_self_matches = false, native32_link_matches = false,
         roundtrip = false;
    if (!native32) {
        if (!read(native_teb + 0x30, native_self) ||
            !read(native_teb, native32_link) ||
            !read(native_teb + 0x180c, reverse_displacement))
            return false;
        native_self_matches = native_self == native_teb;
        native32_link_matches = native32_link == teb;
        roundtrip = native_teb + reverse_displacement == teb;
    }
    if (primary) {
        main_information = information;
        for (unsigned index = 0; index != 4; ++index)
            main_words[index] = words[index];
    }
    bool same_words = true;
    for (unsigned index = 0; index != 4; ++index)
        same_words = same_words && words[index] == main_words[index];
    using GetVersion = LONG(WINAPI *)(OSVERSIONINFOW *);
    using GetMachines = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
    const auto version_function = reinterpret_cast<GetVersion>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    const auto machine_function = reinterpret_cast<GetMachines>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    USHORT process_machine = 0, native_machine = 0;
    if (!version_function || version_function(&version) != 0 ||
        !machine_function ||
        !machine_function(GetCurrentProcess(), &process_machine,
                          &native_machine))
        return false;
    SYSTEM_INFO system = {};
    GetNativeSystemInfo(&system);
    std::printf(
        "{\"sample\":\"%s\",\"teb32_self\":%s,\"wow_teb_offset\":%ld,"
        "\"native_teb_is_32\":%s,\"native_teb_self\":%s,\"native_teb_32_link\":"
        "%s,"
        "\"reverse_wow_teb_offset\":%ld,\"teb_roundtrip\":%s,"
        "\"tls32_information_nonnull\":%s,\"tls_views_same\":%s,"
        "\"shared_information_with_main\":%s,\"same_words_as_main\":%s,"
        "\"information_minus_peb32\":%lld,\"information_words\":[%lu,%lu,%lu],"
        "\"unknown_word_nonzero\":%s,"
        "\"native_page_size\":%lu,\"native_processor_architecture\":%u,"
        "\"build\":%lu,\"process_machine\":%u,\"native_machine\":%u,"
        "\"information_native_machine\":%u,\"information_emulated_machine\":%u,"
        "\"section_handle_nonnull\":%s,\"work_list_nonnull\":%s}\n",
        sample, self == teb ? "true" : "false", static_cast<long>(displacement),
        native32 ? "true" : "false", native_self_matches ? "true" : "false",
        native32_link_matches ? "true" : "false",
        static_cast<long>(reverse_displacement), roundtrip ? "true" : "false",
        slot32 ? "true" : "false", slot32 == information ? "true" : "false",
        information == main_information ? "true" : "false",
        same_words ? "true" : "false",
        static_cast<long long>(information) - peb,
        static_cast<unsigned long>(words[0]),
        static_cast<unsigned long>(words[1]),
        static_cast<unsigned long>(words[2]), words[3] ? "true" : "false",
        system.dwPageSize, system.wProcessorArchitecture, version.dwBuildNumber,
        process_machine, native_machine, extended.native_machine,
        extended.emulated_machine, extended.section_handle ? "true" : "false",
        extended.work_list ? "true" : "false");
    return self == teb && displacement < 0 && !native32 &&
           native_self_matches && native32_link_matches && roundtrip &&
           words[0] == system.dwPageSize && same_words &&
           extended.native_machine == native_machine &&
           extended.emulated_machine == process_machine &&
           information == main_information;
}

DWORD WINAPI worker(void *) { return observe("thread", false) ? 0 : 12; }
} // namespace

int main() {
    if (!observe("main", true))
        return 10;
    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    if (!thread)
        return 11;
    const DWORD waited = WaitForSingleObject(thread, 10000);
    DWORD code = 13;
    const bool completed =
        waited == WAIT_OBJECT_0 && GetExitCodeThread(thread, &code);
    const bool closed = CloseHandle(thread) != FALSE;
    return completed && closed ? static_cast<int>(code) : 13;
}
