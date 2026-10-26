#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <windows.h>

using Query = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);

struct Version {
    ULONG size, major, minor, build, platform;
    wchar_t service_pack[128];
};

static ULONG invoke(Query query, ULONG cls, void *output, ULONG *returned,
                    ULONG &raised) {
    __try {
        return static_cast<ULONG>(query(cls, output, 12, returned));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = GetExceptionCode();
        return raised;
    }
}

int main(int argc, char **argv) {
    if (argc != 4 ||
        (std::strcmp(argv[1], "NtQuerySystemInformation") &&
         std::strcmp(argv[1], "NtWow64GetNativeSystemInformation")))
        return 12;
    char *end = nullptr;
    const unsigned wanted_class = std::strtoul(argv[2], &end, 10);
    if (!end || *end || (wanted_class != 1 && wanted_class != 63))
        return 12;
    const unsigned wanted_offset = std::strtoul(argv[3], &end, 10);
    if (!end || *end || wanted_offset > 16)
        return 12;
#if defined(_M_ARM64)
    const char *arch = "arm64";
#elif defined(_M_X64)
    const char *arch = "x64";
#elif defined(_M_IX86)
    const char *arch = "x86";
#else
#error Windows ARM64, x64 or x86 required.
#endif
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto version_query = reinterpret_cast<LONG(NTAPI *)(Version *)>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    Version version = {};
    version.size = sizeof(version);
    USHORT process_machine = 0, native_machine = 0;
    if (!version_query || version_query(&version) ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 11;
    std::printf("{\"kind\":\"identity\",\"arch\":\"%s\",\"build\":%lu,"
                "\"native_machine\":%u}\n",
                arch, version.build, unsigned(native_machine));
    for (const char *name :
         {"NtQuerySystemInformation", "NtWow64GetNativeSystemInformation"}) {
        if (std::strcmp(name, argv[1]))
            continue;
        auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, name));
        if (!query) {
            std::printf("{\"kind\":\"unavailable_api\",\"api\":\"%s\"}\n",
                        name);
            continue;
        }
        for (ULONG cls : {1ul, 63ul}) {
            if (cls != wanted_class)
                continue;
            for (unsigned offset = 0; offset <= 16; ++offset) {
                if (offset != wanted_offset)
                    continue;
                alignas(16) unsigned char data[80];
                std::memset(data, 0xa5, sizeof(data));
                auto returned = reinterpret_cast<ULONG *>(data + offset);
                ULONG raised = 0;
                const auto status = invoke(query, cls, data, returned, raised);
                ULONG value = 0;
                std::memcpy(&value, returned, 4);
                std::printf("{\"kind\":\"alias\",\"api\":\"%s\",\"class\":%lu,"
                            "\"offset\":%u,\"status\":%lu,\"raised\":%lu,"
                            "\"returned\":%lu,"
                            "\"output\":\"",
                            name, cls, offset, status, raised, value);
                for (auto byte : data)
                    std::printf("%02x", unsigned(byte));
                std::puts("\"}");
                std::fflush(stdout);
            }
        }
    }
    return 0;
}
