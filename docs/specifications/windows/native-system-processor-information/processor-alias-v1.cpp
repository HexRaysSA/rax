#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <windows.h>

using Query = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);

struct Version {
    ULONG size, major, minor, build, platform;
    wchar_t service_pack[128];
};

int main() {
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
        auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, name));
        if (!query) {
            std::printf("{\"kind\":\"unavailable_api\",\"api\":\"%s\"}\n",
                        name);
            continue;
        }
        for (ULONG cls : {1ul, 63ul}) {
            for (unsigned offset = 0; offset <= 16; ++offset) {
                alignas(16) unsigned char data[80];
                std::memset(data, 0xa5, sizeof(data));
                auto returned = reinterpret_cast<ULONG *>(data + offset);
                const auto status =
                    static_cast<ULONG>(query(cls, data, 12, returned));
                ULONG value = 0;
                std::memcpy(&value, returned, 4);
                std::printf("{\"kind\":\"alias\",\"api\":\"%s\",\"class\":%lu,"
                            "\"offset\":%u,\"status\":%lu,\"returned\":%lu,"
                            "\"output\":\"",
                            name, cls, offset, status, value);
                for (auto byte : data)
                    std::printf("%02x", unsigned(byte));
                std::puts("\"}");
            }
        }
    }
    return 0;
}
