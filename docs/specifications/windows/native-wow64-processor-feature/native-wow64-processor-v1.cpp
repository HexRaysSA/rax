#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <initializer_list>

#if !defined(_M_IX86)
#error This control requires the WoW64 x86 executable view.
#endif

using Query = ULONG(NTAPI *)(ULONG);
using RtlQuery = BOOLEAN(NTAPI *)(ULONG);

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    const auto query = reinterpret_cast<Query>(
        GetProcAddress(module, "NtWow64IsProcessorFeaturePresent"));
    const auto rtl = reinterpret_cast<RtlQuery>(
        GetProcAddress(module, "RtlIsProcessorFeaturePresent"));
    using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
    const auto version =
        reinterpret_cast<Version>(GetProcAddress(module, "RtlGetVersion"));
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    USHORT process_machine = 0, native_machine = 0;
    if (!query || !rtl || !version || version(&info) < 0 ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 2;
    std::printf("{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
                "\"native_machine\":%u,\"pointer_bytes\":%zu}\n",
                info.dwBuildNumber, process_machine, native_machine,
                sizeof(void *));
    const auto observe = [&](ULONG feature) {
        std::printf("{\"kind\":\"feature\",\"index\":%lu,\"nt\":%lu,"
                    "\"rtl\":%u,\"win32\":%u}\n",
                    feature, query(feature),
                    static_cast<unsigned>(rtl(feature)),
                    IsProcessorFeaturePresent(feature) ? 1u : 0u);
    };
    for (ULONG feature = 0; feature != 256; ++feature)
        observe(feature);
    for (ULONG feature : {0x10000ul, 0x80000000ul, 0xfffffffful})
        observe(feature);
    return 0;
}
