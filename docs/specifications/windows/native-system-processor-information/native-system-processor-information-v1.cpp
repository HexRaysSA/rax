#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <intrin.h>
#include <windows.h>

#if !defined(_M_IX86) && !defined(_M_X64) && !defined(_M_ARM64)
#error Windows x86, x64 or ARM64 control required.
#endif

using Query = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);

static ULONG invoke(Query query, ULONG cls, void *output, ULONG length,
                    ULONG *returned, ULONG &raised) {
    __try {
        return static_cast<ULONG>(query(cls, output, length, returned));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = GetExceptionCode();
        return raised;
    }
}

static void row(Query query, const char *api, ULONG cls, ULONG length,
                const char *mode) {
    auto *data = static_cast<unsigned char *>(
        VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    auto *ret = static_cast<unsigned char *>(
        VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!data || !ret)
        ExitProcess(13);
    std::memset(data, 0xa5, 8192);
    std::memset(ret, 0xcc, 8192);
    auto *output = data + 128;
    auto *returned = reinterpret_cast<ULONG *>(ret + 128);
    DWORD ignored = 0;
    if (!std::strcmp(mode, "null_output"))
        output = nullptr;
    else if (!std::strcmp(mode, "misaligned_output"))
        ++output;
    else if (!std::strcmp(mode, "null_return"))
        returned = nullptr;
    else if (!std::strcmp(mode, "misaligned_return"))
        returned = reinterpret_cast<ULONG *>(ret + 129);
    else if (!std::strcmp(mode, "bad_return")) {
        returned = reinterpret_cast<ULONG *>(ret + 4096);
        VirtualProtect(ret + 4096, 4096, PAGE_NOACCESS, &ignored);
    } else if (!std::strcmp(mode, "readonly_output"))
        VirtualProtect(data, 4096, PAGE_READONLY, &ignored);
    else if (!std::strcmp(mode, "guard_output"))
        VirtualProtect(data, 4096, PAGE_READWRITE | PAGE_GUARD, &ignored);
    else if (!std::strcmp(mode, "alias_return"))
        returned = reinterpret_cast<ULONG *>(output);
    if (!std::strcmp(mode, "cross12") || !std::strcmp(mode, "cross44")) {
        output = data + 4096 - (!std::strcmp(mode, "cross12") ? 12 : 44);
        VirtualProtect(data + 4096, 4096, PAGE_NOACCESS, &ignored);
    } else if (!std::strcmp(mode, "readonly_guard_output")) {
        VirtualProtect(data, 4096, PAGE_READONLY | PAGE_GUARD, &ignored);
    } else if (!std::strcmp(mode, "guard_return")) {
        VirtualProtect(ret, 4096, PAGE_READWRITE | PAGE_GUARD, &ignored);
    } else if (!std::strcmp(mode, "both_guard")) {
        VirtualProtect(data, 4096, PAGE_READWRITE | PAGE_GUARD, &ignored);
        VirtualProtect(ret, 4096, PAGE_READWRITE | PAGE_GUARD, &ignored);
    } else if (!std::strcmp(mode, "readonly_return")) {
        VirtualProtect(ret, 4096, PAGE_READONLY, &ignored);
    } else if (!std::strcmp(mode, "return_cross2")) {
        returned = reinterpret_cast<ULONG *>(ret + 4094);
        VirtualProtect(ret + 4096, 4096, PAGE_NOACCESS, &ignored);
    }
    ULONG raised = 0;
    const ULONG status = invoke(query, cls, output, length, returned, raised);
    MEMORY_BASIC_INFORMATION info = {};
    VirtualQuery(data, &info, sizeof(info));
    const bool guard = (info.Protect & PAGE_GUARD) != 0;
    VirtualQuery(ret, &info, sizeof(info));
    const bool ret_guard = (info.Protect & PAGE_GUARD) != 0;
    VirtualProtect(data, 8192, PAGE_READWRITE, &ignored);
    VirtualProtect(ret, 8192, PAGE_READWRITE, &ignored);
    ULONG returned_value = 0;
    if (returned)
        std::memcpy(&returned_value, returned, 4);
    std::printf(
        "{\"kind\":\"query\",\"api\":\"%s\",\"class\":%lu,\"length\":%lu,"
        "\"mode\":\"%s\",\"status\":%lu,\"raised\":%lu,"
        "\"returned\":%lu,\"guard\":%s,\"return_guard\":%s,\"output\":\"",
        api, cls, length, mode, status, raised, returned_value,
        guard ? "true" : "false", ret_guard ? "true" : "false");
    if (output)
        for (unsigned i = 0; i < 80; ++i)
            std::printf("%02x", output[i]);
    std::puts("\"}");
    VirtualFree(data, 0, MEM_RELEASE);
    VirtualFree(ret, 0, MEM_RELEASE);
}

struct Version {
    ULONG size, major, minor, build, platform;
    wchar_t service_pack[128];
};
static_assert(sizeof(Version) == 276);

static void identity(HMODULE ntdll) {
    const auto version = reinterpret_cast<LONG(WINAPI *)(Version *)>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    const auto wow =
        reinterpret_cast<BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *)>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                           "IsWow64Process2"));
    Version v = {};
    v.size = static_cast<ULONG>(sizeof(v));
    USHORT process_machine = 0, native_machine = 0, shared_architecture = 0;
    SIZE_T copied = 0;
    if (!version || version(&v) || !wow ||
        !wow(GetCurrentProcess(), &process_machine, &native_machine) ||
        !ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<const void *>(std::uintptr_t(0x7ffe026a)),
            &shared_architecture, sizeof(shared_architecture), &copied) ||
        copied != sizeof(shared_architecture))
        ExitProcess(15);
    SYSTEM_INFO process = {}, native = {};
    GetSystemInfo(&process);
    GetNativeSystemInfo(&native);
#if defined(_M_ARM64)
    const char *arch = "arm64";
#elif defined(_M_X64)
    const char *arch = "x64";
#else
    const char *arch = "x86";
#endif
    std::printf(
        "{\"kind\":\"identity\",\"arch\":\"%s\",\"build\":%lu,"
        "\"process_machine\":%u,\"native_machine\":%u,\"shared_native_"
        "architecture\":%u,"
        "\"system_info\":[%u,%u,%u,%lu],\"native_system_info\":[%u,%u,%u,%lu],"
        "\"maximum_processors\":%lu,\"active_processors\":%lu,\"cpuid1\":",
        arch, v.build, unsigned(process_machine), unsigned(native_machine),
        unsigned(shared_architecture), unsigned(process.wProcessorArchitecture),
        unsigned(process.wProcessorLevel), unsigned(process.wProcessorRevision),
        process.dwNumberOfProcessors, unsigned(native.wProcessorArchitecture),
        unsigned(native.wProcessorLevel), unsigned(native.wProcessorRevision),
        native.dwNumberOfProcessors,
        GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS),
        GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
#if defined(_M_IX86) || defined(_M_X64)
    int cpuid[4] = {};
    __cpuidex(cpuid, 1, 0);
    std::printf("[%u,%u,%u,%u]", unsigned(cpuid[0]), unsigned(cpuid[1]),
                unsigned(cpuid[2]), unsigned(cpuid[3]));
#else
    std::printf("null");
#endif
    std::printf(",\"processor_features\":[");
    bool first = true;
    for (unsigned index :
         {2u,  6u,  10u, 13u, 14u, 17u, 18u, 19u, 24u, 25u, 27u, 28u,
          29u, 30u, 31u, 32u, 33u, 34u, 36u, 37u, 38u, 39u, 40u, 41u}) {
        unsigned char shared = 0;
        copied = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<void *>(std::uintptr_t(0x7ffe0274) + index),
                &shared, 1, &copied) ||
            copied != 1)
            ExitProcess(16);
        std::printf("%s[%u,%s,%u]", first ? "" : ",", index,
                    IsProcessorFeaturePresent(index) ? "true" : "false",
                    unsigned(shared));
        first = false;
    }
    std::puts("]}");
}

int main() {
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    identity(ntdll);
    const char *apis[] = {"NtQuerySystemInformation",
                          "NtWow64GetNativeSystemInformation"};
    const char *modes[] = {
        "valid",           "null_output",       "misaligned_output",
        "null_return",     "misaligned_return", "bad_return",
        "readonly_output", "guard_output",      "readonly_guard_output",
        "cross12",         "cross44",           "alias_return",
        "guard_return",    "both_guard",        "readonly_return",
        "return_cross2"};
    for (const char *api : apis) {
        auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, api));
        if (!query) {
            if (!std::strcmp(api, "NtQuerySystemInformation"))
                return 14;
            std::printf("{\"kind\":\"unavailable_api\",\"api\":\"%s\"}\n", api);
            continue;
        }
        for (ULONG cls : {1ul, 63ul})
            for (ULONG length : {0ul, 11ul, 12ul, 13ul, 64ul, 0xfffffffful})
                for (const char *mode : modes)
                    row(query, api, cls, length, mode);
        for (ULONG cls : {0ul, 62ul, 114ul})
            for (ULONG length : {0ul, 12ul, 44ul, 63ul, 64ul, 65ul, 128ul})
                row(query, api, cls, length, "valid");
        for (ULONG cls : {2ul, 50ul, 55ul, 0xfffffffful})
            for (ULONG length : {0ul, 12ul, 64ul})
                row(query, api, cls, length, "valid");
    }
    return 0;
}
