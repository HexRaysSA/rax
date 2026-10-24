#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <windows.h>

struct Observation {
    unsigned seen;
    DWORD code;
    DWORD flags;
    DWORD context_flags;
    DWORD parameters;
    std::int64_t record_to_context;
    std::int64_t context_to_sp;
    std::int64_t record_to_sp;
    unsigned context_alignment;
    unsigned sp_alignment;
    bool pc_matches;
};

static Observation observation;
static std::uintptr_t scratch;

static std::int64_t delta(std::uintptr_t a, std::uintptr_t b) {
    return a >= b ? static_cast<std::int64_t>(a - b)
                  : -static_cast<std::int64_t>(b - a);
}

static LONG CALLBACK observe(EXCEPTION_POINTERS *pointers) {
    const auto *record = pointers->ExceptionRecord;
    const auto *context = pointers->ContextRecord;
    if (record->NumberParameters < 2 ||
        record->ExceptionInformation[1] < scratch ||
        record->ExceptionInformation[1] - scratch >= 4096 ||
        (record->ExceptionCode != 0xc0000005 &&
         record->ExceptionCode != 0x80000001)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
#if defined(_M_ARM64)
    const auto sp = static_cast<std::uintptr_t>(context->Sp);
    const auto pc = static_cast<std::uintptr_t>(context->Pc);
#elif defined(_M_X64)
    const auto sp = static_cast<std::uintptr_t>(context->Rsp);
    const auto pc = static_cast<std::uintptr_t>(context->Rip);
#elif defined(_M_IX86)
    const auto sp = static_cast<std::uintptr_t>(context->Esp);
    const auto pc = static_cast<std::uintptr_t>(context->Eip);
#else
#error Unsupported observer ABI
#endif
    const auto record_at = reinterpret_cast<std::uintptr_t>(record);
    const auto context_at = reinterpret_cast<std::uintptr_t>(context);
    ++observation.seen;
    observation.code = record->ExceptionCode;
    observation.flags = record->ExceptionFlags;
    observation.context_flags = context->ContextFlags;
    observation.parameters = record->NumberParameters;
    observation.record_to_context = delta(record_at, context_at);
    observation.context_to_sp = delta(context_at, sp);
    observation.record_to_sp = delta(record_at, sp);
    observation.context_alignment = static_cast<unsigned>(context_at % 16);
    observation.sp_alignment = static_cast<unsigned>(sp % 16);
    observation.pc_matches =
        pc == reinterpret_cast<std::uintptr_t>(record->ExceptionAddress);
    return EXCEPTION_CONTINUE_SEARCH;
}

static bool run_case(unsigned ordinal) {
    auto *page = static_cast<volatile DWORD *>(
        VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!page) {
        return false;
    }
    scratch = reinterpret_cast<std::uintptr_t>(page);
    *page = 0x12345678;
    DWORD old = 0;
    const DWORD protection = ordinal == 0   ? PAGE_NOACCESS
                             : ordinal == 1 ? PAGE_READONLY
                                            : PAGE_READWRITE | PAGE_GUARD;
    if (!VirtualProtect(const_cast<DWORD *>(page), 4096, protection, &old)) {
        VirtualFree(const_cast<DWORD *>(page), 0, MEM_RELEASE);
        return false;
    }
    observation = {};
    DWORD caught = 0;
    __try {
        if (ordinal & 1) {
            *page = 0x76543210;
        } else {
            const volatile DWORD value = *page;
            (void)value;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        caught = GetExceptionCode();
    }
    const bool freed =
        VirtualFree(const_cast<DWORD *>(page), 0, MEM_RELEASE) != FALSE;
    std::printf(
        "{\"kind\":\"case\",\"ordinal\":%u,\"caught\":\"%08lX\",\"seen\":%u,"
        "\"code\":\"%08lX\",\"flags\":%lu,\"context_flags\":\"%08lX\","
        "\"parameters\":%lu,\"record_to_context_bytes\":%lld,"
        "\"context_to_fault_sp_bytes\":%lld,\"record_to_fault_sp_bytes\":%lld,"
        "\"context_mod16\":%u,\"fault_sp_mod16\":%u,\"pc_matches\":%s,"
        "\"freed\":%s}\n",
        ordinal, caught, observation.seen, observation.code, observation.flags,
        observation.context_flags, observation.parameters,
        static_cast<long long>(observation.record_to_context),
        static_cast<long long>(observation.context_to_sp),
        static_cast<long long>(observation.record_to_sp),
        observation.context_alignment, observation.sp_alignment,
        observation.pc_matches ? "true" : "false", freed ? "true" : "false");
    return freed && observation.seen == 1 && observation.pc_matches &&
           caught == (ordinal < 2 ? DWORD(0xc0000005) : DWORD(0x80000001));
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    auto module = GetModuleHandleW(L"ntdll.dll");
    using Version = LONG(WINAPI *)(OSVERSIONINFOW *);
    auto version_query =
        reinterpret_cast<Version>(GetProcAddress(module, "RtlGetVersion"));
    OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    if (!module || !version_query || version_query(&version) != 0) {
        return 1;
    }
    auto base = reinterpret_cast<std::uintptr_t>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    const auto size = nt->OptionalHeader.SizeOfImage;
    std::printf("{\"kind\":\"host\",\"build\":%lu,\"pointer_bytes\":%zu,"
                "\"context_bytes\":%zu,\"record_bytes\":%zu,\"ntdll_machine\":%"
                "u,\"ntdll_image_bytes\":%lu}\n",
                version.dwBuildNumber, sizeof(void *), sizeof(CONTEXT),
                sizeof(EXCEPTION_RECORD),
                static_cast<unsigned>(nt->FileHeader.Machine),
                static_cast<unsigned long>(size));
    const char *names[] = {"KiUserExceptionDispatcher", "RtlDispatchException"};
    for (unsigned index = 0; index < 2; ++index) {
        const char *name = names[index];
        auto address =
            reinterpret_cast<std::uintptr_t>(GetProcAddress(module, name));
        if (address == 0 && index == 1) {
            std::printf(
                "{\"kind\":\"code\",\"export\":\"%s\",\"available\":false}\n",
                name);
            continue;
        }
        if (address < base || address - base > size ||
            size - (address - base) < 192) {
            return 2;
        }
        std::printf(
            "{\"kind\":\"code\",\"export\":\"%s\",\"rva\":%llu,\"hex\":\"",
            name, static_cast<unsigned long long>(address - base));
        auto bytes = reinterpret_cast<const unsigned char *>(address);
        for (unsigned i = 0; i < 192; ++i) {
            std::printf("%02x", bytes[i]);
        }
        std::printf("\"}\n");
    }
    auto handler = AddVectoredExceptionHandler(1, observe);
    if (!handler) {
        return 3;
    }
    bool passed = true;
    for (unsigned i = 0; i < 4; ++i) {
        passed = run_case(i) && passed;
    }
    const bool removed = RemoveVectoredExceptionHandler(handler) != 0;
    std::printf("{\"kind\":\"complete\",\"cases\":4,\"handler_removed\":%s}\n",
                removed ? "true" : "false");
    return passed && removed ? 0 : 4;
}
