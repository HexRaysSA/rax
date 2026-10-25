#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <cstring>

static constexpr DWORD code = 0xe0425345;
static unsigned observed;

__declspec(noinline) static void capture(CONTEXT *context) {
    RtlCaptureContext(context);
}

static LONG CALLBACK observe(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode == code) {
        ++observed;
        std::printf("{\"kind\":\"handler\",\"ordinal\":%u}\n", observed);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void *program_counter(const CONTEXT &context) {
#if defined(_M_ARM64)
    return reinterpret_cast<void *>(context.Pc);
#elif defined(_M_X64)
    return reinterpret_cast<void *>(context.Rip);
#else
    return reinterpret_cast<void *>(static_cast<ULONG_PTR>(context.Eip));
#endif
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    const bool last = std::strcmp(argv[1], "last") == 0;
    const bool invalid_record = std::strcmp(argv[1], "invalid-record") == 0;
    const bool invalid_context = std::strcmp(argv[1], "invalid-context") == 0;
    const bool split = std::strcmp(argv[1], "context-split") == 0;
    const bool split_aligned =
        std::strcmp(argv[1], "context-split-aligned") == 0;
    unsigned char *split_buffer = nullptr;
    unsigned record_offset = 0, context_offset = 0;
    for (unsigned offset = 1; offset <= 32; ++offset) {
        char mode[32];
        std::snprintf(mode, sizeof(mode), "record-%u", offset);
        if (std::strcmp(argv[1], mode) == 0)
            record_offset = offset;
        std::snprintf(mode, sizeof(mode), "context-%u", offset);
        if (std::strcmp(argv[1], mode) == 0)
            context_offset = offset;
    }
    if (!last && !invalid_record && !invalid_context && !record_offset &&
        !context_offset && !split && !split_aligned)
        return 3;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    using Raise = LONG(NTAPI *)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
    auto raise = reinterpret_cast<Raise>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtRaiseException"));
    auto handler = AddVectoredExceptionHandler(1, observe);
    if (!raise || !handler)
        return 4;
    CONTEXT context{};
    EXCEPTION_RECORD record{};
    DWORD caught = 0;
    LONG returned = 0;
    bool call_returned = false;
    using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
    auto version = reinterpret_cast<Version>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    USHORT process_machine = 0, native_machine = 0;
    if (!version || version(&info) < 0 ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 9;
    std::printf(
        "{\"kind\":\"ready\",\"mode\":\"%s\",\"code\":%lu,\"build\":%lu,"
        "\"process_machine\":%u,\"native_machine\":%u,\"pointer_bytes\":%zu}\n",
        argv[1], code, info.dwBuildNumber, process_machine, native_machine,
        sizeof(void *));
    alignas(CONTEXT) unsigned char context_bytes[sizeof(CONTEXT) + 64]{};
    alignas(EXCEPTION_RECORD) unsigned char
        record_bytes[sizeof(EXCEPTION_RECORD) + 64]{};
    __try {
        capture(&context);
        record.ExceptionCode = code;
        record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        record.ExceptionAddress = program_counter(context);
        std::memcpy(record_bytes + record_offset, &record, sizeof(record));
        std::memcpy(context_bytes + context_offset, &context, sizeof(context));
        auto record_argument = invalid_record
                                   ? reinterpret_cast<PEXCEPTION_RECORD>(1)
                                   : reinterpret_cast<PEXCEPTION_RECORD>(
                                         record_bytes + record_offset);
        auto context_argument =
            invalid_context
                ? reinterpret_cast<PCONTEXT>(1)
                : reinterpret_cast<PCONTEXT>(context_bytes + context_offset);
        if (split || split_aligned) {
            split_buffer = static_cast<unsigned char *>(VirtualAlloc(
                nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            if (!split_buffer)
                return 10;
            auto bytes = split_buffer + 4096 - sizeof(CONTEXT) +
                         (split_aligned ? 16 : 1);
            std::memcpy(bytes, &context, sizeof(context));
            DWORD old = 0;
            if (!VirtualProtect(split_buffer + 4096, 4096, PAGE_NOACCESS, &old))
                return 11;
            context_argument = reinterpret_cast<PCONTEXT>(bytes);
        }
        returned = raise(record_argument, context_argument, FALSE);
        call_returned = true;
    } __except (GetExceptionCode() == code ? EXCEPTION_EXECUTE_HANDLER
                                           : EXCEPTION_CONTINUE_SEARCH) {
        caught = GetExceptionCode();
    }
    if (split_buffer && !VirtualFree(split_buffer, 0, MEM_RELEASE))
        return 12;
    const bool removed = RemoveVectoredExceptionHandler(handler) != 0;
    std::printf("{\"kind\":\"complete\",\"seen\":%u,\"caught\":%lu,"
                "\"call_returned\":%s,\"status\":%lu,\"removed\":%s}\n",
                observed, caught, call_returned ? "true" : "false",
                static_cast<DWORD>(returned), removed ? "true" : "false");
    if (!removed)
        return 5;
    // Exact statuses and expected process termination belong to the driver.
    return observed == 0 && caught == 0 && call_returned ? 0 : 7;
}
