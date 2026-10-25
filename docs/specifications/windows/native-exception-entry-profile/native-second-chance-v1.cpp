#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <cstring>

static constexpr DWORD code = 0xe0425345;
static unsigned observed;

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
    if (!last && !invalid_record && !invalid_context)
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
    std::printf("{\"kind\":\"ready\",\"mode\":\"%s\",\"code\":%lu}\n", argv[1],
                code);
    __try {
        RtlCaptureContext(&context);
        record.ExceptionCode = code;
        record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        record.ExceptionAddress = program_counter(context);
        auto record_argument =
            invalid_record ? reinterpret_cast<PEXCEPTION_RECORD>(1) : &record;
        auto context_argument =
            invalid_context ? reinterpret_cast<PCONTEXT>(1) : &context;
        returned = raise(record_argument, context_argument, FALSE);
        call_returned = true;
    } __except (GetExceptionCode() == code ? EXCEPTION_EXECUTE_HANDLER
                                           : EXCEPTION_CONTINUE_SEARCH) {
        caught = GetExceptionCode();
    }
    const bool removed = RemoveVectoredExceptionHandler(handler) != 0;
    std::printf("{\"kind\":\"complete\",\"seen\":%u,\"caught\":%lu,"
                "\"call_returned\":%s,\"status\":%lu,\"removed\":%s}\n",
                observed, caught, call_returned ? "true" : "false",
                static_cast<DWORD>(returned), removed ? "true" : "false");
    if (!removed)
        return 5;
    if (invalid_record || invalid_context)
        return observed == 0 && caught == 0 && call_returned &&
                       static_cast<DWORD>(returned) == 0xc0000005
                   ? 0
                   : 7;
    return 8;
}
