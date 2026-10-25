#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>

using Raise = LONG(NTAPI *)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);

__declspec(noinline) static void capture(CONTEXT *context) {
    RtlCaptureContext(context);
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

static void observe(Raise raise, unsigned mode, uintptr_t pointer) {
    CONTEXT context{};
    capture(&context);
    EXCEPTION_RECORD record{};
    record.ExceptionCode = 0xe0425345;
    record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    record.ExceptionAddress = program_counter(context);
    const auto input_record =
        mode == 1 ? &record : reinterpret_cast<PEXCEPTION_RECORD>(pointer);
    const auto input_context =
        mode == 0 ? &context : reinterpret_cast<PCONTEXT>(pointer);
    LONG status = 0;
    DWORD caught = 0;
    bool returned = false;
    __try {
        status = raise(input_record, input_context, FALSE);
        returned = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        caught = GetExceptionCode();
    }
    std::printf("{\"kind\":\"case\",\"mode\":%u,\"pointer\":%llu,\"status\":%"
                "lu,\"returned\":%s,\"caught\":%lu}\n",
                mode, static_cast<unsigned long long>(pointer),
                static_cast<DWORD>(status), returned ? "true" : "false",
                caught);
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    auto raise =
        reinterpret_cast<Raise>(GetProcAddress(module, "NtRaiseException"));
    using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
    auto version =
        reinterpret_cast<Version>(GetProcAddress(module, "RtlGetVersion"));
    USHORT process_machine = 0, native_machine = 0;
    OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (!raise || !version || version(&info) < 0 ||
        !IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine))
        return 2;
    std::printf("{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
                "\"native_machine\":%u,\"pointer_bytes\":%zu}\n",
                info.dwBuildNumber, process_machine, native_machine,
                sizeof(void *));
    constexpr uintptr_t pointers[] = {0, 1,  2,  3,  4,  7,
                                      8, 12, 15, 16, 32, 4096};
    for (unsigned mode = 0; mode != 3; ++mode)
        for (uintptr_t pointer : pointers)
            observe(raise, mode, pointer);
    return 0;
}
