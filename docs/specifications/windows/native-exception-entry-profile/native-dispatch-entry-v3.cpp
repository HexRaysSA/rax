#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define PSAPI_VERSION 2
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <psapi.h>
#include <string>

static std::uintptr_t pc(const CONTEXT &c) {
#if defined(_M_ARM64)
    return c.Pc;
#elif defined(_M_X64)
    return c.Rip;
#else
    return c.Eip;
#endif
}

static std::uintptr_t sp(const CONTEXT &c) {
#if defined(_M_ARM64)
    return c.Sp;
#elif defined(_M_X64)
    return c.Rsp;
#else
    return c.Esp;
#endif
}

static void set_pc(CONTEXT &c, std::uintptr_t value) {
#if defined(_M_ARM64)
    c.Pc = value;
#elif defined(_M_X64)
    c.Rip = value;
#else
    c.Eip = static_cast<DWORD>(value);
#endif
}

static std::int64_t delta(std::uintptr_t a, std::uintptr_t b) {
    return a >= b ? static_cast<std::int64_t>(a - b)
                  : -static_cast<std::int64_t>(b - a);
}

static unsigned observed;
static std::int64_t child_context_delta;
static std::int64_t child_record_delta;

static LONG CALLBACK observe(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode == 0xc0000005) {
        ++observed;
        child_context_delta =
            delta(reinterpret_cast<std::uintptr_t>(p->ContextRecord),
                  sp(*p->ContextRecord));
        child_record_delta =
            delta(reinterpret_cast<std::uintptr_t>(p->ExceptionRecord),
                  sp(*p->ContextRecord));
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static void perform_fault(volatile DWORD *p) {
    *p = 0x87654321;
}

static int child() {
    auto *p = static_cast<volatile DWORD *>(
        VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!p)
        return 10;
    *p = 0x12345678;
    DWORD old = 0;
    if (!VirtualProtect(const_cast<DWORD *>(p), 4096, PAGE_READONLY, &old)) {
        VirtualFree(const_cast<DWORD *>(p), 0, MEM_RELEASE);
        return 11;
    }
    auto handler = AddVectoredExceptionHandler(1, observe);
    if (!handler) {
        VirtualFree(const_cast<DWORD *>(p), 0, MEM_RELEASE);
        return 12;
    }
    DWORD caught = 0;
    __try {
        perform_fault(p);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        caught = GetExceptionCode();
    }
    const bool removed = RemoveVectoredExceptionHandler(handler) != 0;
    const bool freed =
        VirtualFree(const_cast<DWORD *>(p), 0, MEM_RELEASE) != FALSE;
    std::printf("{\"kind\":\"child_handler\",\"seen\":%u,\"caught\":\"%08lX\","
                "\"context_to_fault_sp_bytes\":%lld,\"record_to_fault_sp_"
                "bytes\":%lld,\"handler_removed\":%s,\"freed\":%s}\n",
                observed, caught, static_cast<long long>(child_context_delta),
                static_cast<long long>(child_record_delta),
                removed ? "true" : "false", freed ? "true" : "false");
    return caught == 0xc0000005 && observed == 1 && removed && freed ? 0 : 13;
}

static bool read(HANDLE process, std::uintptr_t address, void *out,
                 SIZE_T bytes) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                             out, bytes, &got) &&
           got == bytes;
}

static bool patch(HANDLE process, std::uintptr_t address, const void *data,
                  SIZE_T bytes) {
    DWORD old = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void *>(address), bytes,
                          PAGE_EXECUTE_READWRITE, &old))
        return false;
    SIZE_T written = 0;
    const bool stored =
        WriteProcessMemory(process, reinterpret_cast<void *>(address), data,
                           bytes, &written) &&
        written == bytes;
    const bool flushed =
        FlushInstructionCache(process, reinterpret_cast<void *>(address),
                              bytes) != FALSE;
    DWORD discarded = 0;
    const bool restored =
        VirtualProtectEx(process, reinterpret_cast<void *>(address), bytes, old,
                         &discarded) != FALSE;
    return stored && flushed && restored;
}

static bool same_file(const BY_HANDLE_FILE_INFORMATION &a,
                      const BY_HANDLE_FILE_INFORMATION &b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
           a.nFileIndexHigh == b.nFileIndexHigh &&
           a.nFileIndexLow == b.nFileIndexLow;
}

static bool capture(HANDLE process, const CONTEXT &entry, const CONTEXT &fault,
                    const EXCEPTION_RECORD &exception) {
    constexpr SIZE_T limit = 8192;
    if (sp(entry) >= sp(fault) || sp(fault) - sp(entry) > limit)
        return false;
    const auto length = static_cast<SIZE_T>(sp(fault) - sp(entry));
    alignas(16) std::array<unsigned char, limit> frame{};
    if (!read(process, sp(entry), frame.data(), length))
        return false;
    unsigned contexts = 0, records = 0;
    SIZE_T context_offset = 0, record_offset = 0;
    DWORD context_flags = 0;
    for (SIZE_T at = 0; at < length; at += 4) {
        if (sizeof(CONTEXT) <= length - at) {
            CONTEXT candidate{};
            std::memcpy(&candidate, frame.data() + at, sizeof(candidate));
            if (pc(candidate) == pc(fault) && sp(candidate) == sp(fault) &&
                (candidate.ContextFlags & 0x00ff0000) ==
                    (CONTEXT_CONTROL & 0x00ff0000)) {
                ++contexts;
                context_offset = at;
                context_flags = candidate.ContextFlags;
            }
        }
        if (sizeof(EXCEPTION_RECORD) <= length - at) {
            EXCEPTION_RECORD candidate{};
            std::memcpy(&candidate, frame.data() + at, sizeof(candidate));
            if (candidate.ExceptionCode == exception.ExceptionCode &&
                candidate.ExceptionFlags == 0 &&
                candidate.ExceptionAddress == exception.ExceptionAddress &&
                candidate.NumberParameters == 2 &&
                candidate.ExceptionInformation[0] ==
                    exception.ExceptionInformation[0] &&
                candidate.ExceptionInformation[1] ==
                    exception.ExceptionInformation[1]) {
                ++records;
                record_offset = at;
            }
        }
    }
    std::printf("{\"kind\":\"dispatcher_entry\",\"frame_bytes\":%zu,\"entry_sp_"
                "mod16\":%u,\"context_candidates\":%u,\"record_candidates\":%u,"
                "\"context_offset_bytes\":%zu,\"record_offset_bytes\":%zu,"
                "\"context_flags\":\"%08lX\",\"frame_captured\":%s}\n",
                length, static_cast<unsigned>(sp(entry) % 16), contexts,
                records, context_offset, record_offset, context_flags, "true");
    return contexts == 1 && records == 1;
}

static int parent();

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    return argc == 2 && std::strcmp(argv[1], "--child") == 0 ? child()
                                                             : parent();
}

static int parent() {
    std::array<wchar_t, 32768> path{}, ntpath{}, mapped{};
    const DWORD chars = GetModuleFileNameW(nullptr, path.data(),
                                           static_cast<DWORD>(path.size()));
    auto ntmodule = GetModuleHandleW(L"ntdll.dll");
    const DWORD ntchars = GetModuleFileNameW(ntmodule, ntpath.data(),
                                             static_cast<DWORD>(ntpath.size()));
    const DWORD mapped_chars =
        GetMappedFileNameW(GetCurrentProcess(), ntmodule, mapped.data(),
                           static_cast<DWORD>(mapped.size()));
    if (!chars || chars >= path.size() || !ntchars ||
        ntchars >= ntpath.size() || !mapped_chars ||
        mapped_chars >= mapped.size())
        return 20;
    const auto ntbase = reinterpret_cast<std::uintptr_t>(ntmodule);
    const auto entry_rva = reinterpret_cast<std::uintptr_t>(GetProcAddress(
                               ntmodule, "KiUserExceptionDispatcher")) -
                           ntbase;
    const auto ownbase =
        reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto fault_rva =
        reinterpret_cast<std::uintptr_t>(&perform_fault) - ownbase;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(ntbase);
    const auto nt =
        reinterpret_cast<const IMAGE_NT_HEADERS *>(ntbase + dos->e_lfanew);
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    using Version = LONG(WINAPI *)(OSVERSIONINFOW *);
    auto query_version =
        reinterpret_cast<Version>(GetProcAddress(ntmodule, "RtlGetVersion"));
    if (!query_version || query_version(&version) != 0)
        return 26;
    using QueryMachines = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
    auto query_machines = reinterpret_cast<QueryMachines>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
    USHORT process_machine = 0, native_machine = 0;
    if (!query_machines ||
        !query_machines(GetCurrentProcess(), &process_machine, &native_machine))
        return 27;
    std::printf("{\"kind\":\"host\",\"build\":%lu,\"native_processor_"
                "architecture\":%u,\"process_machine\":%u,\"native_machine\":%"
                "u,\"ntdll_machine\":%u,\"context_bytes\":%zu,"
                "\"record_bytes\":%zu,\"dispatcher_rva\":%llu}\n",
                version.dwBuildNumber,
                static_cast<unsigned>(system.wProcessorArchitecture),
                static_cast<unsigned>(process_machine),
                static_cast<unsigned>(native_machine),
                static_cast<unsigned>(nt->FileHeader.Machine), sizeof(CONTEXT),
                sizeof(EXCEPTION_RECORD),
                static_cast<unsigned long long>(entry_rva));
#if defined(_M_ARM64)
    constexpr SIZE_T instruction_bytes = 4;
    const std::array<unsigned char, 4> breakpoint{0x00, 0x00, 0x3e, 0xd4};
#else
    constexpr SIZE_T instruction_bytes = 1;
    const std::array<unsigned char, 4> breakpoint{0xcc, 0, 0, 0};
#endif
    if (entry_rva >= nt->OptionalHeader.SizeOfImage ||
        nt->OptionalHeader.SizeOfImage - entry_rva < instruction_bytes)
        return 21;
    constexpr SIZE_T code_bytes = 192;
    if (nt->OptionalHeader.SizeOfImage - entry_rva < code_bytes)
        return 28;
    std::printf("{\"kind\":\"code\",\"export\":\"KiUserExceptionDispatcher\","
                "\"rva\":%llu,\"hex\":\"",
                static_cast<unsigned long long>(entry_rva));
    const auto *instructions =
        reinterpret_cast<const unsigned char *>(ntbase + entry_rva);
    for (SIZE_T at = 0; at < code_bytes; ++at)
        std::printf("%02x", static_cast<unsigned>(instructions[at]));
    std::printf("\"}\n");
    auto ntfile =
        CreateFileW(ntpath.data(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    BY_HANDLE_FILE_INFORMATION own_file{};
    const bool have_file = ntfile != INVALID_HANDLE_VALUE &&
                           GetFileInformationByHandle(ntfile, &own_file);
    if (ntfile != INVALID_HANDLE_VALUE)
        CloseHandle(ntfile);
    HANDLE output = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE),
                         GetCurrentProcess(), &output, 0, TRUE,
                         DUPLICATE_SAME_ACCESS))
        return 22;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    auto input =
        CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
        CloseHandle(output);
        return 23;
    }
    std::wstring command = L"\"" + std::wstring(path.data()) + L"\" --child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output;
    startup.hStdError = output;
    startup.hStdInput = input;
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(path.data(), command.data(), nullptr,
                                        nullptr, TRUE, DEBUG_ONLY_THIS_PROCESS,
                                        nullptr, nullptr, &startup, &process);
    const DWORD launch_error = created ? 0 : GetLastError();
    CloseHandle(output);
    CloseHandle(input);
    if (!created) {
        std::printf("{\"kind\":\"create_failed\",\"error\":%lu}\n",
                    launch_error);
        return 24;
    }
    bool failed = !DebugSetProcessKillOnExit(TRUE);
    bool exited = false, fault_seen = false, installed = false,
         captured = false, restored = false;
    DWORD exit_code = 0xffffffff;
    unsigned loader_breaks = 0;
    std::uintptr_t child_base = 0, child_ntdll = 0, target = 0;
    CONTEXT fault{};
    EXCEPTION_RECORD fault_record{};
    std::array<unsigned char, 4> original{};
    const ULONGLONG started = GetTickCount64();
    for (unsigned events = 0;
         events < 512 && GetTickCount64() - started < 15000 && !exited;
         ++events) {
        DEBUG_EVENT event{};
        if (!WaitForDebugEventEx(&event, 100))
            continue;
        DWORD disposition = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            child_base = reinterpret_cast<std::uintptr_t>(
                event.u.CreateProcessInfo.lpBaseOfImage);
            if (event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            BY_HANDLE_FILE_INFORMATION file{};
            bool matches =
                have_file && event.u.LoadDll.hFile &&
                GetFileInformationByHandle(event.u.LoadDll.hFile, &file) &&
                same_file(own_file, file);
            if (!matches) {
                std::array<wchar_t, 32768> name{};
                const DWORD length = GetMappedFileNameW(
                    process.hProcess, event.u.LoadDll.lpBaseOfDll, name.data(),
                    static_cast<DWORD>(name.size()));
                matches = length && length < name.size() &&
                          _wcsicmp(name.data(), mapped.data()) == 0;
            }
            if (matches)
                child_ntdll = reinterpret_cast<std::uintptr_t>(
                    event.u.LoadDll.lpBaseOfDll);
            if (event.u.LoadDll.hFile)
                CloseHandle(event.u.LoadDll.hFile);
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto &exception = event.u.Exception.ExceptionRecord;
            const auto address =
                reinterpret_cast<std::uintptr_t>(exception.ExceptionAddress);
            disposition = DBG_EXCEPTION_NOT_HANDLED;
            if (!fault_seen && exception.ExceptionCode == 0xc0000005 &&
                event.u.Exception.dwFirstChance && child_base &&
                address >= child_base + fault_rva &&
                address - (child_base + fault_rva) < 64 &&
                exception.NumberParameters == 2 &&
                exception.ExceptionInformation[0] == 1 &&
                event.dwThreadId == process.dwThreadId) {
                fault.ContextFlags = CONTEXT_FULL;
                fault_record = exception;
                target = child_ntdll + entry_rva;
                fault_seen = true;
                const bool context_read =
                    GetThreadContext(process.hThread, &fault) != FALSE;
                const bool code_read =
                    child_ntdll && read(process.hProcess, target,
                                        original.data(), instruction_bytes);
                const bool same_code =
                    code_read && std::memcmp(original.data(),
                                             reinterpret_cast<const void *>(
                                                 ntbase + entry_rva),
                                             instruction_bytes) == 0;
                installed = context_read && same_code &&
                            patch(process.hProcess, target, breakpoint.data(),
                                  instruction_bytes);
                failed = failed || !installed;
                std::printf("{\"kind\":\"fault_stop\",\"context_read\":%s,"
                            "\"selected_ntdll_identity\":%s,\"breakpoint_"
                            "installed\":%s,\"fault_sp_mod16\":%u}\n",
                            context_read ? "true" : "false",
                            same_code ? "true" : "false",
                            installed ? "true" : "false",
                            static_cast<unsigned>(sp(fault) % 16));
            } else if (installed && address == target &&
                       (exception.ExceptionCode == 0x80000003 ||
                        exception.ExceptionCode == 0x4000001f) &&
                       event.dwThreadId == process.dwThreadId) {
                CONTEXT entry{};
                entry.ContextFlags = CONTEXT_FULL;
                const bool context_read =
                    GetThreadContext(process.hThread, &entry) != FALSE;
                captured = context_read && capture(process.hProcess, entry,
                                                   fault, fault_record);
                restored = patch(process.hProcess, target, original.data(),
                                 instruction_bytes);
                if (context_read) {
                    set_pc(entry, target);
                    restored =
                        (SetThreadContext(process.hThread, &entry) != FALSE) &&
                        restored;
                } else {
                    restored = false;
                }
                installed = false;
                failed = failed || !captured || !restored;
                disposition = DBG_CONTINUE;
            } else if (!fault_seen && event.u.Exception.dwFirstChance &&
                       (exception.ExceptionCode == 0x80000003 ||
                        exception.ExceptionCode == 0x4000001f) &&
                       loader_breaks++ < 4) {
                disposition = DBG_CONTINUE;
            } else if (!event.u.Exception.dwFirstChance) {
                failed = true;
                std::printf("{\"kind\":\"last_chance\",\"code\":\"%08lX\"}\n",
                            exception.ExceptionCode);
            }
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            exited = true;
            exit_code = event.u.ExitProcess.dwExitCode;
        }
        if (failed && !exited)
            TerminateProcess(process.hProcess, 97);
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                                disposition))
            failed = true;
    }
    if (!exited) {
        failed = true;
        TerminateProcess(process.hProcess, 98);
        for (unsigned events = 0; events < 128 && !exited; ++events) {
            DEBUG_EVENT event{};
            if (!WaitForDebugEventEx(&event, 50))
                continue;
            if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
                event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
            if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
                event.u.LoadDll.hFile)
                CloseHandle(event.u.LoadDll.hFile);
            if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                exited = true;
                exit_code = event.u.ExitProcess.dwExitCode;
            }
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                               DBG_CONTINUE);
        }
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 1000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::printf("{\"kind\":\"complete\",\"fault_seen\":%s,\"entry_captured\":%"
                "s,\"breakpoint_restored\":%s,\"child_exit\":%lu,\"child_"
                "wait\":%lu,\"failed\":%s}\n",
                fault_seen ? "true" : "false", captured ? "true" : "false",
                restored ? "true" : "false", exit_code, wait,
                failed ? "true" : "false");
    return !failed && fault_seen && captured && restored && exited &&
                   exit_code == 0 && wait == WAIT_OBJECT_0
               ? 0
               : 25;
}
