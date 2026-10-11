// Fresh controlled child only: catch installed LdrInitializeThunk before its
// first instruction. A private COW breakpoint is removed by process teardown.
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static bool read(HANDLE process, ULONG_PTR address, void *out, SIZE_T size) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, reinterpret_cast<void *>(address), out, size, &got) && got == size;
}
static bool context(HANDLE thread, CONTEXT &state) {
    state = {};
    state.ContextFlags = CONTEXT_FULL;
#if defined(_M_ARM64)
    state.ContextFlags |= CONTEXT_ARM64_X18;
#endif
    return GetThreadContext(thread, &state) != 0;
}
static ULONG_PTR pc(const CONTEXT &state) {
#if defined(_M_ARM64)
    return state.Pc;
#elif defined(_M_X64)
    return state.Rip;
#else
    return state.Eip;
#endif
}
int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup, &child)) {
        std::printf("create error=%lu\n", GetLastError()); return 3;
    }
    bool good = true, pending = false, caught = false;
    DEBUG_EVENT event{};
    CONTEXT state{};
    good = context(child.hThread, state);
    MEMORY_BASIC_INFORMATION region{};
    good = good && VirtualQueryEx(child.hProcess, reinterpret_cast<void *>(pc(state)), &region, sizeof(region)) == sizeof(region);
    const auto self = reinterpret_cast<ULONG_PTR>(GetModuleHandleW(L"ntdll.dll"));
    const auto entry = reinterpret_cast<ULONG_PTR>(GetProcAddress(reinterpret_cast<HMODULE>(self), "LdrInitializeThunk"));
    const ULONG_PTR target = reinterpret_cast<ULONG_PTR>(region.AllocationBase) + (entry - self);
    std::printf("profile width=%zu child=%lu module=%llX initial-pc=%llX loader-rva=%llX target=%llX\n",
        sizeof(void *), child.dwProcessId, reinterpret_cast<unsigned long long>(region.AllocationBase),
        static_cast<unsigned long long>(pc(state)), static_cast<unsigned long long>(entry - self), static_cast<unsigned long long>(target));
    BYTE original[4]{};
#if defined(_M_ARM64)
    const DWORD trap = 0xD43E0000; const SIZE_T count = 4;
#else
    const DWORD trap = 0xCC; const SIZE_T count = 1;
#endif
    DWORD previous = 0, discarded = 0;
    SIZE_T written = 0;
    good = good && entry >= self && read(child.hProcess, target, original, count);
    good = good && VirtualProtectEx(child.hProcess, reinterpret_cast<void *>(target), count, PAGE_EXECUTE_READWRITE, &previous);
    if (good) {
        good = WriteProcessMemory(child.hProcess, reinterpret_cast<void *>(target), &trap, count, &written) && written == count;
        good = VirtualProtectEx(child.hProcess, reinterpret_cast<void *>(target), count, previous, &discarded) && good;
        good = FlushInstructionCache(child.hProcess, reinterpret_cast<void *>(target), count) && good;
    }
    std::printf("patch ok=%u bytes=%llu original=%02X%02X%02X%02X\n", good, static_cast<unsigned long long>(count), original[0], original[1], original[2], original[3]);
    good = good && ResumeThread(child.hThread) != static_cast<DWORD>(-1);
    const ULONGLONG started = GetTickCount64();
    while (good && !caught && GetTickCount64() - started < 15000) {
        if (!WaitForDebugEvent(&event, 100)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            std::printf("debug wait error=%lu\n", GetLastError()); good = false; break;
        }
        pending = true;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto &record = event.u.Exception.ExceptionRecord;
            const auto address = reinterpret_cast<ULONG_PTR>(record.ExceptionAddress);
            std::printf("exception code=%08lX address=%llX first=%lu thread=%lu\n", record.ExceptionCode, static_cast<unsigned long long>(address), event.u.Exception.dwFirstChance, event.dwThreadId);
            if (address == target && event.dwThreadId == child.dwThreadId) {
                caught = context(child.hThread, state);
                ULONG_PTR saved = 0, parameter = 0;
#if defined(_M_ARM64)
                saved = state.X0; parameter = state.X1;
#elif defined(_M_X64)
                saved = state.Rcx; parameter = state.Rdx;
#else
                ULONG_PTR args[2]{};
                caught = read(child.hProcess, state.Esp + 4, args, sizeof(args)) && caught;
                saved = args[0]; parameter = args[1];
#endif
                CONTEXT resume{};
                caught = read(child.hProcess, saved, &resume, sizeof(resume)) && caught;
                std::printf("loader pc=%llX context=%llX parameter=%llX context-bytes=%zu saved-pc=%llX\n", static_cast<unsigned long long>(pc(state)), static_cast<unsigned long long>(saved), static_cast<unsigned long long>(parameter), sizeof(resume), static_cast<unsigned long long>(pc(resume)));
                break;
            }
        }
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            std::printf("child exited=%lu\n", event.u.ExitProcess.dwExitCode); good = false;
        }
        good = ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) && good;
        pending = false;
    }
    const BOOL terminated = TerminateProcess(child.hProcess, 0);
    if (pending) ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    const DWORD waited = WaitForSingleObject(child.hProcess, 5000);
    std::printf("complete caught=%u good=%u terminate=%u wait=%08lX\n", caught, good, !!terminated, waited);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    return caught && good && terminated && waited == WAIT_OBJECT_0 ? 0 : 4;
}
