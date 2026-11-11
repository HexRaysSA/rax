#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <map>
#include <vector>

#if !defined(_M_ARM64)
#error This observer uses the native Windows ARM64 debug context.
#endif

// Observed ARM64EC wrapper from the exact RAX x64 fixture boundary.
constexpr std::array<std::uint32_t, 13> wrapper{
    0xd10043ff, 0xb0ffffd0, 0x9100c210, 0xf90003f0, 0xd4003281, 0xf94003e9, 0xb0ffffd0, 0x9100c210, 0xeb090210, 0x910043ff, 0x54fc0ac1, 0xd2800009, 0xd65f03c0
};
constexpr DWORD execute_el0 = 0x1e5; // DBGBCR BAS=1111, PMC=10, E=1.
constexpr ULONG_PTR svc_offset = 4 * sizeof(std::uint32_t);

static bool read(HANDLE process, ULONG_PTR address, void *out, SIZE_T size) {
    SIZE_T got = 0;
    return address != 0 &&
           ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                             out, size, &got) != 0 && got == size;
}

static ULONG_PTR find_wrapper(HANDLE process, ULONG_PTR base) {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!read(process, base, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 65536 ||
        !read(process, base + dos.e_lfanew, &nt, sizeof nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage > 64 * 1024 * 1024)
        return 0;
    const auto end = base + nt.OptionalHeader.SizeOfImage;
    ULONG_PTR result = 0;
    for (auto start = base; start < end;) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQueryEx(process, reinterpret_cast<const void *>(start),
                            &region, sizeof region) || !region.RegionSize)
            break;
        const auto next = reinterpret_cast<ULONG_PTR>(region.BaseAddress) + region.RegionSize;
        if (next <= start)
            return 0;
        const DWORD access = region.Protect & 0xff;
        if (region.State == MEM_COMMIT && !(region.Protect & PAGE_GUARD) &&
            (access == PAGE_EXECUTE || access == PAGE_EXECUTE_READ ||
             access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY)) {
            const auto length = (next < end ? next : end) - start;
            std::vector<std::uint32_t> words(length / sizeof(std::uint32_t));
            if (read(process, start, words.data(), words.size() * sizeof(words[0]))) {
                for (size_t i = 0; i + wrapper.size() <= words.size(); ++i) {
                    if (words[i + 4] != wrapper[4])
                        continue;
                    if (!std::equal(wrapper.begin(), wrapper.end(), words.begin() + i))
                        continue;
                    if (result)
                        return 0;
                    result = start + i * sizeof(std::uint32_t) + svc_offset;
                }
            }
        }
        start = next;
    }
    return result;
}

static void dump(HANDLE process, const char *name, ULONG_PTR address, SIZE_T bytes) {
    std::vector<unsigned char> data(bytes);
    const bool ok = bytes && bytes <= 952 && read(process, address, data.data(), bytes);
    std::printf("bytes name=%s length=%zu readable=%u hex=", name, bytes, unsigned(ok));
    if (ok)
        for (const auto byte : data)
            std::printf("%02x", unsigned(byte));
    std::puts("");
}

struct Thread {
    HANDLE handle = nullptr;
    CONTEXT saved{};
    int slot = -1;
    ULONG_PTR armed = 0;
    std::array<ULONG_PTR, 9> args{};
    ULONG capacity = 0;
    unsigned ordinal = 0;
    bool selected = false;

    bool arm(ULONG_PTR address) {
        if (slot < 0) {
            saved.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(handle, &saved))
                return false;
            for (int i = 0; i < ARM64_MAX_BREAKPOINTS; ++i) {
                if (!(saved.Bcr[i] & 1)) {
                    slot = i;
                    break;
                }
            }
            if (slot < 0)
                return false;
        }
        CONTEXT context = saved;
        if (address) {
            context.Bvr[slot] = address;
            context.Bcr[slot] = execute_el0;
        }
        if (!SetThreadContext(handle, &context))
            return false;
        armed = address;
        CONTEXT observed{};
        observed.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        const bool readback = GetThreadContext(handle, &observed) != 0;
        const bool match = readback && observed.Bvr[slot] == context.Bvr[slot] &&
                           observed.Bcr[slot] == context.Bcr[slot];
        std::printf("arm slot=%d target=%llx readback=%u got-address=%llx got-control=%lx match=%u\n",
                    slot, address, unsigned(readback), observed.Bvr[slot],
                    observed.Bcr[slot], unsigned(match));
        return match;
    }
};

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    PROCESS_INFORMATION child{};
    wchar_t command[] = L"x64.exe";
    if (!CreateProcessW(L".\\x64.exe", command, nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup, &child))
        return 2;
    if (!DebugSetProcessKillOnExit(FALSE)) {
        std::printf("disable-debugger-kill failed=%lu\n", GetLastError());
        return 3;
    }
    std::printf("owned-child pid=%lu main-tid=%lu\n", child.dwProcessId, child.dwThreadId);
    std::map<DWORD, Thread> threads;
    ULONG_PTR svc = 0;
    unsigned entries = 0, returns = 0, selected_returns = 0;
    bool exited = false, initial_break = false, error = false;
    DWORD exit_code = 0;
    while (!exited) {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 1000)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT)
                continue;
            error = true;
            break;
        }
        DWORD disposition = DBG_CONTINUE;
        if (event.dwProcessId != child.dwProcessId)
            error = true;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT ||
            event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            auto &thread = threads[event.dwThreadId];
            thread.handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                       THREAD_QUERY_INFORMATION, FALSE, event.dwThreadId);
            if (!thread.handle || (svc && !thread.arm(svc)))
                error = true;
            if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
                event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            auto &dll = event.u.LoadDll;
            wchar_t path[1024]{};
            if (dll.hFile) {
                const DWORD length = GetFinalPathNameByHandleW(dll.hFile, path, 1024,
                                                               FILE_NAME_NORMALIZED);
                CloseHandle(dll.hFile);
                if (length && length < 1024) {
                    const wchar_t *leaf = std::wcsrchr(path, L'\\');
                    if (leaf && _wcsicmp(leaf + 1, L"ntdll.dll") == 0) {
                        const auto base = reinterpret_cast<ULONG_PTR>(dll.lpBaseOfDll);
                        const auto site = find_wrapper(child.hProcess, base);
                        std::printf("provider path=%ls base=%llx svc=%llx\n", path, base, site);
                        if (site && !svc) {
                            svc = site;
                            for (auto &[tid, thread] : threads) {
                                std::printf("setup-thread tid=%lu\n", tid);
                                if (!thread.arm(svc))
                                    error = true;
                            }
                        }
                    }
                }
            }
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto &exception = event.u.Exception.ExceptionRecord;
            const auto address = reinterpret_cast<ULONG_PTR>(exception.ExceptionAddress);
            auto it = threads.find(event.dwThreadId);
            if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP && it != threads.end() &&
                it->second.armed == address && address != 0) {
                auto &thread = it->second;
                CONTEXT c{};
                c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (!GetThreadContext(thread.handle, &c) || c.Pc != address) {
                    std::printf("context mismatch pc=%llx address=%llx error=%lu\n",
                                c.Pc, address, GetLastError());
                    error = true;
                } else if (address == svc) {
                    thread.ordinal = ++entries;
                    auto &a = thread.args;
                    std::copy_n(c.X, 8, a.begin());
                    a[8] = 0;
                    const bool stack_read = read(child.hProcess, c.Sp + 16, &a[8], 8);
                    thread.capacity = 0;
                    read(child.hProcess, a[8], &thread.capacity, 4);
                    std::array<ULONG_PTR, 2> name{};
                    const bool name_read = read(child.hProcess, a[1], name.data(), sizeof name);
                    const auto name_bytes = static_cast<unsigned>(name[0] & 0xffff);
                    std::array<wchar_t, 256> name_text{};
                    thread.selected = stack_read && name_read && name_bytes &&
                        name_bytes < sizeof name_text && !(name_bytes & 1) &&
                        read(child.hProcess, name[1], name_text.data(), name_bytes);
                    std::printf("entry ordinal=%u tid=%lu pc=%llx lr=%llx sp=%llx length-pointer=%llx "
                                "capacity=%lu selected=%u name=%ls\n",
                                thread.ordinal, event.dwThreadId, c.Pc, c.Lr, c.Sp, a[8],
                                thread.capacity, unsigned(thread.selected), name_text.data());
                    dump(child.hProcess, "qos", a[2], 12);
                    dump(child.hProcess, "client-before", a[3], 48);
                    if (a[4]) dump(child.hProcess, "server-sid", a[4], 12);
                    dump(child.hProcess, "server-before", a[5], 24);
                    dump(child.hProcess, "maximum-before", a[6], 4);
                    if (thread.capacity && thread.capacity <= 952)
                        dump(child.hProcess, "information-before", a[7], thread.capacity);
                    if (!thread.arm(svc + sizeof(std::uint32_t)))
                        error = true;
                } else {
                    ++returns;
                    selected_returns += unsigned(thread.selected);
                    const auto &a = thread.args;
                    ULONG length = 0;
                    read(child.hProcess, a[8], &length, 4);
                    std::printf("return ordinal=%u tid=%lu status=%08lx length=%lu selected=%u\n",
                                thread.ordinal, event.dwThreadId, DWORD(c.X0), length,
                                unsigned(thread.selected));
                    dump(child.hProcess, "handle-after", a[0], 8);
                    dump(child.hProcess, "client-after", a[3], 48);
                    dump(child.hProcess, "server-after", a[5], 24);
                    dump(child.hProcess, "maximum-after", a[6], 4);
                    if (length && length <= 952)
                        dump(child.hProcess, "information-after", a[7], length);
                    if (!thread.arm(entries < 32 ? svc : 0))
                        error = true;
                }
            } else if (!initial_break && exception.ExceptionCode == EXCEPTION_BREAKPOINT) {
                initial_break = true;
            } else {
                disposition = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
            auto it = threads.find(event.dwThreadId);
            if (it != threads.end()) {
                CloseHandle(it->second.handle);
                threads.erase(it);
            }
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            exit_code = event.u.ExitProcess.dwExitCode;
            exited = true;
        }
        if (error && !exited) {
            for (auto &[tid, thread] : threads) {
                if (thread.armed && !thread.arm(0))
                    std::printf("restore failed tid=%lu error=%lu\n", tid, GetLastError());
            }
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition))
            error = true;
        if (error)
            break;
    }
    if (!exited)
        DebugActiveProcessStop(child.dwProcessId);
    for (const auto &[tid, thread] : threads) {
        if (thread.handle)
            CloseHandle(thread.handle);
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    std::printf("done natural-exit=%u exit=%lu entries=%u returns=%u selected-returns=%u error=%u\n",
                unsigned(exited), exit_code, entries, returns, selected_returns, unsigned(error));
    return error || !exited || exit_code || !selected_returns ? 4 : 0;
}
