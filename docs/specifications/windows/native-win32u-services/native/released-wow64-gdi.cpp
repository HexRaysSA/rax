// Observe the GUI state of a fixed x86 test process before and after a stock GDI call.
#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <string>
#include <windows.h>
#include <winternl.h>

namespace {
constexpr DWORD timeout_ms = 20000;

class OwnedHandle {
public:
    explicit OwnedHandle(HANDLE value) : value_(value) {}
    OwnedHandle(const OwnedHandle &) = delete;
    OwnedHandle &operator=(const OwnedHandle &) = delete;
    ~OwnedHandle() { if (value_) CloseHandle(value_); }
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

using ProcessQuery = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool process_peb(HANDLE process, std::uintptr_t &peb)
{
    auto query = reinterpret_cast<ProcessQuery>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION info{};
    ULONG size = 0;
    if (!query || query(process, ProcessBasicInformation, &info, sizeof(info), &size) < 0 ||
        size != sizeof(info)) return false;
    peb = reinterpret_cast<std::uintptr_t>(info.PebBaseAddress);
    return peb != 0;
}

template <class T>
bool read(HANDLE process, std::uintptr_t address, T &value)
{
    SIZE_T size = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                             &value, sizeof(value), &size) && size == sizeof(value);
}

#if defined(_WIN64)
bool report_view(HANDLE process, const char *kind, std::uintptr_t base)
{
    if (!base) return true;
    // The desktop client field can point inside the view.
    MEMORY_BASIC_INFORMATION first{};
    if (VirtualQueryEx(process, reinterpret_cast<const void *>(base), &first, sizeof(first)) !=
        sizeof(first)) return false;
    const auto allocation = reinterpret_cast<std::uintptr_t>(first.AllocationBase);
    if (!allocation) return false;
    std::size_t offset = 0;
    constexpr std::size_t limit = 64u << 20;
    while (offset < limit) {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQueryEx(process, reinterpret_cast<const void *>(allocation + offset),
                           &region, sizeof(region)) != sizeof(region)) return false;
        if (reinterpret_cast<std::uintptr_t>(region.AllocationBase) != allocation)
            return offset != 0;
        if (!region.RegionSize || region.RegionSize > limit - offset) return false;
        std::printf("view=%s low=%u offset=%zu bytes=%zu state=%lx protection=%lx kind=%lx\n",
            kind, unsigned(allocation < (1ull << 32)), offset, region.RegionSize,
            region.State, region.Protect, region.Type);
        offset += region.RegionSize;
    }
    return false;
}

bool snapshot(HANDLE process, HANDLE thread, const char *phase)
{
    using ThreadQuery = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto query = reinterpret_cast<ThreadQuery>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    std::uint64_t info[6]{};
    ULONG size = 0;
    std::uintptr_t peb = 0, gdi = 0, thread_info = 0;
    std::uint32_t process_value = 0;
    std::uint64_t client[20]{};
    if (!process_peb(process, peb) || !query ||
        query(thread, 0, info, sizeof(info), &size) < 0 || size != sizeof(info) || !info[1] ||
        !read(process, peb + 0xf8, gdi) || !read(process, peb + 0x108, process_value) ||
        !read(process, info[1] + 0x78, thread_info) || !read(process, info[1] + 0x800, client))
        return false;
    std::printf("companion=%s gdi=%u process=%u process_high_bit=%u thread=%u "
                "client_flags=%016llx client_views=%u record=%u\n",
        phase, unsigned(gdi != 0), unsigned(process_value != 0), process_value >> 31,
        unsigned(thread_info != 0), static_cast<unsigned long long>(client[0]),
        unsigned(client[4] != 0 && client[5] != 0), unsigned(client[12] != 0));
    return report_view(process, "gdi", gdi) && report_view(process, "desktop", client[5]);
}
#else
bool snapshot_x86(const char *phase)
{
    std::uintptr_t peb = 0;
    std::uint32_t gdi = 0;
    if (!process_peb(GetCurrentProcess(), peb) || !read(GetCurrentProcess(), peb + 0x94, gdi))
        return false;
    std::printf("x86=%s gdi=%u\n", phase, unsigned(gdi != 0));
    return true;
}
#endif
}

#if defined(_WIN64)
int wmain(int argc, wchar_t **argv)
{
    if (argc != 2) return 2;
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    OwnedHandle ready(CreateEventW(&security, FALSE, FALSE, nullptr));
    OwnedHandle proceed(CreateEventW(&security, FALSE, FALSE, nullptr));
    if (!ready.get() || !proceed.get()) return 3;
    std::wstring command = L"\"" + std::wstring(argv[1]) + L"\" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(ready.get())) + L" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(proceed.get()));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(argv[1], command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                        &startup, &child)) return 4;
    OwnedHandle process(child.hProcess), thread(child.hThread);
    const auto phase = [&](const char *name) {
        HANDLE events[] = {ready.get(), process.get()};
        return WaitForMultipleObjects(2, events, FALSE, timeout_ms) == WAIT_OBJECT_0 &&
            snapshot(process.get(), thread.get(), name) && SetEvent(proceed.get());
    };
    const bool complete = phase("before") && phase("after");
    if (!complete) SetEvent(proceed.get());
    DWORD exit_code = 0;
    if (WaitForSingleObject(process.get(), timeout_ms * 2) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.get(), &exit_code)) return 5;
    std::printf("measurement=%u child_exit=%lu\n", unsigned(complete), exit_code);
    return complete && !exit_code ? 0 : 6;
}
#else
int wmain(int argc, wchar_t **argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc != 3) return 2;
    auto ready = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(argv[1], nullptr, 10)));
    auto proceed = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(argv[2], nullptr, 10)));
    const auto sync = [&] { return SetEvent(ready) && WaitForSingleObject(proceed, timeout_ms) == WAIT_OBJECT_0; };
    if (!snapshot_x86("before") || !sync()) return 3;
    auto gdi = LoadLibraryExW(L"gdi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!gdi) return 4;
    auto stock = reinterpret_cast<HGDIOBJ(WINAPI *)(int)>(GetProcAddress(gdi, "GetStockObject"));
    if (!stock || !stock(WHITE_BRUSH)) return 5;
    auto win32u = GetModuleHandleW(L"win32u.dll");
    if (!win32u) return 6;
    const bool legacy = GetProcAddress(win32u, "NtGdiInit") != nullptr;
    const bool init2 = GetProcAddress(win32u, "NtGdiInit2") != nullptr;
    std::printf("x86_stock=1 legacy=%u init2=%u\n", unsigned(legacy), unsigned(init2));
    if (!snapshot_x86("after") || !sync()) return 7;
    return 0;
}
#endif
