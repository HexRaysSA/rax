// Selected Windows child before primary-thread resume; read-only inspection.
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

using QueryProcess = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
struct BasicInformation {
    LONG exit_status;
    void *peb;
    ULONG_PTR affinity;
    LONG priority;
    ULONG_PTR pid;
    ULONG_PTR parent;
};

static bool read(HANDLE process, ULONG_PTR at, void *out, SIZE_T bytes) {
    SIZE_T got = 0;
    const BOOL ok = ReadProcessMemory(process, reinterpret_cast<void *>(at), out, bytes, &got);
    std::printf("read address=%llX requested=%llu returned=%llu ok=%u error=%lu\n",
        static_cast<unsigned long long>(at), static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(got), !!ok, ok ? 0 : GetLastError());
    return ok && got == bytes;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    auto query = reinterpret_cast<QueryProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!query) return 3;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const BOOL created = CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
    std::printf("create ok=%u error=%lu width=%zu\n", !!created, created ? 0 : GetLastError(), sizeof(void *));
    if (!created) return 4;
    bool good = true;
    BasicInformation basic{};
    ULONG returned = 0;
    const LONG status = query(child.hProcess, 0, &basic, sizeof(basic), &returned);
    std::printf("basic status=%08lX returned=%lu declared=%zu peb=%llX\n",
        static_cast<unsigned long>(status), returned, sizeof(basic), reinterpret_cast<unsigned long long>(basic.peb));
    if (status < 0) good = false;
    BYTE peb[0x80]{};
    if (good) good = read(child.hProcess, reinterpret_cast<ULONG_PTR>(basic.peb), peb, sizeof(peb));
    if (good) {
        ULONG_PTR heap = 0, ldr = 0, image = 0;
        std::memcpy(&heap, peb + (sizeof(void *) == 8 ? 0x30 : 0x18), sizeof(heap));
        std::memcpy(&ldr, peb + (sizeof(void *) == 8 ? 0x18 : 0x0C), sizeof(ldr));
        std::memcpy(&image, peb + (sizeof(void *) == 8 ? 0x10 : 0x08), sizeof(image));
        std::printf("peb heap=%llX ldr=%llX image=%llX\n",
            static_cast<unsigned long long>(heap), static_cast<unsigned long long>(ldr), static_cast<unsigned long long>(image));
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
#if defined(_M_ARM64)
    context.ContextFlags |= CONTEXT_ARM64_X18;
#endif
    const BOOL got = GetThreadContext(child.hThread, &context);
    std::printf("context ok=%u error=%lu bytes=%zu flags=%08lX\n", !!got, got ? 0 : GetLastError(), sizeof(context), context.ContextFlags);
    if (!got) good = false;
    ULONG_PTR pc = 0;
    if (got) {
#if defined(_M_ARM64)
        pc = context.Pc;
        std::printf("registers pc=%llX sp=%llX x0=%llX x1=%llX x18=%llX lr=%llX\n",
            context.Pc, context.Sp, context.X0, context.X1, context.X18, context.Lr);
#elif defined(_M_X64)
        pc = context.Rip;
        std::printf("registers pc=%llX sp=%llX rcx=%llX rdx=%llX\n", context.Rip, context.Rsp, context.Rcx, context.Rdx);
#else
        pc = context.Eip;
        std::printf("registers pc=%lX sp=%lX eax=%lX ebx=%lX\n", context.Eip, context.Esp, context.Eax, context.Ebx);
#endif
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQueryEx(child.hProcess, reinterpret_cast<void *>(pc), &region, sizeof(region)) != sizeof(region)) good = false;
        else std::printf("pc module=%llX rva=%llX protect=%08lX type=%08lX\n",
            reinterpret_cast<unsigned long long>(region.AllocationBase),
            static_cast<unsigned long long>(pc - reinterpret_cast<ULONG_PTR>(region.AllocationBase)), region.Protect, region.Type);
    }
    const BOOL terminated = TerminateProcess(child.hProcess, 0);
    const DWORD error = terminated ? 0 : GetLastError();
    const DWORD waited = WaitForSingleObject(child.hProcess, 5000);
    std::printf("cleanup terminate=%u error=%lu wait=%08lX\n", !!terminated, error, waited);
    good = good && terminated && waited == WAIT_OBJECT_0;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return good ? 0 : 5;
}
