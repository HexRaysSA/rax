// Controlled child snapshots before its primary thread is resumed.
// Read-only child inspection; no writes to the child or registry.
#include <windows.h>
#include <winternl.h>
#include <cstddef>
// Extracted from phnt/ntrtl.h revision 53fbbdc5b5d2b08761db1c7b26bfa8c820924356.
// Original bytes and license are retained beside this probe.
#define RTL_MAX_DRIVE_LETTERS 32
typedef struct _ABI_CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ABI_CURDIR, *PABI_CURDIR;
typedef struct _ABI_RTL_DRIVE_LETTER_ABI_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} ABI_RTL_DRIVE_LETTER_ABI_CURDIR, *PABI_RTL_DRIVE_LETTER_ABI_CURDIR;
typedef struct _ABI_RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    ABI_CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    ABI_RTL_DRIVE_LETTER_ABI_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads; // THRESHOLD
    UNICODE_STRING RedirectionDllName; // REDSTONE5
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum; // 20H1
    ULONG HeapMemoryTypeMask; // WIN11 22H2
} ABI_RTL_USER_PROCESS_PARAMETERS, *PABI_RTL_USER_PROCESS_PARAMETERS;

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <initializer_list>

using QueryProcess = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
struct BasicInformation {
    LONG exit_status;
    void *peb;
    ULONG_PTR affinity;
    LONG priority;
    ULONG_PTR pid;
    ULONG_PTR parent;
};

struct Child {
    PROCESS_INFORMATION info{};
    bool stop() {
        bool ok = true;
        if (info.hProcess) {
            const BOOL terminated = TerminateProcess(info.hProcess, 0);
            const DWORD error = terminated ? 0 : GetLastError();
            const DWORD waited = WaitForSingleObject(info.hProcess, 5000);
            std::printf("cleanup terminate=%u error=%lu wait=%08lX\n", !!terminated, error, waited);
            ok = terminated && waited == WAIT_OBJECT_0;
            CloseHandle(info.hProcess);
            info.hProcess = nullptr;
        }
        if (info.hThread) {
            CloseHandle(info.hThread);
            info.hThread = nullptr;
        }
        return ok;
    }
    ~Child() { if (info.hProcess || info.hThread) stop(); }
};

static bool read(HANDLE process, ULONG_PTR at, void *out, SIZE_T bytes) {
    SIZE_T got = 0;
    const BOOL ok = ReadProcessMemory(process, reinterpret_cast<void *>(at), out, bytes, &got);
    std::printf("read address=%llX requested=%llu returned=%llu ok=%u error=%lu\n",
        static_cast<unsigned long long>(at), static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(got), !!ok, ok ? 0 : GetLastError());
    return ok && got == bytes;
}

static ULONG_PTR pointer(const BYTE *data, unsigned offset) {
    ULONG_PTR value;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}
static ULONG word(const BYTE *data, unsigned offset) {
    ULONG value;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}
static void dump(const char *name, const BYTE *data, unsigned bytes) {
    std::printf("%s bytes=%u hex=", name, bytes);
    for (unsigned i = 0; i < bytes; ++i) std::printf("%02X", data[i]);
    std::printf("\n");
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query = reinterpret_cast<QueryProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!query) return 3;
    Child child;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    const BOOL created = CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child.info);
    std::printf("create width=%zu ok=%u error=%lu\n", sizeof(void *), !!created,
        created ? 0 : GetLastError());
    if (!created) return 4;
    BasicInformation basic{};
    ULONG returned = 0;
    const LONG status = query(child.info.hProcess, 0, &basic, sizeof(basic), &returned);
    std::printf("basic status=%08lX supplied=%zu returned=%lu peb=%p pid=%llu\n",
        static_cast<ULONG>(status), sizeof(basic), returned, basic.peb,
        static_cast<unsigned long long>(basic.pid));
    if (status < 0 || returned != sizeof(basic)) return 5;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    const BOOL captured = GetThreadContext(child.info.hThread, &context);
    std::printf("context size=%zu flags=%08lX ok=%u error=%lu\n", sizeof(context),
        context.ContextFlags, !!captured, captured ? 0 : GetLastError());
    if (!captured) return 6;
    ULONG_PTR pc = 0;
#if defined(_M_ARM64)
    pc = context.Pc;
    std::printf("arm64 PC=%llX SP=%llX LR=%llX CPSR=%08lX X=", context.Pc, context.Sp, context.Lr, context.Cpsr);
    for (unsigned i = 0; i < 31; ++i) std::printf("%s%llX", i ? "," : "", context.X[i]);
    std::printf(" FPCR=%08lX FPSR=%08lX\n", context.Fpcr, context.Fpsr);
#elif defined(_M_X64)
    pc = context.Rip;
    std::printf("x64 PC=%llX SP=%llX RCX=%llX RDX=%llX R8=%llX R9=%llX R10=%llX RBP=%llX MXCSR=%08lX\n",
        context.Rip, context.Rsp, context.Rcx, context.Rdx, context.R8, context.R9, context.R10, context.Rbp, context.MxCsr);
#elif defined(_M_IX86)
    pc = context.Eip;
    std::printf("x86 PC=%08lX SP=%08lX EAX=%08lX EBX=%08lX ECX=%08lX EDX=%08lX EBP=%08lX FS=%04lX\n",
        context.Eip, context.Esp, context.Eax, context.Ebx, context.Ecx, context.Edx, context.Ebp, context.SegFs);
#else
#error unsupported probe architecture
#endif
    MEMORY_BASIC_INFORMATION mapping{};
    const SIZE_T queried = VirtualQueryEx(child.info.hProcess, reinterpret_cast<void *>(pc), &mapping, sizeof(mapping));
    std::printf("pc-mapping returned=%llu base=%p allocation=%p rva=%llX state=%08lX type=%08lX protect=%08lX\n",
        static_cast<unsigned long long>(queried), mapping.BaseAddress, mapping.AllocationBase,
        static_cast<unsigned long long>(pc - reinterpret_cast<ULONG_PTR>(mapping.AllocationBase)),
        mapping.State, mapping.Type, mapping.Protect);
    for (const char *name : {"RtlUserThreadStart", "LdrInitializeThunk"}) {
        const FARPROC entry = GetProcAddress(ntdll, name);
        std::printf("parent-export %s rva=%llX\n", name,
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(entry) - reinterpret_cast<ULONG_PTR>(ntdll)));
    }
    BYTE peb[512]{}, code[32]{}, stack[64]{};
    if (!read(child.info.hProcess, reinterpret_cast<ULONG_PTR>(basic.peb), peb, sizeof(peb))) return 7;
    const bool wide = sizeof(void *) == 8;
    std::printf("peb image=%llX ldr=%llX parameters=%llX process-heap=%llX heap-count=%lu heap-max=%lu heap-array=%llX\n",
        static_cast<unsigned long long>(pointer(peb, wide ? 0x10 : 8)),
        static_cast<unsigned long long>(pointer(peb, wide ? 0x18 : 0x0C)),
        static_cast<unsigned long long>(pointer(peb, wide ? 0x20 : 0x10)),
        static_cast<unsigned long long>(pointer(peb, wide ? 0x30 : 0x18)),
        word(peb, wide ? 0xE8 : 0x88), word(peb, wide ? 0xEC : 0x8C),
        static_cast<unsigned long long>(pointer(peb, wide ? 0xF0 : 0x90)));
    dump("peb", peb, sizeof(peb));
    std::printf("parameter-layout width=%zu size=%zu redirection=%zu heap-partition=%zu cpu-masks=%zu cpu-count=%zu thread-maximum=%zu heap-memory-type=%zu\n",sizeof(void *),sizeof(ABI_RTL_USER_PROCESS_PARAMETERS),
        offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,RedirectionDllName),offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,HeapPartitionName),offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,DefaultThreadpoolCpuSetMasks),offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,DefaultThreadpoolCpuSetMaskCount),offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,DefaultThreadpoolThreadMaximum),offsetof(ABI_RTL_USER_PROCESS_PARAMETERS,HeapMemoryTypeMask));
    BYTE parameters[sizeof(ABI_RTL_USER_PROCESS_PARAMETERS)]{};
    const ULONG_PTR parameter_address=pointer(peb,wide ? 0x20 : 0x10);
    if(!read(child.info.hProcess,parameter_address,parameters,sizeof(parameters)))return 11;
    std::printf("parameter-header maximum-length=%lu length=%lu flags=%08lX\n",word(parameters,0),word(parameters,4),word(parameters,8));
    dump("parameters",parameters,sizeof(parameters));
    if (!read(child.info.hProcess, pc, code, sizeof(code))) return 8;
    dump("pc-code", code, sizeof(code));
#if defined(_M_ARM64)
    const ULONG_PTR sp = context.Sp;
#elif defined(_M_X64)
    const ULONG_PTR sp = context.Rsp;
#else
    const ULONG_PTR sp = context.Esp;
#endif
    MEMORY_BASIC_INFORMATION stack_mapping{};
    if (!VirtualQueryEx(child.info.hProcess, reinterpret_cast<void *>(sp), &stack_mapping, sizeof(stack_mapping))) return 9;
    const ULONG_PTR stack_end = reinterpret_cast<ULONG_PTR>(stack_mapping.BaseAddress) + stack_mapping.RegionSize;
    const SIZE_T available = stack_end > sp ? stack_end - sp : 0;
    const SIZE_T stack_bytes = available < sizeof(stack) ? available : sizeof(stack);
    if (!stack_bytes || !read(child.info.hProcess, sp, stack, stack_bytes)) return 9;
    dump("stack", stack, static_cast<unsigned>(stack_bytes));
    return child.stop() ? 0 : 10;
}
