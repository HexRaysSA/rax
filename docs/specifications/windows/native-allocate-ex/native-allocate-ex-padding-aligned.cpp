#include <windows.h>
#include <cstdio>
#include <cstdint>
static_assert(sizeof(MEM_EXTENDED_PARAMETER) == 16);
using Allocate = LONG (NTAPI *)(HANDLE, void **, SIZE_T *, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
int main() {
    auto allocate = reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemoryEx"));
    if (!allocate) return 1;
    const ULONGLONG values[] = {0, 0x100000000ULL, 0xffffffff00000000ULL, 1};
    const ULONG allocation_types[] = {MEM_RESERVE, MEM_RESERVE | MEM_COMMIT};
    for (auto flags : allocation_types) for (auto value : values) {
        alignas(16) MEM_EXTENDED_PARAMETER parameter{};
        parameter.Type = MemExtendedParameterNumaNode;
        parameter.ULong64 = value;
        alignas(16) void *base = nullptr;
        alignas(16) SIZE_T size = 4096;
        const LONG status = allocate(GetCurrentProcess(), &base, &size, flags, PAGE_READWRITE, &parameter, 1);
        MEMORY_BASIC_INFORMATION mapping{};
        if (status >= 0) VirtualQuery(base, &mapping, sizeof(mapping));
        const BOOL freed = status >= 0 ? VirtualFree(base, 0, MEM_RELEASE) : TRUE;
        std::printf("width=%zu type=2 flags=%08lX payload=%016llX status=%08lX base=%p size=%llX state=%08lX freed=%u error=%lu parameter=%p base-output=%p size-output=%p\n",
            sizeof(void *), flags, value, static_cast<ULONG>(status), base,
            static_cast<unsigned long long>(size), mapping.State, !!freed, freed ? 0 : GetLastError(), &parameter, &base, &size);
        if (!freed) return 2;
    }
    return 0;
}
