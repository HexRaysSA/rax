#include <windows.h>
#include <cstdio>
#include <cstdint>
struct Parameter { ULONGLONG type, value; };
using Allocate = LONG (NTAPI *)(HANDLE, void **, SIZE_T *, ULONG, ULONG, Parameter *, ULONG);
int main() {
    auto allocate = reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemoryEx"));
    if (!allocate) return 1;
    const ULONGLONG values[] = {0, 0x100000000ULL, 0xffffffff00000000ULL, 1};
    for (auto value : values) {
        Parameter parameter{2, value};
        void *base = nullptr;
        SIZE_T size = 4096;
        const LONG status = allocate(GetCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &parameter, 1);
        MEMORY_BASIC_INFORMATION mapping{};
        if (status >= 0) VirtualQuery(base, &mapping, sizeof(mapping));
        const BOOL freed = status >= 0 ? VirtualFree(base, 0, MEM_RELEASE) : TRUE;
        std::printf("width=%zu type=2 payload=%016llX status=%08lX base=%p size=%llX state=%08lX freed=%u error=%lu\n",
            sizeof(void *), value, static_cast<ULONG>(status), base,
            static_cast<unsigned long long>(size), mapping.State, !!freed, freed ? 0 : GetLastError());
        if (!freed) return 2;
    }
    return 0;
}
