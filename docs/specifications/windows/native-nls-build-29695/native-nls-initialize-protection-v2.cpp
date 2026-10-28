#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>

#if defined(_M_IX86)
using Initialize = LONG(NTAPI *)(PVOID *, ULONG *, LARGE_INTEGER *);
#else
using Initialize = LONG(NTAPI *)(PVOID *, ULONG *, LARGE_INTEGER *, ULONG *);
#endif
using Protect = LONG(NTAPI *)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
using Free = LONG(NTAPI *)(HANDLE, PVOID *, SIZE_T *, ULONG);
using Unmap = LONG(NTAPI *)(HANDLE, PVOID);

int main() {
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  auto initialize = reinterpret_cast<Initialize>(
      GetProcAddress(ntdll, "NtInitializeNlsFiles"));
  auto protect = reinterpret_cast<Protect>(
      GetProcAddress(ntdll, "NtProtectVirtualMemory"));
  auto free =
      reinterpret_cast<Free>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  auto unmap =
      reinterpret_cast<Unmap>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  if (!initialize || !protect || !free || !unmap)
    return 90;
  const ULONG protections[] = {PAGE_NOACCESS,
                               PAGE_READONLY,
                               PAGE_READWRITE,
                               PAGE_WRITECOPY,
                               PAGE_EXECUTE,
                               PAGE_EXECUTE_READ,
                               PAGE_EXECUTE_READWRITE,
                               PAGE_EXECUTE_WRITECOPY,
                               PAGE_READONLY | PAGE_GUARD,
                               PAGE_READWRITE | PAGE_GUARD};
  unsigned cases = 0;
  for (unsigned index = 0; index < 12; ++index) {
    PVOID original = nullptr;
    ULONG locale = 0;
#if defined(_M_IX86)
    LONG created = initialize(&original, &locale, nullptr);
#else
    LONG created = initialize(&original, &locale, nullptr, nullptr);
#endif
    if (created < 0 || !original)
      return 91;
    PVOID base = original;
    SIZE_T size = index == 10 ? 0 : 4096;
    ULONG old = 0xA5A5A5A5;
    LONG status;
    if (index < 10)
      status =
          protect(GetCurrentProcess(), &base, &size, protections[index], &old);
    else
      status = free(GetCurrentProcess(), &base, &size,
                    index == 10 ? MEM_RELEASE : MEM_DECOMMIT);
    MEMORY_BASIC_INFORMATION query = {};
    if (VirtualQuery(original, &query, sizeof(query)) != sizeof(query))
      return 92;
    printf("case ordinal=%u operation=%s requested=%08lX status=%08lX "
           "base=%p result-base=%p result-size=%zu old=%08lX "
           "state=%08lX protection=%08lX type=%08lX\n",
           index, index < 10 ? "protect" : "free",
           index < 10 ? protections[index]
                      : (index == 10 ? MEM_RELEASE : MEM_DECOMMIT),
           static_cast<unsigned long>(status), original, base, size, old,
           query.State, query.Protect, query.Type);
    if (query.State != MEM_FREE) {
      LONG closed = unmap(GetCurrentProcess(), original);
      printf("unmap status=%08lX\n", static_cast<unsigned long>(closed));
      if (closed < 0)
        return 93;
    }
    ++cases;
  }
  printf("complete cases=%u pointer-bytes=%zu\n", cases, sizeof(void *));
  return 0;
}
