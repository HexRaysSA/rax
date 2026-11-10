#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <windows.h>

static void dump(const char *name, const void *address, size_t length) {
  unsigned char bytes[2048]{};
  SIZE_T got = 0;
  if (length > sizeof bytes)
    ExitProcess(21);
  BOOL ok =
      ReadProcessMemory(GetCurrentProcess(), address, bytes, length, &got);
  printf("dump name=%s address=%llX requested=%zu ok=%u error=%lu got=%zu hex=",
         name,
         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(address)),
         length, unsigned(ok), ok ? 0 : GetLastError(), static_cast<size_t>(got));
  for (SIZE_T i = 0; i < got; ++i)
    printf("%02X", bytes[i]);
  puts("");
  if (!ok || got != length)
    ExitProcess(22);
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  HMODULE n = GetModuleHandleW(L"ntdll.dll");
  auto get_peb = reinterpret_cast<void *(NTAPI *)()>(
      GetProcAddress(n, "RtlGetCurrentPeb"));
  if (!get_peb)
    return 23;
  void *peb = get_peb();
  printf("profile width=%zu pid=%lu ntdll=%llX peb=%llX\n", sizeof(void *),
         GetCurrentProcessId(),
         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(n)),
         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(peb)));
  dump("peb", peb, 2048);
  auto csr = GetProcAddress(n, "CsrGetProcessId");
  printf(
      "csr-pid-export present=%u rva=%llX\n", unsigned(csr != nullptr),
      csr ? static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(csr) -
                                            reinterpret_cast<uintptr_t>(n))
          : 0);
  if (csr) {
    dump("csr-pid-code", reinterpret_cast<const void *>(csr), 64);
    // The preceding ARM64 producer's retained and decoded export is a bounded
    // readonly load/CSEL/RET of a pointer-width ID, with no arguments or calls.
    using CsrPid = uintptr_t(NTAPI *)();
    printf("csr-pid-value value=%llX\n",
           static_cast<unsigned long long>(reinterpret_cast<CsrPid>(csr)()));
  }
  uintptr_t shared = 0, statics = 0;
  SIZE_T got = 0;
  auto raw = static_cast<unsigned char *>(peb);
  if (!ReadProcessMemory(GetCurrentProcess(),
                         raw + (sizeof(void *) == 8 ? 0x88 : 0x4C), &shared,
                         sizeof shared, &got) ||
      got != sizeof shared)
    return 24;
  if (!ReadProcessMemory(GetCurrentProcess(),
                         raw + (sizeof(void *) == 8 ? 0x98 : 0x54), &statics,
                         sizeof statics, &got) ||
      got != sizeof statics)
    return 25;
  printf("selected shared=%llX statics=%llX offset=%llX\n",
         static_cast<unsigned long long>(shared),
         static_cast<unsigned long long>(statics),
         static_cast<unsigned long long>(statics - shared));
  if (shared) {
    MEMORY_BASIC_INFORMATION q{};
    SIZE_T returned =
        VirtualQuery(reinterpret_cast<void *>(shared), &q, sizeof q);
    printf("region returned=%zu base=%llX allocation=%llX size=%zu state=%lX "
           "protect=%lX type=%lX\n",
           static_cast<size_t>(returned),
           static_cast<unsigned long long>(
               reinterpret_cast<uintptr_t>(q.BaseAddress)),
           static_cast<unsigned long long>(
               reinterpret_cast<uintptr_t>(q.AllocationBase)),
           static_cast<size_t>(q.RegionSize), q.State, q.Protect, q.Type);
    dump("selected-prefix", reinterpret_cast<void *>(shared), 128);
  }
  puts("complete status=0 read-only=1");
  return 0;
}
