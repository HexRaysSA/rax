#define WIN32_LEAN_AND_MEAN
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <vector>
#include <windows.h>
#include <winternl.h>
using Connect = NTSTATUS(NTAPI *)(PWSTR, ULONG, PVOID, ULONG, PBOOLEAN);
struct Result {
  ULONG status, exception;
};
static Result invoke(Connect fn, PWSTR directory, ULONG server, void *data,
                     PULONG length, PBOOLEAN inside) {
  __try {
    return {static_cast<ULONG>(
                fn(directory, server, data, length ? *length : 0, inside)),
            0};
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return {0xDEADBEEF, GetExceptionCode()};
  }
}

static bool snapshot_allocation(unsigned slot, unsigned long long value) {
  if (static_cast<unsigned long long>(static_cast<uintptr_t>(value)) != value)
    return false;
  MEMORY_BASIC_INFORMATION first{};
  if (VirtualQuery(reinterpret_cast<void *>(static_cast<uintptr_t>(value)),
                   &first, sizeof(first)) != sizeof(first))
    return false;
  const auto allocation = reinterpret_cast<uintptr_t>(first.AllocationBase);
  if (!allocation || allocation != static_cast<uintptr_t>(value))
    return false;
  SIZE_T offset = 0, committed = 0;
  unsigned runs = 0;
  while (offset < (64u << 20) && runs < 16384) {
    MEMORY_BASIC_INFORMATION region{};
    const auto address = allocation + offset;
    if (address < allocation ||
        VirtualQuery(reinterpret_cast<void *>(address), &region,
                     sizeof(region)) != sizeof(region))
      return false;
    if (reinterpret_cast<uintptr_t>(region.AllocationBase) != allocation) {
      std::printf(
          "MAP-END slot=%u base=%016llX bytes=%zu runs=%u committed=%zu\n",
          slot, static_cast<unsigned long long>(allocation), static_cast<size_t>(offset), runs,
          static_cast<size_t>(committed));
      return offset != 0;
    }
    if (reinterpret_cast<uintptr_t>(region.BaseAddress) != address ||
        region.Type != MEM_MAPPED || region.RegionSize == 0 ||
        region.RegionSize % 4096 != 0 ||
        region.RegionSize > (64u << 20) - offset)
      return false;
    std::printf("MAP slot=%u base=%016llX offset=%zu bytes=%zu state=%08lX "
                "protect=%08lX type=%08lX hex=",
                slot, static_cast<unsigned long long>(allocation), static_cast<size_t>(offset),
                static_cast<size_t>(region.RegionSize), region.State, region.Protect, region.Type);
    if (region.State == MEM_COMMIT && region.Protect == PAGE_READONLY) {
      committed += region.RegionSize;
      if (committed > (16u << 20))
        return false;
      std::vector<BYTE> first_bytes(region.RegionSize),
          second_bytes(region.RegionSize);
      SIZE_T got_first = 0, got_second = 0;
      if (!ReadProcessMemory(
              GetCurrentProcess(), reinterpret_cast<void *>(address),
              first_bytes.data(), first_bytes.size(), &got_first) ||
          !ReadProcessMemory(
              GetCurrentProcess(), reinterpret_cast<void *>(address),
              second_bytes.data(), second_bytes.size(), &got_second) ||
          got_first != first_bytes.size() || got_second != second_bytes.size())
        return false;
      for (BYTE b : first_bytes)
        std::printf("%02X", unsigned(b));
      std::printf(" stable=%u", unsigned(first_bytes == second_bytes));
    } else if (region.State != MEM_RESERVE || region.Protect != 0) {
      return false;
    }
    std::puts("");
    offset += region.RegionSize;
    ++runs;
  }
  return false;
}

int main(int argc, char **argv) {
  auto module = GetModuleHandleW(L"ntdll.dll");
  auto connect = reinterpret_cast<Connect>(
      GetProcAddress(module, "CsrClientConnectToServer"));
  if (!connect)
    return 2;
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 3;
  std::printf("PROFILE %s POINTER_BYTES %zu\n", argc > 1 ? argv[1] : "unknown",
              sizeof(void *));
  unsigned calls = 0;
  wchar_t directory[] = L"\\Windows";
  using ProcessId = ULONG(NTAPI *)();
  using Allocate = void *(NTAPI *)(ULONG, ULONG);
  using Free = void(NTAPI *)(void *);
  auto process_id =
      reinterpret_cast<ProcessId>(GetProcAddress(module, "CsrGetProcessId"));
  auto allocate = reinterpret_cast<Allocate>(
      GetProcAddress(module, "CsrAllocateCaptureBuffer"));
  auto release =
      reinterpret_cast<Free>(GetProcAddress(module, "CsrFreeCaptureBuffer"));
  std::printf("BOOTSTRAP before-pid-available=%u before-pid=%lu\n",
              unsigned(process_id != nullptr), process_id ? process_id() : 0);
  BOOLEAN boot_inside = 0xA5;
  auto boot = invoke(connect, directory, 0, nullptr, nullptr, &boot_inside);
  std::printf(
      "BOOTSTRAP status=%08lX exception=%08lX inside=%u after-pid=%lu\n",
      boot.status, boot.exception, unsigned(boot_inside),
      process_id ? process_id() : 0);
  if (allocate && release) {
    void *capture = allocate(1, 584);
    std::printf("ALLOCATE requested-pointers=1 requested-data=584 ok=%u\n",
                unsigned(capture != nullptr));
    if (capture)
      release(capture);
  }

  // The observed guest operation has ServerDllIndex3 and584 zero input bytes.
  // It connects this disposable client only; no host handle/address is
  // supplied.
  for (unsigned sample = 0; sample < 2; ++sample) {
    alignas(16) std::array<BYTE, 1024> bytes{};
    std::memset(bytes.data() + 584, 0xA5, bytes.size() - 584);
    ULONG length = 584;
    BOOLEAN inside = 0xA5;
    auto result = invoke(connect, directory, 3, bytes.data(), &length, &inside);
    std::printf("CONNECT sample=%u server=3 supplied=584 status=%08lX "
                "exception=%08lX returned=%lu inside=%u data=",
                sample, result.status, result.exception, length,
                unsigned(inside));
    for (BYTE b : bytes)
      std::printf("%02X", unsigned(b));
    std::printf("\n");
    if (result.status == 0 && result.exception == 0) {
      using MappedName = DWORD(WINAPI *)(HANDLE, LPVOID, LPWSTR, DWORD);
      auto mapped_name = reinterpret_cast<MappedName>(GetProcAddress(
          GetModuleHandleW(L"kernel32.dll"), "K32GetMappedFileNameW"));
      if (sample == 0) {
        for (unsigned slot : {16u, 40u}) {
          unsigned long long value = 0;
          std::memcpy(&value, bytes.data() + slot, 8);
          if (!snapshot_allocation(slot, value))
            return 8;
        }
      }
      for (unsigned slot : {8u, 16u, 32u, 40u, 56u}) {
        unsigned long long value = 0;
        std::memcpy(&value, bytes.data() + slot, 8);
        if (static_cast<unsigned long long>(static_cast<uintptr_t>(value)) !=
            value)
          return 7;
        void *address = reinterpret_cast<void *>(static_cast<uintptr_t>(value));
        MEMORY_BASIC_INFORMATION region{};
        SIZE_T queried = VirtualQuery(address, &region, sizeof(region));
        wchar_t name[2048]{};
        DWORD count =
            mapped_name ? mapped_name(GetCurrentProcess(), address, name, 2048)
                        : 0;
        std::printf("REGION sample=%u slot=%u address=%016llX queried=%zu "
                    "base=%016llX allocation=%016llX bytes=%zu state=%08lX "
                    "protect=%08lX type=%08lX file=",
                    sample, slot, value, static_cast<size_t>(queried),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(region.BaseAddress)),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(region.AllocationBase)),
                    static_cast<size_t>(region.RegionSize), region.State, region.Protect,
                    region.Type);
        for (DWORD i = 0; i < count; ++i)
          std::printf("%04X", unsigned(name[i]));
        BYTE prefix[64]{};
        SIZE_T got = 0;
        BOOL read = ReadProcessMemory(GetCurrentProcess(), address, prefix,
                                      sizeof(prefix), &got);
        std::printf(" read=%u got=%zu prefix=", unsigned(read), static_cast<size_t>(got));
        for (SIZE_T i = 0; i < got; ++i)
          std::printf("%02X", unsigned(prefix[i]));
        std::printf("\n");
      }
    }
    ++calls;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 4;
  std::printf("SUMMARY calls=%u handles-before=%lu handles-after=%lu\n", calls,
              before, after);
  // NTDLL may retain its newly initialized CSR connection until process exit.
  // No returned NTDLL-owned port is closed by this probe. Counts remain raw.
  return 0;
}
