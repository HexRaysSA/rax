#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <vector>

using Create = LONG(NTAPI *)(HANDLE *, ULONG, OBJECT_ATTRIBUTES *, LARGE_INTEGER *,
                            ULONG, ULONG, HANDLE);
using Map = LONG(NTAPI *)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T,
                         LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
using Unmap = LONG(NTAPI *)(HANDLE, void *);
using Close = LONG(NTAPI *)(HANDLE);
using Version = LONG(WINAPI *)(OSVERSIONINFOW *);

struct Case {
  SIZE_T commit;
  SIZE_T size;
  ULONG flags;
  ULONG_PTR zero = 0;
  std::uint64_t offset = 0;
  bool offset_pointer = false;
  unsigned base_kind = 0;
};

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  auto dll = GetModuleHandleW(L"ntdll.dll");
  auto create = reinterpret_cast<Create>(GetProcAddress(dll, "NtCreateSection"));
  auto map = reinterpret_cast<Map>(GetProcAddress(dll, "NtMapViewOfSection"));
  auto unmap = reinterpret_cast<Unmap>(GetProcAddress(dll, "NtUnmapViewOfSection"));
  auto close = reinterpret_cast<Close>(GetProcAddress(dll, "NtClose"));
  auto version = reinterpret_cast<Version>(GetProcAddress(dll, "RtlGetVersion"));
  if (!create || !map || !unmap || !close || !version) return 2;
  OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  USHORT machine = 0, native = 0;
  if (version(&os) < 0 || !IsWow64Process2(GetCurrentProcess(), &machine, &native))
    return 3;
  std::printf("KERNEL major=%lu minor=%lu build=%lu pointer-bytes=%zu machine=%04X native=%04X\n",
      os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, sizeof(void *),
      machine, native);
  HANDLE self = reinterpret_cast<HANDLE>(std::intptr_t(-1));
  DWORD before = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 4;
  HANDLE section = nullptr;
  LARGE_INTEGER maximum{};
  maximum.QuadPart = 65536;
  LONG made = create(&section, 0x000f001f, nullptr, &maximum,
                     PAGE_READWRITE, SEC_COMMIT, nullptr);
  std::printf("CREATE status=%08lX handle=%llX maximum=%lld protect=%08lX attributes=%08lX\n",
      ULONG(made), static_cast<unsigned long long>(std::uintptr_t(section)),
      maximum.QuadPart, ULONG(PAGE_READWRITE), ULONG(SEC_COMMIT));
  if (made < 0 || !section) return 5;
  std::vector<Case> cases;
  for (ULONG flags : {0ul, ULONG(MEM_TOP_DOWN)}) {
    for (SIZE_T commit : {SIZE_T(0), SIZE_T(1), SIZE_T(4095), SIZE_T(4096),
                          SIZE_T(16384), SIZE_T(65535), SIZE_T(65536), SIZE_T(65537)})
      for (SIZE_T size : {SIZE_T(0), SIZE_T(1), SIZE_T(4095), SIZE_T(4096),
                          SIZE_T(16384), SIZE_T(65536), SIZE_T(65537)})
        cases.push_back({commit, size, flags});
    for (ULONG_PTR zero : {ULONG_PTR(1), ULONG_PTR(8), ULONG_PTR(21),
                            ULONG_PTR(22), ULONG_PTR(31), ULONG_PTR(32),
                            ULONG_PTR(0xffffffffu)})
      cases.push_back({16384, 0, flags, zero});
    for (std::uint64_t offset : {0ull, 4096ull, 65535ull, 65536ull})
      cases.push_back({16384, 0, flags, 0, offset, true});
    cases.push_back({16384, 0, flags, 0, 0, false, 1});
    cases.push_back({16384, 0, flags, 0, 0, false, 2});
  }
  unsigned ordinal = 0, mapped = 0, released = 0, failures = 0;
  for (const auto &c : cases) {
    void *reservation = nullptr;
    if (c.base_kind) {
      reservation = VirtualAlloc(nullptr, 65536, MEM_RESERVE, PAGE_NOACCESS);
      if (!reservation) { ++failures; break; }
    }
    void *address = c.base_kind == 2
        ? static_cast<unsigned char *>(reservation) + 1 : reservation;
    const auto base_in = std::uintptr_t(address);
    SIZE_T size = c.size;
    LARGE_INTEGER offset{};
    offset.QuadPart = static_cast<LONGLONG>(c.offset);
    LONG status = map(section, self, &address, c.zero, c.commit,
                       c.offset_pointer ? &offset : nullptr, &size, 2,
                       c.flags, PAGE_READWRITE);
    std::printf("CASE ordinal=%u commit=%zu size-in=%zu flags=%08lX zero=%llX offset-present=%u offset-in=%llX base-kind=%u base-in=%llX inherit=2 protect=%08lX status=%08lX base-out=%llX size-out=%zu offset-out=%llX\n",
        ordinal++, static_cast<std::size_t>(c.commit),
        static_cast<std::size_t>(c.size), c.flags,
        static_cast<unsigned long long>(c.zero), unsigned(c.offset_pointer),
        static_cast<unsigned long long>(c.offset), c.base_kind,
        static_cast<unsigned long long>(base_in), ULONG(PAGE_READWRITE), ULONG(status),
        static_cast<unsigned long long>(std::uintptr_t(address)), static_cast<std::size_t>(size),
        static_cast<unsigned long long>(offset.QuadPart));
    if (status >= 0) {
      ++mapped;
      MEMORY_BASIC_INFORMATION region{};
      SIZE_T queried = VirtualQuery(address, &region, sizeof(region));
      std::printf("REGION ordinal=%u queried=%zu region-bytes=%zu state=%08lX protect=%08lX type=%08lX allocation-protect=%08lX allocation=%llX\n",
          ordinal - 1, static_cast<std::size_t>(queried),
          static_cast<std::size_t>(region.RegionSize), region.State, region.Protect,
          region.Type, region.AllocationProtect,
          static_cast<unsigned long long>(std::uintptr_t(region.AllocationBase)));
      if (!address || !size || size > 65536 || size % 4096 || !queried ||
          region.State != MEM_COMMIT || region.Type != MEM_MAPPED)
        ++failures;
      LONG dropped = unmap(self, address);
      std::printf("UNMAP ordinal=%u status=%08lX\n", ordinal - 1, ULONG(dropped));
      if (dropped >= 0) ++released; else ++failures;
    }
    if (reservation && !VirtualFree(reservation, 0, MEM_RELEASE)) ++failures;
  }
  void *write_view = nullptr, *read_view = nullptr;
  SIZE_T write_size = 0, read_size = 0;
  LONG first = map(section, self, &write_view, 0, 16384, nullptr, &write_size,
                    2, MEM_TOP_DOWN, PAGE_READWRITE);
  LONG second = map(section, self, &read_view, 0, 0, nullptr, &read_size,
                     2, 0, PAGE_READONLY);
  bool coherent = false, retained = false;
  LONG write_unmap = LONG(0xc0000001u), read_unmap = LONG(0xc0000001u);
  if (first >= 0) ++mapped;
  if (second >= 0) ++mapped;
  if (first >= 0 && second >= 0 && write_view && read_view &&
      write_size == 65536 && read_size == 65536) {
    *static_cast<volatile ULONG *>(write_view) = 0x5a17c0de;
    coherent = *static_cast<volatile const ULONG *>(read_view) == 0x5a17c0de;
  }
  if (first >= 0) { write_unmap = unmap(self, write_view); if (write_unmap >= 0) ++released; }
  LONG closed = close(section);
  section = nullptr;
  if (second >= 0 && read_view && read_size == 65536)
    retained = *static_cast<volatile const ULONG *>(read_view) == 0x5a17c0de;
  if (second >= 0) { read_unmap = unmap(self, read_view); if (read_unmap >= 0) ++released; }
  std::printf("ALIAS write-status=%08lX read-status=%08lX write-base=%llX read-base=%llX write-size=%zu read-size=%zu coherent=%u retained-after-close=%u write-unmap=%08lX close=%08lX read-unmap=%08lX\n",
      ULONG(first), ULONG(second), static_cast<unsigned long long>(std::uintptr_t(write_view)),
      static_cast<unsigned long long>(std::uintptr_t(read_view)),
      static_cast<std::size_t>(write_size), static_cast<std::size_t>(read_size),
      unsigned(coherent), unsigned(retained), ULONG(write_unmap), ULONG(closed), ULONG(read_unmap));
  DWORD after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &after)) ++failures;
  if (!coherent || !retained || closed < 0 || write_unmap < 0 || read_unmap < 0 ||
      before != after || mapped != released) ++failures;
  std::printf("DONE cases=%u expected=%zu mapped=%u released=%u handles-before=%lu handles-after=%lu failures=%u\n",
      ordinal, cases.size(), mapped, released, before, after, failures);
  return failures ? 21 : 0;
}
