#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <winternl.h>

using OpenSection = LONG(NTAPI *)(HANDLE *, ULONG, OBJECT_ATTRIBUTES *);
using QuerySection = LONG(NTAPI *)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);
using MapSection = LONG(NTAPI *)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T,
                                 LARGE_INTEGER *, SIZE_T *, ULONG, ULONG,
                                 ULONG);
using UnmapSection = LONG(NTAPI *)(HANDLE, void *);
using Close = LONG(NTAPI *)(HANDLE);

static void fail(const char *operation) {
  printf("failure=%s error=%lu\n", operation, GetLastError());
  ExitProcess(21);
}

static void dump(const char *name, const void *pointer, size_t bytes) {
  printf("bytes name=%s size=%zu hex=", name, bytes);
  const auto data = static_cast<const unsigned char *>(pointer);
  for (size_t i = 0; i < bytes; ++i)
    printf("%02X", unsigned(data[i]));
  puts("");
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  auto open =
      reinterpret_cast<OpenSection>(GetProcAddress(ntdll, "NtOpenSection"));
  auto query =
      reinterpret_cast<QuerySection>(GetProcAddress(ntdll, "NtQuerySection"));
  auto map =
      reinterpret_cast<MapSection>(GetProcAddress(ntdll, "NtMapViewOfSection"));
  auto unmap = reinterpret_cast<UnmapSection>(
      GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  auto close = reinterpret_cast<Close>(GetProcAddress(ntdll, "NtClose"));
  if (!open || !query || !map || !unmap || !close)
    fail("installed-exports");
  WCHAR text[] = L"\\Windows\\SharedSection";
  UNICODE_STRING name{};
  name.Length = sizeof(text) - sizeof(WCHAR);
  name.MaximumLength = sizeof(text);
  name.Buffer = text;

  OBJECT_ATTRIBUTES object{};
  object.Length = sizeof(object);
  object.ObjectName = &name;
  object.Attributes = 0x40;
  HANDLE section = nullptr;
  LONG opened = open(&section, 4, &object);
  if (opened < 0 || !section)
    fail("open-read-section");
  struct Case {
    SIZE_T offset, size, zero, commit;
    ULONG inherit, flags, protection;
    bool offset_pointer;
  };
  const Case cases[] = {
      {0, 0, 0, 0, 2, 0, 2, false},
      {0, 1, 0, 0, 2, 0, 2, false},
      {0, 4096, 0, 0, 2, 0, 2, false},
      {0, 20480, 0, 0, 2, 0, 2, false},
      {0, 20481, 0, 0, 2, 0, 2, false},
      {0, 1048576, 0, 0, 2, 0, 2, false},
      {0, 1048577, 0, 0, 2, 0, 2, false},
      {0, 0, 0, 0, 2, 0, 2, true},
      {1, 0, 0, 0, 2, 0, 2, true},
      {4096, 0, 0, 0, 2, 0, 2, true},
      {65535, 0, 0, 0, 2, 0, 2, true},
      {65536, 0, 0, 0, 2, 0, 2, true},
      {1048576, 0, 0, 0, 2, 0, 2, true},
      {1048577, 1, 0, 0, 2, 0, 2, true},
      {65536, 4096, 0, 0, 2, 0, 2, true},
      {0, 0, 1, 0, 2, 0, 2, false},
      {0, 0, 16, 0, 2, 0, 2, false},
      {0, 0, 21, 0, 2, 0, 2, false},
      {0, 0, 32, 0, 2, 0, 2, false},
      {0, 0, 0, 1, 2, 0, 2, false},
      {0, 0, 0, 4096, 2, 0, 2, false},
      {0, 0, 0, 1048577, 2, 0, 2, false},
      {0, 0, 0, 0, 0, 0, 2, false},
      {0, 0, 0, 0, 1, 0, 2, false},
      {0, 0, 0, 0, 3, 0, 2, false},
      {0, 0, 0, 0, 2, 0x100000, 2, false},
      {0, 0, 0, 0, 2, 0x800000, 2, false},
      {0, 0, 0, 0, 2, 0x20000000, 2, false},
      {0, 0, 0, 0, 2, 0x2000, 2, false},
      {0, 0, 0, 0, 2, 1, 2, false},
      {0, 0, 0, 0, 2, 0, 1, false},
      {0, 0, 0, 0, 2, 0, 4, false},
      {0, 0, 0, 0, 2, 0, 8, false},
      {0, 0, 0, 0, 2, 0, 0x10, false},
      {0, 0, 0, 0, 2, 0, 0x20, false},
      {0, 0, 0, 0, 2, 0, 0x40, false},
      {0, 0, 0, 0, 2, 0, 0x80, false},
      {0, 0, 0, 0, 2, 0, 0x102, false},
      {0, 0, 0, 0, 2, 0, 0x202, false},
      {0, 0, 0, 0, 2, 0, 0x402, false},
  };
  unsigned ordinal = 0, mapped_views = 0;
  for (const auto &c : cases) {
    void *address = nullptr;
    SIZE_T size = c.size;
    LARGE_INTEGER offset{};
    offset.QuadPart = c.offset;
    LONG result = map(section, reinterpret_cast<HANDLE>(intptr_t(-1)), &address,
                      c.zero, c.commit, c.offset_pointer ? &offset : nullptr,
                      &size, c.inherit, c.flags, c.protection);
    printf("case=%u width=%zu offset-present=%u offset-in=%zu size-in=%zu "
           "zero=%zu commit=%zu inherit=%lu flags=%08lX protect=%08lX "
           "status=%08lX base=%llX size-out=%zu offset-out=%llX\n",
           ordinal++, sizeof(void *), unsigned(c.offset_pointer), static_cast<size_t>(c.offset),
           static_cast<size_t>(c.size), static_cast<size_t>(c.zero), static_cast<size_t>(c.commit), c.inherit, c.flags, c.protection,
           ULONG(result), static_cast<unsigned long long>(uintptr_t(address)),
           static_cast<size_t>(size), static_cast<unsigned long long>(offset.QuadPart));
    if (result >= 0) {
      ++mapped_views;
      SIZE_T at = 0;
      unsigned count = 0;
      while (at < size) {
        MEMORY_BASIC_INFORMATION region{};
        auto current = static_cast<unsigned char *>(address) + at;
        if (!VirtualQuery(current, &region, sizeof(region)) || ++count > 256 ||
            !region.RegionSize)
          fail("query-owned-view");
        SIZE_T within = uintptr_t(current) - uintptr_t(region.BaseAddress);
        SIZE_T span = std::min(region.RegionSize - within, size - at);
        printf("region offset=%zu bytes=%zu state=%08lX protection=%08lX "
               "type=%08lX allocation-protection=%08lX\n",
               static_cast<size_t>(at), static_cast<size_t>(span), region.State, region.Protect, region.Type,
               region.AllocationProtect);
        if (!span)
          fail("region-progress");
        if (ordinal == 1 && region.State == MEM_COMMIT)
          dump("committed-snapshot", current, span);
        at += span;
      }
      LONG released = unmap(reinterpret_cast<HANDLE>(intptr_t(-1)), address);
      printf("unmap status=%08lX\n", ULONG(released));
      if (released < 0)
        fail("release-owned-view");
    }
  }
  LONG closed = close(section);
  printf("close status=%08lX\n", ULONG(closed));
  if (closed < 0)
    fail("close-owned-handle");
  printf("complete cases=%u mapped-views=%u\n", ordinal, mapped_views);
  return 0;
}
