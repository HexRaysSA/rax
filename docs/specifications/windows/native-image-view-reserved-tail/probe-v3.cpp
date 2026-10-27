#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <windows.h>
#include <winternl.h>

using Open = LONG(NTAPI *)(HANDLE *, ULONG, OBJECT_ATTRIBUTES *);
using Map = LONG(NTAPI *)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T,
                          LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
using MapEx = LONG(NTAPI *)(HANDLE, HANDLE, void **, LARGE_INTEGER *, SIZE_T *,
                            ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
using Unmap = LONG(NTAPI *)(HANDLE, void *);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);
using QueryMemory = LONG(NTAPI *)(HANDLE, void *, ULONG, void *, SIZE_T,
                                  SIZE_T *);
struct SectionBasic {
  void *base;
  ULONG attributes;
  LARGE_INTEGER size;
};
struct Extension {
  ULONG kind, flags;
  SIZE_T rva, size;
};
static_assert(sizeof(Extension) == (sizeof(void *) == 8 ? 24 : 16));

int main() {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  auto open = reinterpret_cast<Open>(GetProcAddress(nt, "NtOpenSection"));
  auto map = reinterpret_cast<Map>(GetProcAddress(nt, "NtMapViewOfSection"));
  auto map_ex =
      reinterpret_cast<MapEx>(GetProcAddress(nt, "NtMapViewOfSectionEx"));
  auto unmap =
      reinterpret_cast<Unmap>(GetProcAddress(nt, "NtUnmapViewOfSection"));
  auto query = reinterpret_cast<Query>(GetProcAddress(nt, "NtQuerySection"));
  auto query_memory =
      reinterpret_cast<QueryMemory>(GetProcAddress(nt, "NtQueryVirtualMemory"));
  if (!open || !map || !map_ex || !unmap || !query || !query_memory)
    return 10;
  using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
  OSVERSIONINFOW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  if (reinterpret_cast<Version>(GetProcAddress(nt, "RtlGetVersion"))(&version) <
      0)
    return 11;
  USHORT process = 0, native = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &process, &native))
    return 12;
  printf("identity bits=%u build=%lu process=%04X native=%04X mbi_bytes=%zu\n",
         unsigned(sizeof(void *) * 8), version.dwBuildNumber, unsigned(process),
         unsigned(native), sizeof(MEMORY_BASIC_INFORMATION));
  if (version.dwBuildNumber != 29695 || native != 0xaa64)
    return 13;
  unsigned cases = 0, successful = 0, violations = 0;
  for (const wchar_t *root :
       {L"KnownDlls", L"KnownDlls32", L"KnownDllsChpe32"}) {
    for (const wchar_t *name :
         {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll"}) {
      std::wstring path = L"\\";
      path += root;
      path += L"\\";
      path += name;
      std::string label;
      for (wchar_t c : path)
        label += char(c);
      UNICODE_STRING text{};
      text.Buffer = path.data();
      text.Length = USHORT(path.size() * 2);
      text.MaximumLength = text.Length;
      OBJECT_ATTRIBUTES attributes{};
      attributes.Length = sizeof(attributes);
      attributes.ObjectName = &text;
      attributes.Attributes = 0x40;
      HANDLE section = nullptr;
      LONG status =
          open(&section, SECTION_QUERY | SECTION_MAP_READ, &attributes);
      printf("open label=%s status=%08lX\n", label.c_str(), ULONG(status));
      if (status < 0)
        continue;
      if (!section)
        return 14;
      SectionBasic basic{};
      SIZE_T returned = 0;
      status = query(section, 0, &basic, sizeof(basic), &returned);
      printf("section label=%s status=%08lX returned=%zu attributes=%08lX "
             "bytes=%llu\n",
             label.c_str(), ULONG(status), returned, basic.attributes,
             static_cast<unsigned long long>(basic.size.QuadPart));
      if (status < 0 || basic.size.QuadPart <= 0)
        return 15;
      for (ULONG machine : {0u, 0x14cu, 0x8664u}) {
        for (ULONG flags : {0u, 0x00800000u}) {
          for (SIZE_T requested :
               {SIZE_T(0), SIZE_T(4096), SIZE_T(basic.size.QuadPart)}) {
            for (unsigned unmap_tail : {0u, 1u}) {
              void *base = nullptr;
              SIZE_T size = requested;
              MEM_EXTENDED_PARAMETER parameter{};
              parameter.Type = MemExtendedParameterImageMachine;
              parameter.ULong = machine;
              status =
                  machine ? map_ex(section, GetCurrentProcess(), &base, nullptr,
                                   &size, flags, PAGE_READONLY, &parameter, 1)
                          : map(section, GetCurrentProcess(), &base, 0, 0,
                                nullptr, &size, 2, flags, PAGE_READONLY);
              printf(
                  "map case=%u label=%s machine=%04lX flags=%08lX status=%08lX "
                  "base=%llX bytes=%zu requested=%zu unmap_tail=%u\n",
                  cases++, label.c_str(), machine, flags, ULONG(status),
                  static_cast<unsigned long long>(uintptr_t(base)), size,
                  requested, unmap_tail);
              if (status < 0) {
                if (base)
                  return 16;
                continue;
              }
              if (!base || !size || size > SIZE_T(basic.size.QuadPart))
                return 17;
              ++successful;
              SIZE_T offset = 0;
              unsigned regions = 0;
              while (offset < size) {
                uintptr_t at = uintptr_t(base) + offset;
                MEMORY_BASIC_INFORMATION info{};
                SIZE_T queried = VirtualQuery(reinterpret_cast<void *>(at),
                                              &info, sizeof(info));
                if (queried != sizeof(info))
                  return 18;
                bool valid = uintptr_t(info.BaseAddress) == at &&
                             info.AllocationBase == base &&
                             info.Type == MEM_IMAGE && info.RegionSize &&
                             info.RegionSize <= size - offset;
                printf(
                    "region offset=%llX base=%llX allocation=%llX bytes=%llX "
                    "remaining=%llX state=%08lX protection=%08lX kind=%08lX "
                    "source_predicate=%u\n",
                    static_cast<unsigned long long>(offset),
                    static_cast<unsigned long long>(
                        uintptr_t(info.BaseAddress)),
                    static_cast<unsigned long long>(
                        uintptr_t(info.AllocationBase)),
                    static_cast<unsigned long long>(info.RegionSize),
                    static_cast<unsigned long long>(size - offset), info.State,
                    info.Protect, info.Type, unsigned(valid));
                if (!valid)
                  ++violations;
                if (!info.RegionSize ||
                    uintptr_t(info.BaseAddress) + info.RegionSize <= at ||
                    ++regions > 256)
                  return 19;
                offset = uintptr_t(info.BaseAddress) + info.RegionSize -
                         uintptr_t(base);
              }
              SIZE_T owner_extent = size;
              for (unsigned tail_region = 0; tail_region < 32; ++tail_region) {
                if (owner_extent > SIZE_T(basic.size.QuadPart) + 131072)
                  return 22;
                MEMORY_BASIC_INFORMATION q{};
                if (VirtualQuery(reinterpret_cast<void *>(uintptr_t(base) +
                                                          owner_extent),
                                 &q, sizeof(q)) != sizeof(q))
                  return 23;
                printf(
                    "tail offset=%llX base=%llX allocation=%llX bytes=%llX "
                    "state=%08lX protection=%08lX kind=%08lX owner=%u\n",
                    static_cast<unsigned long long>(owner_extent),
                    static_cast<unsigned long long>(uintptr_t(q.BaseAddress)),
                    static_cast<unsigned long long>(
                        uintptr_t(q.AllocationBase)),
                    static_cast<unsigned long long>(q.RegionSize), q.State,
                    q.Protect, q.Type, unsigned(q.AllocationBase == base));
                if (q.AllocationBase != base)
                  break;
                if (!q.RegionSize || uintptr_t(q.BaseAddress) + q.RegionSize <=
                                         uintptr_t(base) + owner_extent)
                  return 24;
                owner_extent =
                    uintptr_t(q.BaseAddress) + q.RegionSize - uintptr_t(base);
              }
              printf("owner bytes=%llX logical=%llX\n",
                     static_cast<unsigned long long>(owner_extent),
                     static_cast<unsigned long long>(size));
              for (ULONG kind : {0u, 1u}) {
                Extension extension{};
                extension.kind = kind;
                returned = 0;
                status = query_memory(GetCurrentProcess(), base, 14, &extension,
                                      sizeof(extension), &returned);
                printf(
                    "extension kind=%lu status=%08lX returned=%zu flags=%08lX "
                    "rva=%llX bytes=%llX\n",
                    kind, ULONG(status), returned, extension.flags,
                    static_cast<unsigned long long>(extension.rva),
                    static_cast<unsigned long long>(extension.size));
              }
              struct ImageInfo {
                void *base;
                SIZE_T size;
                ULONG flags;
              };
              for (SIZE_T query_offset :
                   {SIZE_T(0), size - 1, owner_extent - 1}) {
                ImageInfo info{};
                SIZE_T info_returned = 0;
                LONG info_status = query_memory(
                    GetCurrentProcess(),
                    reinterpret_cast<void *>(uintptr_t(base) + query_offset), 6,
                    &info, sizeof(info), &info_returned);
                printf("image_info offset=%llX status=%08lX returned=%zu "
                       "base=%llX bytes=%llX flags=%08lX\n",
                       static_cast<unsigned long long>(query_offset),
                       ULONG(info_status), info_returned,
                       static_cast<unsigned long long>(uintptr_t(info.base)),
                       static_cast<unsigned long long>(info.size), info.flags);
              }
              void *unmap_address =
                  (unmap_tail && owner_extent > size)
                      ? reinterpret_cast<void *>(uintptr_t(base) + size)
                      : base;
              LONG unmapped = unmap(GetCurrentProcess(), unmap_address);
              printf("unmap offset=%llX status=%08lX\n",
                     static_cast<unsigned long long>(uintptr_t(unmap_address) -
                                                     uintptr_t(base)),
                     ULONG(unmapped));
              if (unmapped < 0) {
                if (unmap(GetCurrentProcess(), base) < 0)
                  return 20;
              }
              MEMORY_BASIC_INFORMATION after{};
              if (VirtualQuery(base, &after, sizeof(after)) != sizeof(after))
                return 25;
              printf("released base_state=%08lX allocation=%llX\n", after.State,
                     static_cast<unsigned long long>(
                         uintptr_t(after.AllocationBase)));
            }
          }
        }
      }
      if (!CloseHandle(section))
        return 21;
    }
  }
  printf("done cases=%u successful=%u source_predicate_violations=%u\n", cases,
         successful, violations);
  return 0;
}
