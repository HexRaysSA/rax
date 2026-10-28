#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>
using Open = LONG(NTAPI *)(HANDLE *, ULONG, OBJECT_ATTRIBUTES *);
using Map = LONG(NTAPI *)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T,
                          LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
using MapEx = LONG(NTAPI *)(HANDLE, HANDLE, void **, LARGE_INTEGER *, SIZE_T *,
                            ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
using Unmap = LONG(NTAPI *)(HANDLE, void *);
using QueryMemory = LONG(NTAPI *)(HANDLE, void *, ULONG, void *, SIZE_T,
                                  SIZE_T *);
static QueryMemory query_memory;
static bool copy(void *out, const void *in, size_t n) {
  __try {
    memcpy(out, in, n);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}
static bool read_failed = false;
template <class T> static bool read(uintptr_t at, T &value) {
  bool ok = copy(&value, reinterpret_cast<void *>(at), sizeof(value));
  if (!ok)
    read_failed = true;
  return ok;
}
static std::string ascii(uintptr_t at) {
  std::string out;
  for (unsigned i = 0; i < 512; ++i) {
    char c = 0;
    if (!read(at + i, c))
      return "<fault>";
    if (!c)
      return out;
    out += c;
  }
  read_failed = true;
  return "<bounds>";
}
static void wide_hex(const wchar_t *p, size_t n) {
  for (size_t i = 0; i < n; ++i)
    printf("%04X", unsigned(p[i]));
}
static void backing(void *base) {
  alignas(8) unsigned char memory[8192]{};
  SIZE_T length = 0;
  LONG s = query_memory(GetCurrentProcess(), base, 2, memory, sizeof(memory),
                        &length);
  printf(" backing_status=%08lX backing_utf16=", ULONG(s));
  if (s >= 0) {
    UNICODE_STRING u{};
    memcpy(&u, memory, sizeof(u));
    uintptr_t at = uintptr_t(u.Buffer), lo = uintptr_t(memory);
    if (u.Length % 2 == 0 && at >= lo && at - lo <= sizeof(memory) &&
        u.Length <= sizeof(memory) - (at - lo))
      wide_hex(u.Buffer, u.Length / 2);
    else
      printf("INVALID");
  }
}
struct Image {
  uintptr_t base{};
  DWORD bytes{};
  WORD machine{}, magic{};
  DWORD exports{}, export_bytes{};
  bool parse(void *p) {
    base = uintptr_t(p);
    IMAGE_DOS_HEADER d{};
    DWORD signature = 0;
    IMAGE_FILE_HEADER f{};
    if (!read(base, d) || d.e_magic != IMAGE_DOS_SIGNATURE || d.e_lfanew < 0 ||
        d.e_lfanew > 4096)
      return false;
    uintptr_t nt = base + unsigned(d.e_lfanew);
    if (!read(nt, signature) || signature != IMAGE_NT_SIGNATURE ||
        !read(nt + 4, f) || !read(nt + 24, magic))
      return false;
    machine = f.Machine;
    if (magic != 0x10b && magic != 0x20b)
      return false;
    if (!read(nt + 24 + 56, bytes))
      return false;
    uintptr_t dir = nt + 24 + (magic == 0x10b ? 96 : 112);
    return read(dir, exports) && read(dir + 4, export_bytes);
  }
  bool span(DWORD rva, size_t n) const {
    return rva <= bytes && n <= size_t(bytes - rva);
  }
  DWORD symbol(const char *wanted) const {
    IMAGE_EXPORT_DIRECTORY e{};
    if (!exports || !span(exports, sizeof(e)) || !read(base + exports, e) ||
        e.NumberOfNames > 65536 || e.NumberOfFunctions > 65536)
      return 0;
    for (DWORD i = 0; i < e.NumberOfNames; ++i) {
      DWORD name = 0;
      WORD ord = 0;
      if (!read(base + e.AddressOfNames + size_t(i) * 4, name) ||
          !span(name, 1))
        return 0;
      if (ascii(base + name) != wanted)
        continue;
      if (!read(base + e.AddressOfNameOrdinals + size_t(i) * 2, ord) ||
          ord >= e.NumberOfFunctions)
        return 0;
      DWORD fn = 0;
      return read(base + e.AddressOfFunctions + size_t(ord) * 4, fn) ? fn : 0;
    }
    return 0;
  }
  void print(const char *kind, const char *label) const {
    printf("image kind=%s label=%s machine=%04X magic=%04X bytes=%lu", kind,
           label, unsigned(machine), unsigned(magic), bytes);
    for (const char *name :
         {"__C_specific_handler", "LdrInitializeThunk", "NtClose"}) {
      DWORD rva = symbol(name);
      printf(" %s_rva=%08lX %s_code=", name, rva, name);
      unsigned char code[16]{};
      if (rva && span(rva, sizeof(code)) &&
          copy(code, reinterpret_cast<void *>(base + rva), sizeof(code)))
        for (auto b : code)
          printf("%02X", unsigned(b));
      if (rva >= exports && rva < exports + export_bytes)
        printf("forwarder:%s", ascii(base + rva).c_str());
    }
    backing(reinterpret_cast<void *>(base));
    printf("\n");
  }
};
int wmain(int argc, wchar_t **argv) {
  if (argc != 2)
    return 24;
  FILE *output = nullptr;
  if (_wfreopen_s(&output, argv[1], L"wb", stdout) || !output)
    return 25;
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  if (!nt)
    return 10;
  auto open = reinterpret_cast<Open>(GetProcAddress(nt, "NtOpenSection"));
  auto map = reinterpret_cast<Map>(GetProcAddress(nt, "NtMapViewOfSection"));
  auto map_ex =
      reinterpret_cast<MapEx>(GetProcAddress(nt, "NtMapViewOfSectionEx"));
  auto unmap =
      reinterpret_cast<Unmap>(GetProcAddress(nt, "NtUnmapViewOfSection"));
  query_memory =
      reinterpret_cast<QueryMemory>(GetProcAddress(nt, "NtQueryVirtualMemory"));
  if (!open || !map || !map_ex || !unmap || !query_memory)
    return 11;
  using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
  OSVERSIONINFOW v{};
  v.dwOSVersionInfoSize = sizeof(v);
  if (reinterpret_cast<Version>(GetProcAddress(nt, "RtlGetVersion"))(&v) < 0)
    return 12;
  USHORT process = 0, native = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &process, &native))
    return 13;
  printf("identity bits=%u build=%lu process=%04X native=%04X\n",
         unsigned(sizeof(void *) * 8), v.dwBuildNumber, unsigned(process),
         unsigned(native));
  if (v.dwBuildNumber != 29695 || native != 0xaa64)
    return 14;

  using QueryProcess = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
  auto query_process = reinterpret_cast<QueryProcess>(
      GetProcAddress(nt, "NtQueryInformationProcess"));
  if (!query_process)
    return 29;
  PROCESS_BASIC_INFORMATION basic{};
  ULONG basic_length = 0;
  LONG basic_status = query_process(GetCurrentProcess(), 0, &basic,
                                    sizeof(basic), &basic_length);
  unsigned char wow_info[40]{};
  printf("wow64 status=%08lX returned=%lu information=", ULONG(basic_status),
         basic_length);
  if (basic_status < 0 || !basic.PebBaseAddress ||
      !copy(wow_info,
            reinterpret_cast<unsigned char *>(basic.PebBaseAddress) + 0x490,
            sizeof(wow_info)))
    return 37;
  for (auto b : wow_info)
    printf("%02X", unsigned(b));
  printf("\n");

  for (const wchar_t *name :
       {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll"}) {
    HMODULE module = GetModuleHandleW(name);
    if (!module)
      return 15;
    Image image;
    if (!image.parse(module))
      return 16;
    std::string label;
    for (const wchar_t *c = name; *c; ++c)
      label += char(*c);
    image.print("loaded", label.c_str());
    FARPROC handler = GetProcAddress(module, "__C_specific_handler");
    printf("resolved label=%s present=%u inside=%u code=", label.c_str(),
           unsigned(handler != nullptr),
           unsigned(handler && uintptr_t(handler) >= image.base &&
                    uintptr_t(handler) - image.base < image.bytes));
    unsigned char code[16]{};
    if (handler && copy(code, reinterpret_cast<void *>(handler), sizeof(code)))
      for (auto b : code)
        printf("%02X", unsigned(b));
    if (handler)
      backing(reinterpret_cast<void *>(handler));
    printf("\n");
  }
  unsigned cases = 0, successful = 0;
  for (const wchar_t *root :
       {L"KnownDlls", L"KnownDlls32", L"KnownDllsChpe32"}) {
    for (const wchar_t *name :
         {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll"}) {
      std::wstring path = L"\\";
      path += root;
      path += L"\\";
      path += name;
      UNICODE_STRING u{};
      u.Length = USHORT(path.size() * 2);
      u.MaximumLength = u.Length;
      u.Buffer = path.data();
      OBJECT_ATTRIBUTES a{};
      a.Length = sizeof(a);
      a.ObjectName = &u;
      a.Attributes = 0x40;
      HANDLE h = nullptr;
      LONG opened = open(&h, SECTION_QUERY | SECTION_MAP_READ, &a);
      std::string label;
      for (wchar_t c : path)
        label += char(c);
      printf("open label=%s status=%08lX\n", label.c_str(), ULONG(opened));
      if (opened < 0) {
        if (h)
          CloseHandle(h);
        continue;
      }
      if (!h)
        return 17;
      for (ULONG machine : {0u, 0x14cu, 0xaa64u, 0x8664u}) {
        void *base = nullptr;
        SIZE_T size = 0;
        MEM_EXTENDED_PARAMETER parameter{};
        parameter.Type = MemExtendedParameterImageMachine;
        parameter.ULong = machine;
        LONG status = machine ? map_ex(h, GetCurrentProcess(), &base, nullptr,
                                       &size, 0, PAGE_READONLY, &parameter, 1)
                              : map(h, GetCurrentProcess(), &base, 0, 0,
                                    nullptr, &size, 2, 0, PAGE_READONLY);
        ++cases;
        printf("map label=%s request=%04lX status=%08lX size=%llu\n",
               label.c_str(), machine, ULONG(status),
               static_cast<unsigned long long>(size));
        if (status >= 0) {
          if (!base)
            return 18;
          Image image;
          if (!image.parse(base))
            return 19;
          image.print("mapped", label.c_str());
          ++successful;
          if (unmap(GetCurrentProcess(), base) < 0)
            return 20;
        } else if (base)
          return 21;
      }
      if (!CloseHandle(h))
        return 22;
    }
  }
  auto open_directory =
      reinterpret_cast<Open>(GetProcAddress(nt, "NtOpenDirectoryObject"));
  if (!open_directory)
    return 26;
  std::wstring directory = L"\\KnownDlls32";
  UNICODE_STRING du{};
  du.Buffer = directory.data();
  du.Length = USHORT(directory.size() * 2);
  du.MaximumLength = du.Length;
  OBJECT_ATTRIBUTES da{};
  da.Length = sizeof(da);
  da.ObjectName = &du;
  da.Attributes = 0x40;
  HANDLE dh = nullptr;
  LONG ds = open_directory(&dh, 0x3, &da);
  printf("directory status=%08lX\n", ULONG(ds));
  if (ds < 0 || !dh)
    return 27;
  for (const wchar_t *name :
       {L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll"}) {
    std::wstring n = name;
    UNICODE_STRING u{};
    u.Buffer = n.data();
    u.Length = USHORT(n.size() * 2);
    u.MaximumLength = u.Length;
    OBJECT_ATTRIBUTES a{};
    a.Length = sizeof(a);
    a.RootDirectory = dh;
    a.ObjectName = &u;
    a.Attributes = 0x40;
    HANDLE h = nullptr;
    LONG opened = open(&h, SECTION_QUERY | SECTION_MAP_READ, &a);
    std::string label = "relative32:";
    for (wchar_t c : n)
      label += char(c);
    printf("relative_open label=%s status=%08lX\n", label.c_str(),
           ULONG(opened));
    if (opened < 0 || !h)
      return 28;
    void *base = nullptr;
    SIZE_T size = 0;
    LONG status = map(h, GetCurrentProcess(), &base, 0, 0, nullptr, &size, 2, 0,
                      PAGE_READONLY);
    ++cases;
    printf("relative_map label=%s status=%08lX size=%llu\n", label.c_str(),
           ULONG(status), static_cast<unsigned long long>(size));
    if (status >= 0) {
      if (!base)
        return 18;
      Image image;
      if (!image.parse(base))
        return 19;
      image.print("relative", label.c_str());
      ++successful;
      if (unmap(GetCurrentProcess(), base) < 0)
        return 20;
    } else if (base)
      return 21;
    if (!CloseHandle(h))
      return 22;
  }
  if (!CloseHandle(dh))
    return 22;
  if (read_failed)
    return 23;
  printf("done cases=%u successful=%u\n", cases, successful);
  return 0;
}
