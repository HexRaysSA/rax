#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static unsigned ordinal;
static constexpr ULONG QUERY_BYTES = static_cast<ULONG>(sizeof(void *));

static void *argument(unsigned char *memory, unsigned role, unsigned offset) {
  switch (role) {
  case 1:
    return nullptr;
  case 2:
    return reinterpret_cast<void *>(1);
  case 3:
    return memory + offset + 1;
  case 4:
    return memory + 4096 + offset;
  case 5:
    return memory + 8192 + offset;
  case 6:
  case 7:
    return memory + 12288 + offset;
  case 8:
    return memory + 4094;
  case 9:
    return memory + 4092;
  case 10:
    return reinterpret_cast<void *>(~uintptr_t(3));
  case 11:
    return reinterpret_cast<void *>(~uintptr_t(7));
  default:
    return memory + offset;
  }
}

static void bytes(const unsigned char *memory, const void *pointer,
                  unsigned fallback) {
  const auto base = reinterpret_cast<uintptr_t>(memory);
  const auto address = reinterpret_cast<uintptr_t>(pointer);
  const auto selected = address >= base && address <= base + 16384 - 16
                            ? static_cast<const unsigned char *>(pointer)
                            : memory + fallback;
  for (unsigned i = 0; i < 16; ++i)
    std::printf("%02x", selected[i]);
}

static bool observe(const char *family, unsigned handle_kind, HANDLE handle,
                    ULONG access, bool opened, unsigned output_role,
                    unsigned return_role, ULONG length, int alias = -1,
                    ULONG info_class = 26) {
  auto memory = static_cast<unsigned char *>(
      VirtualAlloc(nullptr, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!memory)
    return false;
  std::memset(memory, 0xa5, 16384);
  DWORD old = 0;
  const DWORD guard =
      (output_role == 7 || return_role == 7 ? PAGE_READONLY : PAGE_READWRITE) |
      PAGE_GUARD;
  if (!VirtualProtect(memory + 4096, 4096, PAGE_READONLY, &old) ||
      !VirtualProtect(memory + 8192, 4096, PAGE_NOACCESS, &old) ||
      !VirtualProtect(memory + 12288, 4096, guard, &old))
    return false;
  void *output = argument(memory, output_role, 256);
  auto returned = static_cast<ULONG *>(argument(memory, return_role, 512));
  if (alias >= 0)
    returned = reinterpret_cast<ULONG *>(memory + 256 + alias);
  LONG status = 0;
  DWORD exception = 0;
  __try {
    status = query(handle, info_class, output, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  MEMORY_BASIC_INFORMATION region{};
  if (VirtualQuery(memory + 12288, &region, sizeof(region)) != sizeof(region) ||
      !VirtualProtect(memory, 16384, PAGE_READWRITE, &old))
    return false;
  std::printf(
      "{\"kind\":\"case\",\"ordinal\":%u,\"query_class\":%lu,\"family\":\"%"
      "s\","
      "\"handle_kind\":%u,\"access\":%lu,\"opened\":%s,"
      "\"output_role\":%u,\"return_role\":%u,\"length\":%lu,\"alias\":%d,"
      "\"status\":%lu,\"exception\":%lu,\"guard_protection\":%lu,\"output\":"
      "\"",
      ordinal++, info_class, family, handle_kind, access,
      opened ? "true" : "false", output_role, return_role, length, alias,
      static_cast<DWORD>(status), exception, region.Protect);
  bytes(memory, output, 256);
  std::printf("\",\"returned\":\"");
  bytes(memory, returned, 512);
  std::printf("\"}\n");
  return VirtualFree(memory, 0, MEM_RELEASE) != 0;
}

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  query = reinterpret_cast<Query>(
      GetProcAddress(ntdll, "NtQueryInformationProcess"));
  using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
  const auto version =
      reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  USHORT process_machine = 0, native_machine = 0;
  const auto image =
      reinterpret_cast<const unsigned char *>(GetModuleHandleW(nullptr));
  const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(image);
  if (!query || !version || version(&info) < 0 ||
      dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
      dos->e_lfanew > 4096 ||
      !IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    return 2;
  const auto pe =
      reinterpret_cast<const IMAGE_NT_HEADERS *>(image + dos->e_lfanew);
  if (pe->Signature != IMAGE_NT_SIGNATURE)
    return 3;
  BOOL remote_present = FALSE;
  SetLastError(0);
  const bool remote_ok =
      CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_present) != FALSE;
  const DWORD remote_error = GetLastError();
  std::printf("{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
              "\"native_machine\":%u,\"pointer_bytes\":%zu,\"query_class\":26,"
              "\"debugger_present\":%s,\"remote_query_ok\":%s,"
              "\"remote_error\":%lu,\"remote_debugger_present\":%s}\n",
              info.dwBuildNumber, static_cast<unsigned>(process_machine),
              static_cast<unsigned>(native_machine), sizeof(void *),
              IsDebuggerPresent() ? "true" : "false",
              remote_ok ? "true" : "false", remote_error,
              remote_present ? "true" : "false");
  const auto self = GetCurrentProcess();
  ULONG_PTR basic[6] = {}, wow = 0;
  ULONG got_basic = 0, got_wow = 0;
  const LONG basic_status = query(self, 0, basic, sizeof(basic), &got_basic);
  const LONG wow_status = query(self, 26, &wow, sizeof(wow), &got_wow);
  std::printf(
      "{\"kind\":\"identity\",\"basic_status\":%lu,\"basic_returned\":%lu,"
      "\"peb_from_basic\":%llu,\"wow64_status\":%lu,\"wow64_information\":%llu,"
      "\"wow64_returned\":%lu}\n",
      static_cast<DWORD>(basic_status), got_basic,
      static_cast<unsigned long long>(basic[1]), static_cast<DWORD>(wow_status),
      static_cast<unsigned long long>(wow), got_wow);

  for (ULONG length : {0ul, 1ul, 3ul, 4ul, 5ul, 8ul, 16ul})
    if (!observe("length", 0, self, 0, true, 0, 0, length))
      return 4;
  for (unsigned output = 0; output < 10; ++output)
    for (unsigned returned = 0; returned < 10; ++returned)
      if (!observe("buffer", 0, self, 0, true, output, returned, QUERY_BYTES))
        return 5;
  const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event)
    return 6;
  const HANDLE handles[] = {self, nullptr, reinterpret_cast<HANDLE>(1),
                            GetCurrentThread(), event};
  for (unsigned kind = 0; kind < 5; ++kind)
    for (ULONG length : {QUERY_BYTES - 1, QUERY_BYTES})
      for (unsigned output = 0; output < 4; ++output)
        for (unsigned returned = 0; returned < 3; ++returned)
          if (!observe("handle", kind, handles[kind], 0, true, output, returned,
                       length))
            return 7;
  if (!CloseHandle(event))
    return 8;
  for (ULONG access :
       {0ul, 8ul, 0x20ul, 0x400ul, 0x1000ul, 0x1400ul, 0x1ffffful}) {
    const auto handle = OpenProcess(access, FALSE, GetCurrentProcessId());
    if (!observe("rights", 5, handle, access, handle != nullptr, 0, 0,
                 QUERY_BYTES))
      return 9;
    if (handle && !CloseHandle(handle))
      return 10;
  }
  for (int alias = 0; alias <= static_cast<int>(QUERY_BYTES); ++alias)
    if (!observe("alias", 0, self, 0, true, 0, 0, QUERY_BYTES, alias))
      return 11;
  for (ULONG length : {0ul, 1ul, 3ul, 4ul, 5ul, 8ul, 16ul})
    for (unsigned returned = 0; returned < 10; ++returned)
      if (!observe("null-length", 0, self, 0, true, 1, returned, length))
        return 12;
  struct UpperQuery {
    const char *name;
    ULONG info_class;
    ULONG size;
  };
  const UpperQuery queries[] = {{"upper-wow64", 26, QUERY_BYTES}};
  for (const auto &item : queries)
    for (unsigned kind : {0u, 2u})
      for (ULONG length :
           {0ul, 1ul, item.size - 1, item.size, item.size + 1, 0xfffffffful})
        for (unsigned output : {10u, 11u})
          for (unsigned returned : {0u, 1u, 6u, 7u})
            if (!observe(item.name, kind, handles[kind], 0, true, output,
                         returned, length, -1, item.info_class))
              return 13;
  std::printf("{\"kind\":\"complete\",\"cases\":%u}\n", ordinal);
  return 0;
}
