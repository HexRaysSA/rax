#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <windows.h>
#include <winternl.h>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Set = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG);
static Query query;
static Set set;
static unsigned ordinal;

static void *argument(unsigned char *m, unsigned role) {
  switch (role) {
  case 1:
    return nullptr;
  case 2:
    return reinterpret_cast<void *>(1);
  case 3:
    return m + 257;
  case 4:
    return m + 4352;
  case 5:
    return m + 8448;
  case 6:
  case 7:
    return m + 12544;
  case 8:
    return m + 4094;
  case 9:
    return m + 4092;
  case 10:
    return reinterpret_cast<void *>(~uintptr_t(3));
  case 11:
    return reinterpret_cast<void *>(~uintptr_t(7));
  case 12:
    return m + 8190;
  case 13:
    return m + 12286;
  default:
    return m + 256;
  }
}
static bool policy(ULONG *flags) {
  ULONG size = 0;
  return query(GetCurrentProcess(), 34, flags, sizeof(*flags), &size) == 0 &&
         size == 4;
}
static bool observe(const char *family, unsigned kind, HANDLE handle,
                    ULONG grant, unsigned role, ULONG length, ULONG flags) {
  auto memory = static_cast<unsigned char *>(
      VirtualAlloc(nullptr, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!memory)
    return false;
  std::memset(memory, 0xa5, 16384);
  void *input = argument(memory, role);
  const auto base = reinterpret_cast<uintptr_t>(memory);
  const auto address = reinterpret_cast<uintptr_t>(input);
  const bool local = address >= base && address <= base + 16384 - 4;
  if (local)
    std::memcpy(input, &flags, 4);
  DWORD old = 0;
  const DWORD guard = (role == 7 ? PAGE_READONLY : PAGE_READWRITE) | PAGE_GUARD;
  if (!VirtualProtect(memory + 4096, 4096, PAGE_READONLY, &old) ||
      !VirtualProtect(memory + 8192, 4096, PAGE_NOACCESS, &old) ||
      !VirtualProtect(memory + 12288, 4096, guard, &old))
    return false;
  ULONG before = 0, after = 0;
  if (!policy(&before))
    return false;
  LONG status = 0;
  DWORD exception = 0;
  __try {
    status = set(handle, 34, input, length);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  MEMORY_BASIC_INFORMATION region{};
  if (VirtualQuery(memory + 12288, &region, sizeof(region)) != sizeof(region) ||
      !policy(&after) || !VirtualProtect(memory, 16384, PAGE_READWRITE, &old))
    return false;
  std::printf("{\"kind\":\"case\",\"ordinal\":%u,\"family\":\"%s\",\"handle_"
              "kind\":%u,\"grant\":%lu,\"input_role\":%u,\"length\":%lu,"
              "\"flags\":%lu,\"status\":%lu,\"exception\":%lu,\"guard_"
              "protection\":%lu,\"before\":%lu,\"after\":%lu,\"input\":\"",
              ordinal++, family, kind, grant, role, length, flags,
              static_cast<ULONG>(status), exception, region.Protect, before,
              after);
  const auto bytes = local && address <= base + 16384 - 16
                         ? static_cast<const unsigned char *>(input)
                         : memory + 256;
  for (unsigned i = 0; i < 16; ++i)
    std::printf("%02x", bytes[i]);
  std::printf("\"}\n");
  const bool freed = VirtualFree(memory, 0, MEM_RELEASE) != 0;
  return freed && before == 0x0d && after == before;
}
int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
               SEM_NOOPENFILEERRORBOX);
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  query = reinterpret_cast<Query>(
      GetProcAddress(ntdll, "NtQueryInformationProcess"));
  set = reinterpret_cast<Set>(GetProcAddress(ntdll, "NtSetInformationProcess"));
  using Version = LONG(NTAPI *)(OSVERSIONINFOW *);
  auto version =
      reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  OSVERSIONINFOW info{};
  info.dwOSVersionInfoSize = sizeof(info);
  USHORT process_machine = 0, native_machine = 0;
  DWORD dep = 0;
  BOOL permanent = FALSE;
  ULONG flags = 0;
  auto image =
      reinterpret_cast<const unsigned char *>(GetModuleHandleW(nullptr));
  auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(image);
  if (!query || !set || !version || version(&info) < 0 || !policy(&flags) ||
      !IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    return 2;
  auto pe = reinterpret_cast<const IMAGE_NT_HEADERS *>(image + dos->e_lfanew);
  const BOOL dep_ok =
      GetProcessDEPPolicy(GetCurrentProcess(), &dep, &permanent);
  std::printf("{\"kind\":\"host\",\"build\":%lu,\"process_machine\":%u,"
              "\"native_machine\":%u,\"pointer_bytes\":%zu,\"nx_compat\":%s,"
              "\"system_dep\":%u,\"process_dep_ok\":%s,\"process_dep\":%lu,"
              "\"permanent\":%s,\"execute_flags\":%lu}\n",
              info.dwBuildNumber, unsigned(process_machine),
              unsigned(native_machine), sizeof(void *),
              pe->OptionalHeader.DllCharacteristics &
                      IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                  ? "true"
                  : "false",
              unsigned(GetSystemDEPPolicy()), dep_ok ? "true" : "false", dep,
              permanent ? "true" : "false", flags);
  if (flags != 0x0d)
    return 3;
  const HANDLE self = GetCurrentProcess();
  for (ULONG value = 0; value < 128; ++value)
    if (!observe("flags", 0, self, 0, 0, 4, value))
      return 4;
  for (ULONG value :
       {0x80ul, 0x100ul, 0x200ul, 0x400ul, 0x80000000ul, 0xfffffffful})
    if (!observe("flags", 0, self, 0, 0, 4, value))
      return 5;
  for (ULONG length : {0ul, 1ul, 3ul, 4ul, 5ul, 8ul, 16ul, 0xfffffffful})
    for (unsigned role = 0; role < 14; ++role)
      if (!observe("input", 0, self, 0, role, length, 1))
        return 6;
  auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event)
    return 7;
  const HANDLE handles[] = {self, nullptr, reinterpret_cast<HANDLE>(1),
                            GetCurrentThread(), event};
  for (unsigned kind = 0; kind < 5; ++kind)
    for (ULONG length : {0ul, 3ul, 4ul, 5ul})
      for (unsigned role = 0; role < 10; ++role)
        if (!observe("handle", kind, handles[kind], 0, role, length, 1))
          return 8;
  if (!CloseHandle(event))
    return 9;
  using QueryObject = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
  auto query_object =
      reinterpret_cast<QueryObject>(GetProcAddress(ntdll, "NtQueryObject"));
  if (!query_object)
    return 10;
  for (ULONG requested :
       {0ul, 8ul, 0x20ul, 0x200ul, 0x400ul, 0x1000ul, 0x1200ul, 0x1ffffful}) {
    HANDLE handle = nullptr;
    if (!DuplicateHandle(self, self, self, &handle, requested, FALSE, 0))
      return 11;
    PUBLIC_OBJECT_BASIC_INFORMATION object_info{};
    ULONG returned = 0;
    const LONG status =
        query_object(handle, 0, &object_info, sizeof(object_info), &returned);
    std::printf("{\"kind\":\"grant\",\"requested\":%lu,\"status\":%lu,"
                "\"granted\":%lu}\n",
                requested, static_cast<ULONG>(status),
                object_info.GrantedAccess);
    if (status < 0)
      return 12;
    for (unsigned tag = 0; tag < 4; ++tag)
      for (ULONG value : {1ul, 2ul, 0x0dul, 0xfffffffful})
        if (!observe("rights", 5 + tag,
                     reinterpret_cast<HANDLE>(
                         reinterpret_cast<uintptr_t>(handle) | tag),
                     object_info.GrantedAccess, 0, 4, value))
          return 13;
    if (!CloseHandle(handle))
      return 14;
  }
  std::printf("{\"kind\":\"complete\",\"cases\":%u}\n", ordinal);
  return 0;
}
