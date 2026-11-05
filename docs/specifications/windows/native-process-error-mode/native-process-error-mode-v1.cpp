// Independent Windows process error-mode control. Only this process is changed.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Set = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG);
using QueryObject = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Version = LONG(NTAPI *)(void *);
using ProcessInfo = BOOL(WINAPI *)(HANDLE, int, void *, DWORD);
static Query query;
static Set set;
static QueryObject query_object;
static unsigned calls, exceptions, pending;

static ULONG raw_mode() {
  ULONG mode = 0xa5a5a5a5, length = 0xa5a5a5a5;
  LONG s = query(GetCurrentProcess(), 12, &mode, 4, &length);
  if (s != 0 || length != 4) {
    printf("fatal phase=query-mode status=%08lX length=%lu\n", s, length);
    ExitProcess(20);
  }
  return mode;
}

static void bytes(const unsigned char *p, unsigned n) {
  for (unsigned i = 0; i != n; ++i)
    printf("%02X", p[i]);
}

static DWORD protection(void *p) {
  MEMORY_BASIC_INFORMATION info = {};
  if (!VirtualQuery(p, &info, sizeof(info)))
    ExitProcess(21);
  return info.Protect;
}

static void protect(void *p, DWORD value) {
  DWORD previous;
  if (!VirtualProtect(p, 4096, value, &previous))
    ExitProcess(22);
}

static void modes() {
  const ULONG values[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 0x8000,
                          0x8001, 0x8003, 0x8007, 0x10000,
                          0x40000000, 0xffffffff, 0};
  for (ULONG value : values) {
    ULONG before = raw_mode();
    SetLastError(0x12345678);
    LONG status = set(GetCurrentProcess(), 12, &value, 4);
    DWORD error = GetLastError();
    ULONG after = raw_mode();
    UINT public_mode = GetErrorMode();
    printf("kind=mode api=nt value=%08lX before=%08lX status=%08lX "
           "after=%08lX public=%08X last=%08lX\n",
           value, before, status, after, public_mode, error);
    ++calls;
  }
  for (ULONG value : values) {
    ULONG before = raw_mode();
    SetLastError(0x12345678);
    UINT previous = SetErrorMode(value);
    DWORD error = GetLastError();
    ULONG after = raw_mode();
    UINT public_mode = GetErrorMode();
    printf("kind=mode api=win32 value=%08lX before=%08lX previous=%08X "
           "after=%08lX public=%08X last=%08lX\n",
           value, before, previous, after, public_mode, error);
    ++calls;
  }
}

int main() {
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  query = reinterpret_cast<Query>(GetProcAddress(nt, "NtQueryInformationProcess"));
  set = reinterpret_cast<Set>(GetProcAddress(nt, "NtSetInformationProcess"));
  query_object = reinterpret_cast<QueryObject>(GetProcAddress(nt, "NtQueryObject"));
  auto version = reinterpret_cast<Version>(GetProcAddress(nt, "RtlGetVersion"));
  auto machine = reinterpret_cast<ProcessInfo>(GetProcAddress(
      GetModuleHandleW(L"kernelbase.dll"), "GetProcessInformation"));
  if (!query || !set || !query_object || !version || !machine)
    return 2;
  unsigned char ver[284] = {};
  *reinterpret_cast<ULONG *>(ver) = sizeof(ver);
  if (version(ver))
    return 3;
  // ProcessMachineTypeInfo=9 returns USHORT Machine, USHORT reserved, ULONG flags.
  unsigned char machine_info[8] = {};
  auto process_info = machine;
  if (!process_info(GetCurrentProcess(), 9, machine_info, sizeof(machine_info)))
    return 4;
  auto image = reinterpret_cast<const IMAGE_DOS_HEADER *>(GetModuleHandleW(nullptr));
  auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(
      reinterpret_cast<const unsigned char *>(image) + image->e_lfanew);
  USHORT own_machine = headers->FileHeader.Machine;
  USHORT reported = *reinterpret_cast<USHORT *>(machine_info);
  if (reported != own_machine)
    return 5;
  ULONG original = raw_mode();
  printf("host machine=%u pointer-bytes=%zu build=%lu laa=%u initial=%08lX "
         "public=%08X\n", own_machine, sizeof(void *),
         *reinterpret_cast<ULONG *>(ver + 12),
         !!(headers->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE),
         original, GetErrorMode());

  struct Role { const char *name; HANDLE handle; bool owned; ULONG grant; };
  Role roles[] = {
      {"pseudo", GetCurrentProcess(), false, 0xffffffff},
      {"real-zero", nullptr, true, 0},
      {"real-query", nullptr, true, 0x400},
      {"real-query-limited", nullptr, true, 0x1000},
      {"real-set", nullptr, true, 0x200},
      {"real-set-limited", nullptr, true, 0x2000},
      {"real-all", nullptr, true, 0x1fffff},
      {"event", CreateEventW(nullptr, FALSE, FALSE, nullptr), true, 0},
      {"thread", GetCurrentThread(), false, 0},
      {"invalid", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xdead)), false, 0}};
  if (!roles[7].handle) return 6;
  unsigned owned = 1, closed = 0;
  for (unsigned i = 1; i <= 6; ++i) {
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
                         &roles[i].handle, roles[i].grant, FALSE, 0))
      return 6;
    ++owned;
    unsigned char basic[56] = {};
    ULONG required = 0;
    LONG status = query_object(roles[i].handle, 0, basic, sizeof(basic), &required);
    ULONG actual = *reinterpret_cast<ULONG *>(basic + 4);
    printf("kind=grant role=%s requested=%08lX actual=%08lX status=%08lX "
           "required=%lu\n", roles[i].name, roles[i].grant, actual, status, required);
    if (status)
      return 7;
  }
  auto first = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  auto second = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!first || !second)
    return 8;
  const char *cases[] = {"valid", "buffer-null", "returned-null", "both-null",
      "buffer-bad", "returned-bad", "buffer-unaligned", "returned-unaligned",
      "buffer-readonly", "returned-readonly", "buffer-guard", "returned-guard",
      "buffer-noaccess", "returned-noaccess", "same", "returned-plus2",
      "buffer-cross", "returned-cross", "both-guard", "buffer-readonly-guard",
      "returned-readonly-guard"};
  const ULONG lengths[] = {0, 1, 3, 4, 5, 7, 8, 16, 0xffffffff};
  for (unsigned operation = 0; operation < 2; ++operation) {
    for (const auto &role : roles) {
      for (const auto *name : cases) {
        for (ULONG length : lengths) {
          for (unsigned i = 0; i < 3; ++i) {
            protect(first + i * 4096, PAGE_READWRITE);
            protect(second + i * 4096, PAGE_READWRITE);
          }
          memset(first, 0xa5, 12288);
          memset(second, 0xa5, 12288);
          auto buffer = first + 4096 + 256;
          auto returned = second + 4096 + 256;
          if (!strcmp(name, "buffer-null") || !strcmp(name, "both-null")) buffer = nullptr;
          if (!strcmp(name, "returned-null") || !strcmp(name, "both-null")) returned = nullptr;
          if (!strcmp(name, "buffer-bad")) buffer = reinterpret_cast<unsigned char *>(static_cast<ULONG_PTR>(0xdead0000));
          if (!strcmp(name, "returned-bad")) returned = reinterpret_cast<unsigned char *>(static_cast<ULONG_PTR>(0xdead0000));
          if (!strcmp(name, "buffer-unaligned")) ++buffer;
          if (!strcmp(name, "returned-unaligned")) ++returned;
          if (!strcmp(name, "same")) returned = buffer;
          if (!strcmp(name, "returned-plus2")) returned = buffer + 2;
          if (!strcmp(name, "buffer-cross")) { buffer = first + 8190; protect(first + 8192, PAGE_NOACCESS); }
          if (!strcmp(name, "returned-cross")) { returned = second + 8190; protect(second + 8192, PAGE_NOACCESS); }
          // Setter input is written before permissions, including unaligned
          // and crossing cases. For crossing input only readable bytes remain.
          if (operation && reinterpret_cast<uintptr_t>(buffer) >= reinterpret_cast<uintptr_t>(first) && reinterpret_cast<uintptr_t>(buffer) <= reinterpret_cast<uintptr_t>(first) + 12284) {
            if (!strcmp(name, "buffer-cross")) {
              protect(first + 8192, PAGE_READWRITE);
              ULONG value = 3; memcpy(buffer, &value, 4);
              protect(first + 8192, PAGE_NOACCESS);
            } else { ULONG value = 3; memcpy(buffer, &value, 4); }
          }
          if (!strcmp(name, "buffer-readonly")) protect(first + 4096, PAGE_READONLY);
          if (!strcmp(name, "returned-readonly")) protect(second + 4096, PAGE_READONLY);
          if (!strcmp(name, "buffer-guard") || !strcmp(name, "both-guard")) protect(first + 4096, PAGE_READWRITE | PAGE_GUARD);
          if (!strcmp(name, "returned-guard") || !strcmp(name, "both-guard")) protect(second + 4096, PAGE_READWRITE | PAGE_GUARD);
          if (!strcmp(name, "buffer-noaccess")) protect(first + 4096, PAGE_NOACCESS);
          if (!strcmp(name, "returned-noaccess")) protect(second + 4096, PAGE_NOACCESS);
          if (!strcmp(name, "buffer-readonly-guard")) protect(first + 4096, PAGE_READONLY | PAGE_GUARD);
          if (!strcmp(name, "returned-readonly-guard")) protect(second + 4096, PAGE_READONLY | PAGE_GUARD);
          ULONG reset = 1;
          LONG reset_status = set(GetCurrentProcess(), 12, &reset, 4);
          ULONG before = raw_mode();
          LONG status = 0;
          DWORD exception = 0;
          __try {
            if (operation) status = set(role.handle, 12, buffer, length);
            else status = query(role.handle, 12, buffer, length, reinterpret_cast<ULONG *>(returned));
          } __except (EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); }
          ULONG after = raw_mode();
          DWORD bp = protection(first + 4096), rp = protection(second + 4096);
          DWORD bt = protection(first + 8192), rt = protection(second + 8192);
          for (unsigned i = 0; i < 3; ++i) { protect(first + i * 4096, PAGE_READWRITE); protect(second + i * 4096, PAGE_READWRITE); }
          printf("kind=case op=%s role=%s case=%s len=%lu status=%08lX exception=%08lX "
                 "reset=%08lX before=%08lX after=%08lX buffer-protect=%lX returned-protect=%lX "
                 "buffer-tail=%lX returned-tail=%lX buffer=", operation ? "set" : "query", role.name, name, length,
                 status, exception, reset_status, before, after, bp, rp, bt, rt);
          bytes(first + 4096 + 240, 64); printf(" returned="); bytes(second + 4096 + 240, 64);
          printf(" buffer-edge="); bytes(first + 8192 - 16, 32); printf(" returned-edge="); bytes(second + 8192 - 16, 32); printf("\n");
          ++calls; if (exception) ++exceptions; if (status == 0x103) ++pending;
        }
      }
    }
  }
  modes();
  LONG restored = set(GetCurrentProcess(), 12, &original, 4);
  ULONG final_mode = raw_mode();
  VirtualFree(first, 0, MEM_RELEASE); VirtualFree(second, 0, MEM_RELEASE);
  for (auto &role : roles) if (role.owned && role.handle && CloseHandle(role.handle)) ++closed;
  printf("summary calls=%u exceptions=%u pending=%u owned=%u closed=%u allocations=2 releases=2 "
         "restore-status=%08lX initial=%08lX final=%08lX\n", calls, exceptions, pending, owned, closed, restored, original, final_mode);
  return owned == closed && pending == 0 ? 0 : 9;
}
