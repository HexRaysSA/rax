#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

using Duplicate = LONG(NTAPI *)(HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG);
using Version = LONG(WINAPI *)(OSVERSIONINFOW *);
using Query = LONG(NTAPI *)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
static ULONG granted(Query query, HANDLE h) {
  PUBLIC_OBJECT_BASIC_INFORMATION info{};
  return query && query(h, ObjectBasicInformation, &info, sizeof(info), nullptr) >= 0
      ? info.GrantedAccess : 0xfffffffful;
}
static HANDLE pseudo(std::intptr_t n) { return reinterpret_cast<HANDLE>(n); }
static unsigned long long word(HANDLE value) {
  return static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value));
}
static LONG invoke(Duplicate duplicate, HANDLE process, HANDLE source, HANDLE target,
                   HANDLE *output, ULONG options, DWORD *exception) {
  __try { return duplicate(process, source, target, output, 0x4a, 0, options); }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    *exception = GetExceptionCode();
    return LONG(0xc0000001ul);
  }
}
static bool close_owned(HANDLE handle) {
  DWORD flags = 0;
  if (!GetHandleInformation(handle, &flags)) return false;
  if ((flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) &&
      !SetHandleInformation(handle, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0)) return false;
  return CloseHandle(handle) != FALSE;
}

static int leaf(unsigned index) {
  const unsigned scenario = index / 8;
  const unsigned mode = index % 8;
  if (scenario >= 6) return 2;
  const char *modes[] = {"valid", "null", "one", "unaligned", "readonly", "noaccess", "cross", "overflow"};
  auto duplicate = reinterpret_cast<Duplicate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject"));
  auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
  if (!duplicate || !query) return 3;
  DWORD original = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &original)) return 4;
  HANDLE source_process = pseudo(-1), source = pseudo(-2), target_process = pseudo(-1);
  HANDLE real_source = nullptr;
  ULONG options = 0;
  if (scenario == 1) source = reinterpret_cast<HANDLE>(std::uintptr_t(0x40000000));
  if (scenario == 2) source_process = nullptr;
  if (scenario == 3) target_process = nullptr;
  if (scenario >= 4) {
    LONG status = duplicate(pseudo(-1), pseudo(-2), pseudo(-1), &real_source, 0, 0, DUPLICATE_SAME_ACCESS);
    if (status < 0 || !real_source) return 5;
    source = real_source;
    options = DUPLICATE_CLOSE_SOURCE;
    if (scenario == 5 && !SetHandleInformation(source, HANDLE_FLAG_PROTECT_FROM_CLOSE,
                                               HANDLE_FLAG_PROTECT_FROM_CLOSE)) return 6;
  }
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  const std::size_t page = info.dwPageSize;
  auto memory = static_cast<unsigned char *>(VirtualAlloc(nullptr, 2 * page,
      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!memory) return 7;
  std::memset(memory, 0xa5, 2 * page);
  unsigned char *address = memory + 128;
  DWORD old = 0;
  if (mode == 1) address = nullptr;
  if (mode == 2) address = reinterpret_cast<unsigned char *>(std::uintptr_t(1));
  if (mode == 3) ++address;
  if (mode == 4 && !VirtualProtect(memory, page, PAGE_READONLY, &old)) return 8;
  if (mode == 5 && !VirtualProtect(memory, page, PAGE_NOACCESS, &old)) return 9;
  if (mode == 6) {
    address = memory + page - sizeof(HANDLE) / 2;
    if (!VirtualProtect(memory + page, page, PAGE_NOACCESS, &old)) return 10;
  }
  if (mode == 7) address = reinterpret_cast<unsigned char *>(~std::uintptr_t(0));
  const ULONG source_grant_before = granted(query, source);
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 13;
  DWORD exception = 0;
  LONG status = invoke(duplicate, source_process, source, target_process,
                      reinterpret_cast<HANDLE *>(address), options, &exception);
  if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 14;
  DWORD source_flags = 0;
  SetLastError(0);
  BOOL source_exists = GetHandleInformation(source, &source_flags);
  DWORD source_error = GetLastError();
  const ULONG source_grant_after = granted(query, source);
  MEMORY_BASIC_INFORMATION first{}, second{};
  VirtualQuery(memory, &first, sizeof(first));
  VirtualQuery(memory + page, &second, sizeof(second));
  if (!VirtualProtect(memory, 2 * page, PAGE_READWRITE, &old)) return 11;
  const bool readable = mode == 0 || mode == 3 || mode == 4 || mode == 5 || mode == 6;
  HANDLE output = nullptr;
  if (readable) std::memcpy(&output, address, sizeof(output));
  const ULONG output_grant = readable && status >= 0 && exception == 0 && output
      ? granted(query, output) : 0xfffffffful;
  std::printf("LEAF index=%u scenario=%u mode=%s pointer-bytes=%zu status=%08lX returned=%u exception=%08lX before=%lu after=%lu original=%lu source=%llX source-exists=%u source-flags=%lu source-error=%lu source-grant-before=%08lX source-grant-after=%08lX readable=%u output=%llX output-grant=%08lX first-protect=%08lX second-protect=%08lX bytes=",
      index, scenario, modes[mode], sizeof(void *), ULONG(status), unsigned(exception == 0),
      exception, before, after, original, word(source), unsigned(source_exists), source_flags,
      source_error, source_grant_before, source_grant_after, unsigned(readable), word(output),
      output_grant, first.Protect, second.Protect);
  if (readable) {
    for (std::size_t n = 0; n != sizeof(HANDLE); ++n) std::printf("%02X", unsigned(address[n]));
  }
  std::putchar('\n');
  bool output_closed = false, source_closed = false;
  // A failed/null/partial publication can leave a kernel-owned handle with no
  // known value. Each leaf is a fresh process; natural exit releases that set.
  if (exception == 0 && status >= 0 && readable && output && output != pseudo(-1) && output != pseudo(-2))
    output_closed = close_owned(output);
  if (real_source) {
    DWORD flags = 0;
    if (GetHandleInformation(real_source, &flags)) source_closed = close_owned(real_source);
  }
  if (!VirtualFree(memory, 0, MEM_RELEASE)) return 12;
  DWORD final = 0;
  GetProcessHandleCount(GetCurrentProcess(), &final);
  std::printf("LEAF-DONE index=%u output-closed=%u source-closed=%u final=%lu residual=%lld natural-exit=1\n",
      index, unsigned(output_closed), unsigned(source_closed), final,
      static_cast<long long>(final) - static_cast<long long>(original));
  return 0;
}

int wmain(int argc, wchar_t **argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  if (argc == 3 && std::wcscmp(argv[1], L"--leaf") == 0) {
    wchar_t *end = nullptr;
    unsigned long value = std::wcstoul(argv[2], &end, 10);
    if (!end || *end != 0 || value >= 48) return 2;
    return leaf(unsigned(value));
  }
  if (argc == 2 && std::wcscmp(argv[1], L"--warmup") == 0) return 0;
  if (argc != 1) return 2;
  auto version = reinterpret_cast<Version>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
  OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  USHORT process_machine = 0, native_machine = 0;
  if (!version || version(&os) < 0 || !IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)) return 3;
  std::printf("KERNEL major=%lu minor=%lu build=%lu pointer-bytes=%zu process-machine=%04X native-machine=%04X\n",
      os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, sizeof(void *), process_machine, native_machine);
  if (os.dwMajorVersion != 10 || os.dwMinorVersion != 0 || os.dwBuildNumber != 29704 || native_machine != 0xaa64) return 4;
  wchar_t executable[32768];
  DWORD length = GetModuleFileNameW(nullptr, executable, DWORD(sizeof(executable) / sizeof(executable[0])));
  if (!length || length >= sizeof(executable) / sizeof(executable[0])) return 5;
  auto launch = [&](unsigned index, bool warmup) {
    std::wstring command = L"\"" + std::wstring(executable) + L"\"";
    command += warmup ? L" --warmup" : L" --leaf " + std::to_wstring(index);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child{};
    DWORD before = 0, final = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return false;
    if (!CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &child)) {
      std::printf("%s index=%u create-error=%lu\n", warmup ? "WARMUP" : "CHILD", index, GetLastError());
      return false;
    }
    DWORD waited = WaitForSingleObject(child.hProcess, INFINITE), code = STILL_ACTIVE;
    BOOL queried = GetExitCodeProcess(child.hProcess, &code);
    BOOL thread_closed = CloseHandle(child.hThread), process_closed = CloseHandle(child.hProcess);
    BOOL counted = GetProcessHandleCount(GetCurrentProcess(), &final);
    std::printf("%s index=%u wait=%lu queried=%u exit=%lu thread-closed=%u process-closed=%u counted=%u before=%lu final=%lu\n",
        warmup ? "WARMUP" : "CHILD", index, waited, unsigned(queried), code,
        unsigned(thread_closed), unsigned(process_closed), unsigned(counted), before, final);
    return waited == WAIT_OBJECT_0 && queried && code == 0 && thread_closed && process_closed && counted;
  };
  unsigned warmup_failed = 0;
  for (unsigned i = 0; i != 24; ++i) if (!launch(i, true)) ++warmup_failed;
  DWORD before = 0, final = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 22;
  unsigned finished = 0, failed = 0;
  for (unsigned i = 0; i != 48; ++i) {
    if (launch(i, false)) ++finished;
    else ++failed;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &final)) return 23;
  std::printf("DONE children=%u failed=%u warmup-failed=%u before=%lu final=%lu\n",
      finished, failed, warmup_failed, before, final);
  return finished == 48 && failed == 0 && warmup_failed == 0 && final == before ? 0 : 21;
}
