#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

using Capture = void(WINAPI *)(CONTEXT *);
using Version = LONG(WINAPI *)(OSVERSIONINFOW *);
using QueryThread = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);

static void dump(const char *label, const CONTEXT &c) {
  std::printf("CONTEXT label=%s flags=%08lX cs=%04X ss=%04X ds=%04X es=%04X fs=%04X gs=%04X mxcsr=%08lX rip=%llX rsp=%llX\n",
      label, c.ContextFlags, c.SegCs, c.SegSs, c.SegDs, c.SegEs,
      c.SegFs, c.SegGs, c.MxCsr, static_cast<unsigned long long>(c.Rip),
      static_cast<unsigned long long>(c.Rsp));
}

static void descriptor(QueryThread query, HANDLE thread, const char *phase, ULONG selector) {
  struct Descriptor {
    ULONG selector;
    unsigned char bytes[8];
  } value{};
  static_assert(sizeof(value) == 12);
  value.selector = selector;
  std::memset(value.bytes, 0xa5, sizeof(value.bytes));
  ULONG returned = 0;
  LONG status = query(thread, 6, &value, sizeof(value), &returned);
  std::printf("DESCRIPTOR phase=%s selector=%04lX status=%08lX returned=%lu hex=",
      phase, selector, ULONG(status), returned);
  for (unsigned char b : value.bytes) std::printf("%02X", unsigned(b));
  std::putchar('\n');
}

extern "C" void read_selectors(unsigned short *);
extern "C" unsigned long long read_fsbase();
extern "C" unsigned long long read_gsbase();
extern "C" void read_descriptor(unsigned long, void *);
static void live_segments() {
  unsigned short selectors[6]{};
  read_selectors(selectors);
  std::printf("LIVE cs=%04X ss=%04X ds=%04X es=%04X fs=%04X gs=%04X\n", selectors[0], selectors[1], selectors[2], selectors[3], selectors[4], selectors[5]);
  __try { std::printf("FSBASE value=%llX\n", read_fsbase()); }
  __except(EXCEPTION_EXECUTE_HANDLER) { std::printf("FSBASE exception=%08lX\n", GetExceptionCode()); }
  __try { std::printf("GSBASE value=%llX\n", read_gsbase()); }
  __except(EXCEPTION_EXECUTE_HANDLER) { std::printf("GSBASE exception=%08lX\n", GetExceptionCode()); }
  for (unsigned long selector : {0x33ul, 0x2bul, 0x53ul, 0ul}) {
    struct Value { unsigned long access, limit; unsigned char lar_ok, lsl_ok; unsigned char padding[2]; } value{};
    static_assert(sizeof(value) == 12);
    __try {
      read_descriptor(selector, &value);
      std::printf("LARLSL selector=%04lX lar-ok=%u access=%08lX lsl-ok=%u limit=%08lX\n", selector, unsigned(value.lar_ok), value.access, unsigned(value.lsl_ok), value.limit);
    } __except(EXCEPTION_EXECUTE_HANDLER) { std::printf("LARLSL selector=%04lX exception=%08lX\n", selector, GetExceptionCode()); }
  }
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 2) return 2;
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto capture = reinterpret_cast<Capture>(GetProcAddress(ntdll, "RtlCaptureContext"));
  auto version = reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  auto query = reinterpret_cast<QueryThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
  if (!capture || !version || !query) return 3;
  OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  USHORT process_machine = 0, native_machine = 0;
  if (version(&os) < 0 || !IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)) return 4;
  std::printf("KERNEL major=%lu minor=%lu build=%lu pointer-bytes=%zu process-machine=%04X native-machine=%04X\n",
      os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, sizeof(void *),
      process_machine, native_machine);
  CONTEXT current{};
  capture(&current);
  dump("current-after-CRT", current);
  live_segments();
  const ULONG selectors[] = {0x33, 0x2b, 0x53, 0};
  for (ULONG selector : selectors)
    descriptor(query, reinterpret_cast<HANDLE>(std::intptr_t(-2)), "current", selector);
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION child{};
  if (!CreateProcessW(argv[1], nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                       nullptr, nullptr, &startup, &child)) {
    std::printf("CREATE failed=%lu\n", GetLastError());
    return 5;
  }
  CONTEXT initial{};
  initial.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
  BOOL got = GetThreadContext(child.hThread, &initial);
  DWORD error = got ? 0 : GetLastError();
  std::printf("GET initial=%u error=%lu pid=%lu tid=%lu\n", unsigned(got), error,
      child.dwProcessId, child.dwThreadId);
  if (got) dump("child-before-user-entry", initial);
  for (ULONG selector : selectors)
    descriptor(query, child.hThread, "child-before-user-entry", selector);
  DWORD previous = ResumeThread(child.hThread);
  std::printf("RESUME previous=%lu\n", previous);
  DWORD waited = WaitForSingleObject(child.hProcess, INFINITE);
  DWORD code = STILL_ACTIVE;
  BOOL exited = GetExitCodeProcess(child.hProcess, &code);
  BOOL closed_thread = CloseHandle(child.hThread);
  BOOL closed_process = CloseHandle(child.hProcess);
  std::printf("DONE wait=%lu queried=%u exit=%lu thread-closed=%u process-closed=%u debugger=0\n",
      waited, unsigned(exited), code, unsigned(closed_thread), unsigned(closed_process));
  return got && previous == 1 && waited == WAIT_OBJECT_0 && exited && code == 0 &&
      closed_thread && closed_process ? 0 : 21;
}
