#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

using QueryProcess = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
using Version = LONG(WINAPI *)(OSVERSIONINFOW *);

static bool read(HANDLE process, std::uintptr_t address, void *out, SIZE_T bytes) {
  SIZE_T done = 0;
  return ReadProcessMemory(process, reinterpret_cast<const void *>(address), out,
                           bytes, &done) && done == bytes;
}

static bool field(HANDLE process, const char *name, std::uintptr_t peb,
                  std::uintptr_t offset, unsigned pointer_bytes) {
  std::uintptr_t pointer = 0;
  const bool readable = peb && read(process, peb + offset, &pointer, pointer_bytes);
  MEMORY_BASIC_INFORMATION region{};
  const SIZE_T queried = pointer ? VirtualQueryEx(process,
      reinterpret_cast<const void *>(pointer), &region, sizeof(region)) : 0;
  unsigned char bytes[32]{};
  const bool payload = pointer && read(process, pointer, bytes, sizeof(bytes));
  std::printf("FIELD name=%s peb=%llX offset=%llX pointer-bytes=%u read=%u pointer=%llX relative=%llX query=%llu base=%llX allocation=%llX region-bytes=%llu state=%08lX protect=%08lX type=%08lX payload=%u hex=",
      name, static_cast<unsigned long long>(peb),
      static_cast<unsigned long long>(offset), pointer_bytes,
      static_cast<unsigned>(readable), static_cast<unsigned long long>(pointer),
      static_cast<unsigned long long>(pointer >= peb ? pointer - peb : UINTPTR_MAX),
      static_cast<unsigned long long>(queried),
      static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(region.BaseAddress)),
      static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(region.AllocationBase)),
      static_cast<unsigned long long>(region.RegionSize), region.State,
      region.Protect, region.Type, static_cast<unsigned>(payload));
  if (payload) for (unsigned char byte : bytes) std::printf("%02X", byte);
  std::putchar('\n');
  std::fflush(stdout);
  return readable && (!pointer || payload);
}

static bool snapshot(HANDLE process, QueryProcess query) {
  PROCESS_BASIC_INFORMATION basic{};
  ULONG returned = 0;
  const NTSTATUS native_status = query(process, ProcessBasicInformation, &basic,
      static_cast<ULONG>(sizeof(basic)), &returned);
  std::printf("PEB native-status=%08lX returned=%lu\n",
      static_cast<unsigned long>(native_status), returned);
  bool valid = native_status >= 0 && field(process, "native64",
      reinterpret_cast<std::uintptr_t>(basic.PebBaseAddress), 0x338, 8);
  std::uintptr_t compat = 0;
  returned = 0;
  const NTSTATUS compat_status = query(process, static_cast<PROCESSINFOCLASS>(26),
      &compat, static_cast<ULONG>(sizeof(compat)), &returned);
  std::printf("PEB compat-status=%08lX returned=%lu pointer=%llX\n",
      static_cast<unsigned long>(compat_status), returned,
      static_cast<unsigned long long>(compat));
  if (compat_status < 0) valid = false;
  if (compat && !field(process, "compat32", compat, 0x218, 4)) valid = false;
  return valid;
}

static bool child(const wchar_t *path, const char *name, QueryProcess query) {
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(path, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                      nullptr, nullptr, &startup, &info)) {
    std::printf("CREATE label=%s error=%lu\n", name, GetLastError());
    return false;
  }
  USHORT machine = 0, native = 0;
  const bool identified = IsWow64Process2(info.hProcess, &machine, &native) != FALSE;
  std::printf("CHILD label=%s pid=%lu tid=%lu identify=%u machine=%04X native=%04X\n",
      name, info.dwProcessId, info.dwThreadId, static_cast<unsigned>(identified),
      machine, native);
  bool valid = snapshot(info.hProcess, query) && identified;
  const DWORD suspended = ResumeThread(info.hThread);
  std::printf("RESUME label=%s previous=%lu\n", name, suspended);
  std::fflush(stdout);
  if (suspended != 1) valid = false;
  const DWORD waited = WaitForSingleObject(info.hProcess, INFINITE);
  DWORD code = STILL_ACTIVE;
  const bool exited = GetExitCodeProcess(info.hProcess, &code) != FALSE;
  const bool closed_thread = CloseHandle(info.hThread) != FALSE;
  const bool closed_process = CloseHandle(info.hProcess) != FALSE;
  std::printf("EXIT label=%s wait=%lu query=%u code=%lu thread-closed=%u process-closed=%u\n",
      name, waited, static_cast<unsigned>(exited), code,
      static_cast<unsigned>(closed_thread), static_cast<unsigned>(closed_process));
  std::fflush(stdout);
  return valid && waited == WAIT_OBJECT_0 && exited && code == 0 &&
         closed_thread && closed_process;
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 4) return 2;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto query = reinterpret_cast<QueryProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
  auto version = reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  if (!query || !version) return 3;
  OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  if (version(&os) < 0) return 4;
  std::printf("KERNEL major=%lu minor=%lu build=%lu pointer-bytes=%zu\n",
      os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, sizeof(void *));
  const char *names[] = {"arm64", "x64", "x86"};
  unsigned completed = 0;
  for (int index = 0; index < 3; ++index)
    if (child(argv[index + 1], names[index], query)) ++completed;
  std::printf("DONE completed=%u expected=3 debug-flags=0\n", completed);
  return completed == 3 ? 0 : 9;
}
