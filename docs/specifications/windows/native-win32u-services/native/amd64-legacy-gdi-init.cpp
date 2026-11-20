// Observe the first native NtGdiInit call in a fixed, owned findstr.exe child.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <windows.h>

namespace {
template <class T> bool read(HANDLE process, uintptr_t address, T &out) {
  SIZE_T got = 0;
  return ReadProcessMemory(process, reinterpret_cast<const void *>(address),
                           &out, sizeof(out), &got) && got == sizeof(out);
}

struct GuiState {
  uintptr_t gdi = 0;
  uintptr_t thread = 0;
  uintptr_t desktop = 0;
  uint32_t process = 0;

  bool capture(HANDLE child, uintptr_t teb) {
    uintptr_t peb = 0;
    return teb && read(child, teb + 0x60, peb) && peb &&
           read(child, peb + 0xf8, gdi) && read(child, peb + 0x108, process) &&
           read(child, teb + 0x78, thread) && read(child, teb + 0x828, desktop);
  }

  void report(const char *phase, unsigned sample) const {
    printf("sample=%u phase=%s gdi=%u thread=%u desktop=%u process=%u\n",
           sample, phase, unsigned(gdi != 0), unsigned(thread != 0),
           unsigned(desktop != 0), unsigned(process != 0));
  }
};

class Observer {
public:
  Observer(const PROCESS_INFORMATION &child, uintptr_t local_entry, uintptr_t rva,
           uintptr_t dispatcher, unsigned sample)
      : child(child), local_entry(local_entry), rva(rva), dispatcher(dispatcher),
        sample(sample) {}

  bool observe() {
    bool valid = true, exited = false;
    DWORD exit_code = ~0u;
    const ULONGLONG deadline = GetTickCount64() + 20000;
    while (!exited && valid && GetTickCount64() < deadline) {
      DEBUG_EVENT event{};
      if (!WaitForDebugEvent(&event, 500)) {
        valid = GetLastError() == ERROR_SEM_TIMEOUT;
        continue;
      }
      DWORD disposition = DBG_CONTINUE;
      switch (event.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT:
        teb = reinterpret_cast<uintptr_t>(event.u.CreateProcessInfo.lpThreadLocalBase);
        close_file(event.u.CreateProcessInfo.hFile);
        break;
      case LOAD_DLL_DEBUG_EVENT:
        valid = loaded(event.u.LoadDll);
        close_file(event.u.LoadDll.hFile);
        break;
      case EXCEPTION_DEBUG_EVENT:
        valid = exception(event, disposition);
        break;
      case EXIT_PROCESS_DEBUG_EVENT:
        exited = true;
        exit_code = event.u.ExitProcess.dwExitCode;
        break;
      }
      valid = ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition) && valid;
    }
    if (!exited)
      TerminateProcess(child.hProcess, 120);
    printf("sample=%u entry=%u return=%u callbacks=%u child_exited=%u exit=%lu\n",
           sample, unsigned(entered), unsigned(returned), callbacks, unsigned(exited), exit_code);
    return valid && entry && entered == returned && exited && exit_code == 1;
  }

  bool completed() const { return entered && returned; }

private:
  static void close_file(HANDLE file) {
    if (file && file != INVALID_HANDLE_VALUE)
      CloseHandle(file);
  }

  bool same_entry(uintptr_t local, uintptr_t remote) const {
    std::array<unsigned char, 24> bytes{};
    return read(child.hProcess, remote, bytes) &&
           std::memcmp(bytes.data(), reinterpret_cast<const void *>(local), bytes.size()) == 0;
  }

  bool loaded(const LOAD_DLL_DEBUG_INFO &module) {
    if (entry || !module.hFile)
      return true;
    wchar_t path[32768];
    const DWORD length = GetFinalPathNameByHandleW(module.hFile, path, _countof(path), 0);
    if (!length || length >= _countof(path))
      return true;
    const std::wstring name(path, length);
    const auto separator = name.find_last_of(L'\\');
    if (separator == std::wstring::npos ||
        _wcsicmp(name.c_str() + separator + 1, L"win32u.dll") != 0)
      return true;
    const auto address = reinterpret_cast<uintptr_t>(module.lpBaseOfDll) + rva;
    if (!same_entry(local_entry, address) || !same_entry(dispatcher, dispatcher))
      return false;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(child.hThread, &context))
      return false;
    entry = address;
    context.Dr0 = entry;
    context.Dr6 = 0;
    context.Dr7 = 1;
    return SetThreadContext(child.hThread, &context) != 0;
  }

  bool exception(const DEBUG_EVENT &event, DWORD &disposition) {
    const auto &record = event.u.Exception.ExceptionRecord;
    const auto site = reinterpret_cast<uintptr_t>(record.ExceptionAddress);
    if (record.ExceptionCode == EXCEPTION_BREAKPOINT)
      return true;
    if (record.ExceptionCode != EXCEPTION_SINGLE_STEP || !entry || returned ||
        event.dwThreadId != child.dwThreadId ||
        ((!entered || site != return_site) && site != entry && site != dispatcher)) {
      disposition = DBG_EXCEPTION_NOT_HANDLED;
      return true;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(child.hThread, &context) || context.Rip != site)
      return false;
    GuiState state;
    if (!entered && site == entry && (context.Dr6 & 1)) {
      if (!read(child.hProcess, context.Rsp, return_site) || !return_site ||
          !state.capture(child.hProcess, teb))
        return false;
      state.report("before", sample);
      entered = true;
      context.Dr0 = return_site;
      context.Dr1 = dispatcher;
      context.Dr7 = 5;
    } else if (entered && site == return_site && (context.Dr6 & 1)) {
      if (!state.capture(child.hProcess, teb))
        return false;
      state.report("after", sample);
      printf("sample=%u return_zero=%u return_one=%u\n", sample,
             unsigned(context.Rax == 0), unsigned(context.Rax == 1));
      returned = true;
      context.Dr7 = 0;
    } else if (entered && site == dispatcher && (context.Dr6 & 2)) {
      if (++callbacks > 64)
        return false;
    } else {
      return false;
    }
    context.Dr6 = 0;
    context.EFlags |= 0x10000;
    return SetThreadContext(child.hThread, &context) != 0;
  }

  PROCESS_INFORMATION child;
  uintptr_t local_entry;
  uintptr_t rva;
  uintptr_t dispatcher;
  unsigned sample;
  uintptr_t entry = 0;
  uintptr_t teb = 0;
  uintptr_t return_site = 0;
  unsigned callbacks = 0;
  bool entered = false;
  bool returned = false;
};
} // namespace

int wmain(int argc, wchar_t **argv) {
  if (argc != 2 || (wcscmp(argv[1], L"required") != 0 && wcscmp(argv[1], L"optional") != 0))
    return 2;
  const bool required = wcscmp(argv[1], L"required") == 0;
  wchar_t system[32768];
  const UINT length = GetSystemDirectoryW(system, _countof(system));
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto win32u = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!length || length >= _countof(system) || !ntdll || !win32u)
    return 2;
  const auto entry = reinterpret_cast<uintptr_t>(GetProcAddress(win32u, "NtGdiInit"));
  const auto dispatcher = reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, "KiUserCallbackDispatcher"));
  const auto image = std::wstring(system, length) + L"\\findstr.exe";
  if (!entry || !dispatcher)
    return 2;

  unsigned matches = 0;
  for (unsigned sample = 0; sample < 2; ++sample) {
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    const auto stream = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
    if (stream == INVALID_HANDLE_VALUE)
      return 3;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = startup.hStdOutput = startup.hStdError = stream;
    PROCESS_INFORMATION child{};
    auto command = L"\"" + image + L"\" /l /c:rax-witness";
    const BOOL created = CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, TRUE,
        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup, &child);
    CloseHandle(stream);
    if (!created)
      return 3;
    Observer observer(child, entry, entry - reinterpret_cast<uintptr_t>(win32u), dispatcher, sample);
    const bool valid = observer.observe();
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    if (!valid)
      return 4;
    matches += unsigned(observer.completed());
  }
  FreeLibrary(win32u);
  printf("complete samples=2 matches=%u\n", matches);
  return !required || matches == 2 ? 0 : 5;
}
