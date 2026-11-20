// Observe USER initialization from owned native clients.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <windows.h>

template <class T> bool read(HANDLE child, uintptr_t address, T &out) {
  SIZE_T got = 0;
  return ReadProcessMemory(child, reinterpret_cast<const void *>(address),
                           &out, sizeof(out), &got) && got == sizeof(out);
}

template <class T> T field(const unsigned char *bytes, size_t offset) {
  T value{};
  std::memcpy(&value, bytes + offset, sizeof(value));
  return value;
}

static bool report(HANDLE child, const CONTEXT &context, const char *mode,
                   unsigned sample, bool alpc) {
  const auto address = alpc ? context.R8 : context.Rdx;
  std::array<unsigned char, 88> message{};
  uint32_t lengths = 0;
  if (!address || !read(child, address, lengths))
    return false;
  printf("mode=%s sample=%u transport=%s data_bytes=%u message_bytes=%u\n",
         mode, sample, alpc ? "ALPC" : "LPC", unsigned(lengths & 0xffff),
         unsigned(lengths >> 16));
  if (lengths != 0x00580030 || !read(child, address, message))
    return false;
  if (field<uint32_t>(message.data(), 48) != 0 ||
      field<uint64_t>(message.data(), 64) != 3)
    return false;
  const auto information = field<uint64_t>(message.data(), 80);
  if (information != 576 && information != 584)
    return false;
  uintptr_t capacity_address = 0;
  uint64_t capacity = 0;
  if (alpc && (!read(child, context.Rsp + 48, capacity_address) ||
               !read(child, capacity_address, capacity)))
    return false;
  printf("mode=%s sample=%u transport=%s information_bytes=%llu receive_capacity=%llu "
         "status_zero=%u reserved_zero=%u\n",
         mode, sample, alpc ? "ALPC" : "LPC", static_cast<unsigned long long>(information),
         static_cast<unsigned long long>(capacity),
         unsigned(field<uint32_t>(message.data(), 52) == 0),
         unsigned(field<uint64_t>(message.data(), 56) == 0));
  return true;
}

static bool observe(const std::wstring &image, const std::wstring &arguments,
                    const std::array<uintptr_t, 2> &services, const char *mode,
                    unsigned sample, DWORD expected, bool require_match) {
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  HANDLE stream = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);
  if (stream == INVALID_HANDLE_VALUE)
    return false;
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = startup.hStdOutput = startup.hStdError = stream;
  PROCESS_INFORMATION child{};
  std::wstring command = L"\"" + image + L"\" " + arguments;
  const BOOL created = CreateProcessW(image.c_str(), command.data(), nullptr, nullptr,
      TRUE, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup, &child);
  CloseHandle(stream);
  if (!created)
    return false;
  bool armed = false, found = false, exited = false, valid = true;
  unsigned calls = 0;
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
    case LOAD_DLL_DEBUG_EVENT: {
      const HANDLE image_file = event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT
          ? event.u.CreateProcessInfo.hFile : event.u.LoadDll.hFile;
      if (image_file)
        CloseHandle(image_file);
      auto ready = [&](uintptr_t service) {
        std::array<unsigned char, 24> remote{};
        return read(child.hProcess, service, remote) &&
               std::memcmp(remote.data(), reinterpret_cast<const void *>(service),
                           remote.size()) == 0;
      };
      if (!armed && !found && ready(services[0]) && ready(services[1])) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        valid = GetThreadContext(child.hThread, &context) != 0;
        if (valid) {
          context.Dr0 = services[0];
          context.Dr1 = services[1];
          context.Dr6 = 0;
          context.Dr7 = 5;
          valid = SetThreadContext(child.hThread, &context) != 0;
          armed = valid;
        }
      }
      break;
    }
    case EXCEPTION_DEBUG_EVENT: {
      const auto &exception = event.u.Exception.ExceptionRecord;
      const auto site = uintptr_t(exception.ExceptionAddress);
      if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP && armed &&
          event.dwThreadId == child.dwThreadId &&
          (site == services[0] || site == services[1])) {
        const bool alpc = site == services[0];
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
        valid = ++calls <= 64 && GetThreadContext(child.hThread, &context) &&
                (context.Dr6 & (alpc ? 1 : 2)) != 0 && context.Rip == site;
        if (valid) {
          found = report(child.hProcess, context, mode, sample, alpc);
          context.Dr6 = 0;
          context.EFlags |= 0x10000; // Resume past the instruction breakpoint.
          if (found) {
            context.Dr7 = 0;
            armed = false;
          }
          valid = SetThreadContext(child.hThread, &context) != 0;
        }
      } else if (exception.ExceptionCode != EXCEPTION_BREAKPOINT) {
        disposition = DBG_EXCEPTION_NOT_HANDLED;
      }
      break;
    }
    case EXIT_PROCESS_DEBUG_EVENT:
      exited = true;
      exit_code = event.u.ExitProcess.dwExitCode;
      break;
    }
    valid = ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition) && valid;
  }
  if (!exited)
    TerminateProcess(child.hProcess, 120);
  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  printf("mode=%s sample=%u observed=%u child_exited=%u exit=%lu calls=%u\n",
         mode, sample, unsigned(found), unsigned(exited), exit_code, calls);
  return valid && (!require_match || found) && calls != 0 && exited && exit_code == expected;
}

static int fixed_user(ULONG bytes) {
  using Connect = LONG(NTAPI *)(PCWSTR, ULONG, void *, ULONG, BOOLEAN *);
  const auto connect = reinterpret_cast<Connect>(reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrClientConnectToServer")));
  DWORD session = 0;
  if (!connect || !ProcessIdToSessionId(GetCurrentProcessId(), &session))
    return 2;
  const auto directory = session ? L"\\Sessions\\" + std::to_wstring(session) + L"\\Windows"
                                 : std::wstring(L"\\Windows");
  std::array<uint64_t, 128> information{};
  constexpr uint64_t guard = 0xa5a5a5a5a5a5a5a5;
  for (size_t i = bytes / 8; i < information.size(); ++i)
    information[i] = guard;
  BOOLEAN inside = 0xa5;
  const auto status = connect(directory.c_str(), 3, information.data(), bytes, &inside);
  for (size_t i = bytes / 8; i < information.size(); ++i)
    if (information[i] != guard)
      return 3;
  return status == 0 && inside == 0 ? 0 : 4;
}

int wmain(int argc, wchar_t **argv) {
  if (argc < 2)
    return 2;
  const std::wstring bytes(argv[1]);
  if (bytes != L"576" && bytes != L"584")
    return 2;
  if (argc == 3 && std::wstring(argv[2]) == L"--fixed-user")
    return fixed_user(bytes == L"576" ? 576 : 584);
  wchar_t system[32768];
  wchar_t self[32768];
  const UINT length = GetSystemDirectoryW(system, _countof(system));
  const DWORD self_length = GetModuleFileNameW(nullptr, self, _countof(self));
  const auto library = GetModuleHandleW(L"ntdll.dll");
  const std::array<uintptr_t, 2> services{
      reinterpret_cast<uintptr_t>(GetProcAddress(library, "NtAlpcSendWaitReceivePort")),
      reinterpret_cast<uintptr_t>(GetProcAddress(library, "NtRequestWaitReplyPort")),
  };
  if (!length || length >= _countof(system) || !self_length ||
      self_length >= _countof(self) || !services[0] || !services[1])
    return 2;
  const std::wstring image = std::wstring(system, length) + L"\\findstr.exe";
  for (unsigned sample = 0; sample < 2; ++sample) {
    if (!observe(image, L"/l /c:rax-witness", services, "findstr", sample, 1,
                 bytes == L"584") ||
        !observe(std::wstring(self, self_length), bytes + L" --fixed-user",
                 services, "fixed", sample, 0, true))
      return 3;
  }
  return 0;
}
