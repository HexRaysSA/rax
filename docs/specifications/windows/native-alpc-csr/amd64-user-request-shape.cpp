// Observe the USER client request sent by an owned native findstr child.
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

static bool report(HANDLE child, const CONTEXT &context, unsigned sample) {
  std::array<unsigned char, 88> message{};
  uint32_t lengths = 0;
  if (!context.R8 || !read(child, context.R8, lengths) || lengths != 0x00580030 ||
      !read(child, context.R8, message))
    return false;
  if (field<uint32_t>(message.data(), 48) != 0 ||
      field<uint64_t>(message.data(), 64) != 3)
    return false;
  const auto information = field<uint64_t>(message.data(), 80);
  if (information != 576 && information != 584)
    return false;
  uintptr_t capacity_address = 0;
  uint64_t capacity = 0;
  if (!read(child, context.Rsp + 48, capacity_address) ||
      !read(child, capacity_address, capacity))
    return false;
  printf("sample=%u information_bytes=%llu receive_capacity=%llu "
         "status_zero=%u reserved_zero=%u\n",
         sample, static_cast<unsigned long long>(information),
         static_cast<unsigned long long>(capacity),
         unsigned(field<uint32_t>(message.data(), 52) == 0),
         unsigned(field<uint64_t>(message.data(), 56) == 0));
  return true;
}

static bool observe(const std::wstring &image, uintptr_t service, unsigned sample) {
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
  std::wstring command = L"\"" + image + L"\" /l /c:rax-witness";
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
      std::array<unsigned char, 24> remote{};
      if (!armed && !found && read(child.hProcess, service, remote) &&
          std::memcmp(remote.data(), reinterpret_cast<const void *>(service), remote.size()) == 0) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        valid = GetThreadContext(child.hThread, &context) != 0;
        if (valid) {
          context.Dr0 = service;
          context.Dr6 = 0;
          context.Dr7 = 1;
          valid = SetThreadContext(child.hThread, &context) != 0;
          armed = valid;
        }
      }
      break;
    }
    case EXCEPTION_DEBUG_EVENT: {
      const auto &exception = event.u.Exception.ExceptionRecord;
      if (exception.ExceptionCode == EXCEPTION_SINGLE_STEP && armed &&
          event.dwThreadId == child.dwThreadId &&
          uintptr_t(exception.ExceptionAddress) == service) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
        valid = ++calls <= 64 && GetThreadContext(child.hThread, &context) &&
                (context.Dr6 & 1) != 0 && context.Rip == service;
        if (valid) {
          found = report(child.hProcess, context, sample);
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
  printf("sample=%u observed=%u child_exited=%u exit=%lu calls=%u\n",
         sample, unsigned(found), unsigned(exited), exit_code, calls);
  return valid && found && exited && exit_code == 1;
}

int main() {
  wchar_t system[32768];
  const UINT length = GetSystemDirectoryW(system, _countof(system));
  const auto service = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlpcSendWaitReceivePort"));
  if (!length || length >= _countof(system) || !service)
    return 2;
  const std::wstring image = std::wstring(system, length) + L"\\findstr.exe";
  return observe(image, service, 0) && observe(image, service, 1) ? 0 : 3;
}
