#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>

__declspec(thread) volatile ULONG native_tls_canary = 0x12345678;

static void fail(const char *operation) {
  printf("failure=%s error=%lu\n", operation, GetLastError());
  ExitProcess(21);
}

static void read_exact(HANDLE process, uintptr_t address, void *output,
                       SIZE_T size) {
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void *>(address), output,
                         size, &got) ||
      got != size)
    fail("read-child");
}

static void dump(HANDLE process, uintptr_t address, SIZE_T size,
                 const char *name) {
  std::vector<unsigned char> bytes(size);
  SIZE_T got = 0;
  BOOL ok = ReadProcessMemory(process, reinterpret_cast<void *>(address),
                              bytes.data(), size, &got);
  DWORD error = ok ? 0 : GetLastError();
  printf("dump name=%s address=%llX requested=%zu ok=%u error=%lu got=%zu hex=",
         name, static_cast<unsigned long long>(address), size, unsigned(ok),
         error, got);
  for (SIZE_T i = 0; i < got; ++i)
    printf("%02X", bytes[i]);
  puts("");
}

static void patch(HANDLE process, uintptr_t address,
                  const std::vector<unsigned char> &bytes) {
  DWORD old = 0, ignored = 0;
  SIZE_T written = 0;
  if (!VirtualProtectEx(process, reinterpret_cast<void *>(address),
                        bytes.size(), PAGE_EXECUTE_READWRITE, &old) ||
      !WriteProcessMemory(process, reinterpret_cast<void *>(address),
                          bytes.data(), bytes.size(), &written) ||
      written != bytes.size() ||
      !VirtualProtectEx(process, reinterpret_cast<void *>(address),
                        bytes.size(), old, &ignored) ||
      !FlushInstructionCache(process, reinterpret_cast<void *>(address),
                             bytes.size()))
    fail("patch-owned-child");
}

static uintptr_t argument(HANDLE process, const CONTEXT &context,
                          unsigned index) {
#if defined(_M_ARM64)
  if (index < 8)
    return context.X[index];
  uintptr_t value = 0;
  read_exact(process, context.Sp + (index - 8) * 8, &value, sizeof value);
  return value;
#elif defined(_M_X64)
  const uintptr_t args[] = {context.Rcx, context.Rdx, context.R8, context.R9};
  if (index < 4)
    return args[index];
  uintptr_t value = 0;
  read_exact(process, context.Rsp + 40 + (index - 4) * 8, &value, sizeof value);
  return value;
#else
  ULONG value = 0;
  read_exact(process, context.Esp + 4 * (index + 1), &value, 4);
  return value;
#endif
}

static uintptr_t caller(HANDLE process, const CONTEXT &context) {
#if defined(_M_ARM64)
  return context.Lr;
#elif defined(_M_X64)
  uintptr_t value = 0;
  read_exact(process, context.Rsp, &value, sizeof value);
  return value;
#else
  uintptr_t value = 0;
  read_exact(process, context.Esp, &value, sizeof value);
  return value;
#endif
}

static void set_pc(CONTEXT &context, uintptr_t address) {
#if defined(_M_ARM64)
  context.Pc = address;
#elif defined(_M_X64)
  context.Rip = address;
#else
  context.Eip = ULONG(address);
#endif
}

static ULONG status(const CONTEXT &context) {
#if defined(_M_ARM64)
  return ULONG(context.X0);
#elif defined(_M_X64)
  return ULONG(context.Rax);
#else
  return context.Eax;
#endif
}

#ifndef OBSERVE_SECURE_CONNECT
#define OBSERVE_SECURE_CONNECT 0
#endif
static constexpr bool secure = OBSERVE_SECURE_CONNECT != 0;
static constexpr unsigned argument_count = secure ? 9 : 8;
static constexpr unsigned server_index = secure ? 5 : 4;
static constexpr unsigned maximum_index = secure ? 6 : 5;
static constexpr unsigned information_index = secure ? 7 : 6;
static constexpr unsigned length_index = secure ? 8 : 7;

int main(int argc, char **) {
  if (argc > 1)
    return native_tls_canary == 0x12345678 ? 41 : 42;
  setvbuf(stdout, nullptr, _IONBF, 0);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  uintptr_t entry = uintptr_t(GetProcAddress(ntdll, secure ? "NtSecureConnectPort" : "NtConnectPort"));
  if (!entry)
    fail("exports");
  SIZE_T instruction = 1;
  std::vector<unsigned char> trap{0xCC};
#if defined(_M_ARM64)
  instruction = 4;
  auto breakpoint = GetProcAddress(ntdll, "DbgBreakPoint");
  if (!breakpoint)
    fail("native-breakpoint-export");
  ULONG brk = 0;
  memcpy(&brk, breakpoint, 4);
  if ((brk & 0xFFE0001F) != 0xD4200000)
    fail("native-breakpoint-instruction");
  printf("native-breakpoint instruction=%08lX\n", brk);
  trap.resize(4);
  memcpy(trap.data(), &brk, 4);
#endif
  std::vector<unsigned char> original(instruction),
      return_original(instruction);
  memcpy(original.data(), reinterpret_cast<void *>(entry), instruction);
  wchar_t executable[32768];
  if (!GetModuleFileNameW(nullptr, executable, 32768))
    fail("executable-path");
  std::wstring command = L"\"" + std::wstring(executable) + L"\" --child";
  STARTUPINFOW startup{};
  startup.cb = sizeof startup;
  PROCESS_INFORMATION child{};
  if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
                      DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &startup,
                      &child))
    fail("create-owned-child");
  printf("profile width=%zu child=%lu entry=%llX rva=%llX\n", sizeof(void *),
         child.dwProcessId, static_cast<unsigned long long>(entry),
         static_cast<unsigned long long>(entry - uintptr_t(ntdll)));
  printf("protocol export=%s arguments=%u\n", secure ? "NtSecureConnectPort" : "NtConnectPort", argument_count);
  bool installed = false, waiting_return = false, exited = false;
  ULONG calls = 0, captured = 0, exit_code = 0;
  uintptr_t resume = 0;
  uintptr_t args[9]{};
  ULONG connection_capacity = 0;
  ULONG view_lengths[2]{};

  ULONGLONG deadline = GetTickCount64() + 120000;
  while (!exited && GetTickCount64() < deadline) {
    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, 1000)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT)
        continue;
      fail("debug-event");
    }
    DWORD disposition = DBG_CONTINUE;
    if (!installed && (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT ||
                       event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)) {
      unsigned char bytes[32]{};
      SIZE_T got = 0;
      if (ReadProcessMemory(child.hProcess, reinterpret_cast<void *>(entry),
                            bytes, 32, &got) &&
          got == 32 &&
          memcmp(bytes, reinterpret_cast<void *>(entry), 32) == 0) {
        patch(child.hProcess, entry, trap);
        installed = true;
      }
    }
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
        event.u.CreateProcessInfo.hFile)
      CloseHandle(event.u.CreateProcessInfo.hFile);
    else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
             event.u.LoadDll.hFile)
      CloseHandle(event.u.LoadDll.hFile);
    else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      ULONG exception = event.u.Exception.ExceptionRecord.ExceptionCode;
      uintptr_t address =
          uintptr_t(event.u.Exception.ExceptionRecord.ExceptionAddress);
      bool breakpoint =
          exception == EXCEPTION_BREAKPOINT || exception == 0x4000001F;
      if (breakpoint && installed && address == entry && !waiting_return) {
        if (event.dwThreadId != child.dwThreadId)
          fail("unexpected-call-thread");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(child.hThread, &context))
          fail("entry-context");
        for (unsigned i = 0; i < argument_count; ++i)
          args[i] = argument(child.hProcess, context, i);
        resume = caller(child.hProcess, context);
        printf("entry ordinal=%lu caller=%llX args=", calls,
               static_cast<unsigned long long>(resume));
        for (unsigned index = 0; index < argument_count; ++index)
          printf("%llX,", static_cast<unsigned long long>(args[index]));
        puts("");
        if (args[0])
          dump(child.hProcess, args[0], sizeof(void *), "handle-before");
        if (args[1]) {
          unsigned char name[16]{};
          read_exact(child.hProcess, args[1], name,
                     sizeof(void *) == 8 ? 16 : 8);
          USHORT length = 0, maximum = 0;
          uintptr_t text = 0;
          memcpy(&length, name, 2);
          memcpy(&maximum, name + 2, 2);
          memcpy(&text, name + (sizeof(void *) == 8 ? 8 : 4), sizeof text);
          if (length > maximum || (length & 1) || length > 512)
            fail("bounded-port-name");
          dump(child.hProcess, args[1], sizeof(void *) == 8 ? 16 : 8,
               "port-name-header");
          if (length)
            dump(child.hProcess, text, length, "port-name-utf16");
        }
        if (args[2])
          dump(child.hProcess, args[2], 12, "security-qos");
        for (unsigned i : {3u, server_index}) {
          if (args[i]) {
            ULONG length = 0;
            read_exact(child.hProcess, args[i], &length, 4);
            if (length > 64)
              fail("bounded-view-length");
            view_lengths[i == 3 ? 0 : 1] = length;
            dump(child.hProcess, args[i], length,
                 i == 3 ? "client-view-before" : "server-view-before");
          }
        }
        if constexpr (secure) {
          if (args[4]) {
            unsigned char header[8]{};
            read_exact(child.hProcess, args[4], header, 8);
            if (header[1] > 15)
              fail("bounded-sid");
            dump(child.hProcess, args[4], 8 + header[1] * 4,
                 "required-server-sid");
          }
        }
        if (args[maximum_index])
          dump(child.hProcess, args[maximum_index], 4, "max-message-before");
        connection_capacity = 0;
        if (args[length_index]) {
          read_exact(child.hProcess, args[length_index], &connection_capacity, 4);
          if (connection_capacity > 4096)
            fail("bounded-connection-capacity");
          dump(child.hProcess, args[length_index], 4, "connection-length-before");
        }
        if (args[information_index] && connection_capacity)
          dump(child.hProcess, args[information_index], connection_capacity,
               "connection-before");
        dump(child.hProcess, resume, 512, "caller-code");
        read_exact(child.hProcess, resume, return_original.data(), instruction);
        patch(child.hProcess, entry, original);
        patch(child.hProcess, resume, trap);
        set_pc(context, entry);
        if (!SetThreadContext(child.hThread, &context))
          fail("resume-entry-context");
        waiting_return = true;
      } else if (breakpoint && waiting_return && address == resume) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(child.hThread, &context))
          fail("return-context");
        printf("return ordinal=%lu status=%08lX\n", calls, status(context));
        if (args[0])
          dump(child.hProcess, args[0], sizeof(void *), "handle-after");
        for (unsigned i : {3u, server_index}) {
          if (args[i])
            dump(child.hProcess, args[i], view_lengths[i == 3 ? 0 : 1],
                 i == 3 ? "client-view-after" : "server-view-after");
        }
        if (args[maximum_index])
          dump(child.hProcess, args[maximum_index], 4, "max-message-after");
        if (args[length_index]) {
          ULONG length = 0;
          read_exact(child.hProcess, args[length_index], &length, 4);
          dump(child.hProcess, args[length_index], 4, "connection-length-after");
          if (args[information_index] && length)
            dump(child.hProcess, args[information_index], std::min(length, connection_capacity),
                 "connection-after");
        }
        ++captured;
        patch(child.hProcess, resume, return_original);
        if (captured < 16)
          patch(child.hProcess, entry, trap);
        set_pc(context, resume);
        if (!SetThreadContext(child.hThread, &context))
          fail("resume-return-context");
        waiting_return = false;
        ++calls;
      } else if (!breakpoint) {
        printf("exception code=%08lX address=%llX first=%lu\n", exception,
               static_cast<unsigned long long>(address),
               event.u.Exception.dwFirstChance);
        disposition = DBG_EXCEPTION_NOT_HANDLED;
      }
    } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      exit_code = event.u.ExitProcess.dwExitCode;
      exited = true;
    }
    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition))
      fail("continue-debug-event");
  }
  if (!exited) {
    TerminateProcess(child.hProcess, 78);
    fail("capture-deadline");
  }
  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  printf("complete captured=%lu calls=%lu exit=%lu\n", captured, calls,
         exit_code);
  return installed && captured < 16 && captured == calls && exit_code == 41
             ? 0
             : 22;
}
