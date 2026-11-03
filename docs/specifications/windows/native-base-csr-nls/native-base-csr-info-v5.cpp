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
using ThreadQuery = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);

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

struct Hook {
  const char *name;
  uintptr_t address;
  unsigned count;
  std::vector<unsigned char> original;
};

static SIZE_T message(HANDLE process, uintptr_t address, const char *name) {
  if (!address)
    return 0;
  USHORT length = 0;
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void *>(address + 2),
                         &length, sizeof length, &got) ||
      got != sizeof length) {
    dump(process, address, 40, name);
    return 0;
  }
  SIZE_T bytes = std::clamp<SIZE_T>(length, 40, 4096);
  dump(process, address, bytes, name);
  return bytes;
}

static int client_probe() {
  wchar_t name[LOCALE_NAME_MAX_LENGTH]{};
  int count = GetUserDefaultLocaleName(name, LOCALE_NAME_MAX_LENGTH);
  printf("child-user-locale count=%d error=%lu\n", count, count ? 0 : GetLastError());
  for (LCTYPE type : {LOCALE_SSHORTDATE, LOCALE_SDECIMAL, LOCALE_SLANGUAGE}) {
    wchar_t value[256]{};
    int got = GetLocaleInfoEx(LOCALE_NAME_USER_DEFAULT, type, value, 256);
    printf("child-locale-info type=%lu count=%d error=%lu value=", type, got,
           got ? 0 : GetLastError());
    if (got)
      for (int i = 0; i < got; ++i)
        printf("%04X", unsigned(value[i]));
    puts("");
    if (!got)
      return 44;
  }
  using Allocate = void *(NTAPI *)(ULONG, ULONG);
  using Pointer = ULONG(NTAPI *)(void *, ULONG, void **);
  using Call = LONG(NTAPI *)(void *, void *, ULONG, ULONG);
  using Free = void(NTAPI *)(void *);
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  auto allocate = reinterpret_cast<Allocate>(GetProcAddress(ntdll, "CsrAllocateCaptureBuffer"));
  auto pointer = reinterpret_cast<Pointer>(GetProcAddress(ntdll, "CsrAllocateMessagePointer"));
  auto call = reinterpret_cast<Call>(GetProcAddress(ntdll, "CsrClientCallServer"));
  auto release = reinterpret_cast<Free>(GetProcAddress(ntdll, "CsrFreeCaptureBuffer"));
  if (!allocate || !pointer || !call || !release)
    return 45;
  unsigned char previous[1660]{};
  bool previous_valid = false;
  for (unsigned sample = 0; sample < 6; ++sample) {
    alignas(16) unsigned char packet[952]{};
    void *capture = allocate(1, 1660);
    if (!capture)
      return 46;
    ULONG allocated = pointer(capture, 1660, reinterpret_cast<void **>(packet + 64));
    void *information = nullptr;
    memcpy(&information, packet + 64, sizeof information);
    if (allocated < 1660 || !information)
      return 47;
    unsigned char input[1660]{};
    if (sample == 0 || sample == 4) {
      for (unsigned i = 0; i < 1660; i += 4) {
        ULONG poison = 0xBAADF00D;
        memcpy(input + i, &poison, 4);
      }
    } else if (sample == 1 || sample == 2) {
      memset(input, sample == 1 ? 0xA5 : 0x5A, sizeof input);
    }
    memcpy(information, input, sizeof input);
    ULONG size = 1660;
    memcpy(packet + 72, &size, sizeof size);
    LONG result = call(packet, capture, 0x1001B, 16);
    ULONG reply = 0;
    memcpy(&reply, packet + 52, 4);
    printf("fixed-base-query sample=%u allocated=%lu status=%08lX reply=%08lX bytes=1660 data=",
           sample, allocated, ULONG(result), reply);
    auto bytes = static_cast<unsigned char *>(information);
    for (unsigned i = 0; i < 1660; ++i)
      printf("%02X", bytes[i]);
    puts("");
    if ((result != 0 && ULONG(result) != 0xC0000001) || reply != ULONG(result))
      return 48;
    if (result == 0 && previous_valid && memcmp(previous, bytes, sizeof previous))
      return 49;
    if (result != 0)
      for (unsigned i = 0; i < 1660; ++i)
        if (bytes[i] != input[i])
          return 50;
    if (result == 0) {
      memcpy(previous, bytes, sizeof previous);
      previous_valid = true;
    }
    release(capture);
  }
  return count ? 41 : 44;
}
int main(int argc, char **) {
  if (argc > 1)
    return native_tls_canary == 0x12345678 ? client_probe() : 42;
  setvbuf(stdout, nullptr, _IONBF, 0);
#if !defined(_M_ARM64)
  puts("unsupported-controller-architecture");
  return 23;
#else
  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session))
    fail("controller-session");
  printf("controller-session=%lu\n", session);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto breakpoint = GetProcAddress(ntdll, "DbgBreakPoint");
  if (!breakpoint)
    fail("native-breakpoint-export");
  ULONG brk = 0;
  memcpy(&brk, breakpoint, 4);
  if ((brk & 0xFFE0001F) != 0xD4200000)
    fail("native-breakpoint-instruction");
  std::vector<unsigned char> trap(4);
  memcpy(trap.data(), &brk, 4);
  std::vector<Hook> hooks;
  for (auto [name, count] : {std::pair{"NtSecureConnectPort", 9u},
                             std::pair{"NtAlpcConnectPort", 11u},
                             std::pair{"NtAlpcSendWaitReceivePort", 8u},
                             std::pair{"NtRequestWaitReplyPort", 3u}}) {
    uintptr_t address = uintptr_t(GetProcAddress(ntdll, name));
    if (!address)
      fail("trace-export");
    if (std::any_of(hooks.begin(), hooks.end(),
                    [address](const Hook &h) { return h.address == address; }))
      fail("aliased-trace-exports");
    Hook h{name, address, count, std::vector<unsigned char>(4)};
    memcpy(h.original.data(), reinterpret_cast<void *>(address), 4);
    hooks.push_back(h);
    printf("hook name=%s rva=%llX count=%u\n", name,
           static_cast<unsigned long long>(address - uintptr_t(ntdll)), count);
  }
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
  printf("profile width=%zu child=%lu controller=%lu native-breakpoint=%08lX\n",
         sizeof(void *), child.dwProcessId, GetCurrentProcessId(), brk);
  bool installed = false, exited = false;
  Hook *pending = nullptr;
  uintptr_t args[11]{};
  uintptr_t resume = 0, local = 0, remote = 0;
  SIZE_T view_size = 0, receive_capacity = 0, connection_capacity = 0;
  uintptr_t base_information = 0;
  ULONG base_information_bytes = 0;
  std::vector<unsigned char> return_original(4);
  ULONG entered = 0, returned = 0, exit_code = 0;
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
      bool ready = true;
      for (const auto &h : hooks) {
        unsigned char bytes[32]{};
        SIZE_T got = 0;
        ready &= ReadProcessMemory(child.hProcess,
                                   reinterpret_cast<void *>(h.address), bytes,
                                   sizeof bytes, &got) &&
                 got == sizeof bytes &&
                 memcmp(bytes, reinterpret_cast<void *>(h.address),
                        sizeof bytes) == 0;
      }
      if (ready) {
        for (const auto &h : hooks)
          patch(child.hProcess, h.address, trap);
        installed = true;
      }
    }
    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
        event.u.CreateProcessInfo.hFile)
      CloseHandle(event.u.CreateProcessInfo.hFile);
    else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
             event.u.LoadDll.hFile)
      CloseHandle(event.u.LoadDll.hFile);
    else if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT &&
             event.u.CreateThread.hThread)
      CloseHandle(event.u.CreateThread.hThread);
    else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      ULONG exception = event.u.Exception.ExceptionRecord.ExceptionCode;
      uintptr_t address =
          uintptr_t(event.u.Exception.ExceptionRecord.ExceptionAddress);
      bool trapped =
          exception == EXCEPTION_BREAKPOINT || exception == 0x4000001F;
      auto hit =
          std::find_if(hooks.begin(), hooks.end(), [address](const Hook &h) {
            return h.address == address;
          });
      if (trapped && installed && hit != hooks.end()) {
        if (pending || event.dwThreadId != child.dwThreadId || entered >= 64)
          fail("trace-concurrency-or-bound");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(child.hThread, &context))
          fail("entry-context");
        pending = &*hit;
        for (unsigned i = 0; i < pending->count; ++i)
          args[i] = argument(child.hProcess, context, i);
        resume = caller(child.hProcess, context);
        printf("entry ordinal=%lu name=%s caller=%llX args=", entered,
               pending->name, static_cast<unsigned long long>(resume));
        for (unsigned i = 0; i < pending->count; ++i)
          printf("%llX,", static_cast<unsigned long long>(args[i]));
        puts("");
        if (!strcmp(pending->name, "NtSecureConnectPort")) {
          if (args[3])
            dump(child.hProcess, args[3], 48, "client-view-before");
          connection_capacity = 0;
          if (args[8]) {
            ULONG length = 0;
            read_exact(child.hProcess, args[8], &length, 4);
            connection_capacity = std::min<ULONG>(length, 4096);
          }
          if (args[7] && connection_capacity)
            dump(child.hProcess, args[7], connection_capacity,
                 "connection-before");
        } else if (!strcmp(pending->name, "NtAlpcSendWaitReceivePort")) {
          message(child.hProcess, args[2], "send-message");
          base_information = 0;
          base_information_bytes = 0;
          unsigned char packet[80]{};
          SIZE_T got = 0;
          if (ReadProcessMemory(child.hProcess, reinterpret_cast<void *>(args[2]),
                                packet, sizeof packet, &got) && got == sizeof packet) {
            ULONG api = 0;
            memcpy(&api, packet + 48, 4);
            if (api == 0x1001B) {
              uintptr_t capture = 0, information = 0;
              ULONG count = 0;
              memcpy(&capture, packet + 40, 8);
              memcpy(&information, packet + 64, 8);
              memcpy(&count, packet + 72, 4);
              if (!local || !remote || information < remote ||
                  information - remote > view_size || count > 4096 ||
                  count > view_size - (information - remote) ||
                  capture < remote || capture - remote > view_size - 40)
                fail("base-info-owned-view");
              base_information = local + (information - remote);
              base_information_bytes = count;
              printf("base-info api=%lX capture-remote=%llX info-remote=%llX info-local=%llX bytes=%lu\n",
                     api, static_cast<unsigned long long>(capture),
                     static_cast<unsigned long long>(information),
                     static_cast<unsigned long long>(base_information), count);
              dump(child.hProcess, local + (capture - remote), 40, "base-capture-before");
              dump(child.hProcess, base_information, count, "base-info-before");
            }
          }

          if (args[3])
            dump(child.hProcess, args[3], 8, "send-attributes");
          receive_capacity = 0;
          if (args[5])
            read_exact(child.hProcess, args[5], &receive_capacity,
                       sizeof receive_capacity);
          if (args[4] && receive_capacity)
            dump(child.hProcess, args[4],
                 std::min<SIZE_T>(receive_capacity, 4096), "receive-before");
        } else if (!strcmp(pending->name, "NtRequestWaitReplyPort")) {
          message(child.hProcess, args[1], "request-message");
        } else {
          if (args[1])
            dump(child.hProcess, args[1], 16, "alpc-port-name-header");
        }
        if (local && view_size)
          dump(child.hProcess, local, std::min<SIZE_T>(view_size, 4096),
               "client-section-before-call");
        read_exact(child.hProcess, resume, return_original.data(), 4);
        patch(child.hProcess, pending->address, pending->original);
        patch(child.hProcess, resume, trap);
        set_pc(context, pending->address);
        if (!SetThreadContext(child.hThread, &context))
          fail("resume-entry");
        ++entered;
      } else if (trapped && pending && address == resume) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(child.hThread, &context))
          fail("return-context");
        printf("return ordinal=%lu name=%s status=%08lX\n", returned,
               pending->name, status(context));
        if (!strcmp(pending->name, "NtSecureConnectPort")) {
          if (args[0])
            dump(child.hProcess, args[0], 8, "handle-after");
          if (args[3]) {
            unsigned char view[48]{};
            read_exact(child.hProcess, args[3], view, sizeof view);
            dump(child.hProcess, args[3], sizeof view, "client-view-after");
            if (status(context) == 0) {
              memcpy(&view_size, view + 24, 8);
              memcpy(&local, view + 32, 8);
              memcpy(&remote, view + 40, 8);
              printf("client-alias local=%llX remote=%llX size=%zu\n",
                     static_cast<unsigned long long>(local),
                     static_cast<unsigned long long>(remote), view_size);
            }
          }
          if (args[7] && connection_capacity)
            dump(child.hProcess, args[7], connection_capacity,
                 "connection-after");
        } else if (!strcmp(pending->name, "NtAlpcSendWaitReceivePort")) {
          SIZE_T length = receive_capacity;
          if (args[5])
            read_exact(child.hProcess, args[5], &length, sizeof length);
          printf("receive-length before=%zu after=%zu\n", receive_capacity,
                 length);
          if (base_information && base_information_bytes)
            dump(child.hProcess, base_information, base_information_bytes,
                 "base-info-after");

          if (args[4] && length && receive_capacity)
            dump(child.hProcess, args[4],
                 std::min({length, receive_capacity, SIZE_T(4096)}),
                 "receive-after");
          if (args[6])
            dump(child.hProcess, args[6], 8, "receive-attributes");
        } else if (!strcmp(pending->name, "NtRequestWaitReplyPort")) {
          message(child.hProcess, args[2], "reply-message");
        } else if (args[0]) {
          dump(child.hProcess, args[0], 8, "alpc-handle-after");
        }
        if (local && view_size)
          dump(child.hProcess, local, std::min<SIZE_T>(view_size, 4096),
               "client-section-after-call");
        patch(child.hProcess, resume, return_original);
        patch(child.hProcess, pending->address, trap);
        set_pc(context, resume);
        if (!SetThreadContext(child.hThread, &context))
          fail("resume-return");
        pending = nullptr;
        ++returned;
      } else if (!trapped) {
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
  printf("complete installed=%u entered=%lu returned=%lu exit=%lu\n",
         unsigned(installed), entered, returned, exit_code);
  return installed && entered > 0 && entered == returned && !pending &&
                 exit_code == 41
             ? 0
             : 22;
#endif
}
