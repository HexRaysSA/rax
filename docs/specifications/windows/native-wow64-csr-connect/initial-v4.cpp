#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <windows.h>
#include <winternl.h>

static_assert(sizeof(void *) == 8,
              "Native64 controller with a pure x86 child.");
static_assert(sizeof(WOW64_CONTEXT) == 716);

struct Attribute {
  ULONG_PTR name;
  SIZE_T size;
  ULONG_PTR value;
  SIZE_T *returned;
};
struct Attributes {
  SIZE_T size;
  Attribute entries[3];
};
struct CreateInfo {
  SIZE_T size;
  ULONG state;
  union {
    struct {
      ULONG flags, additional_access;
    } initial;
    struct {
      HANDLE file;
    } failure;
    struct {
      ULONG flags;
      HANDLE file, section;
      ULONGLONG parameters_native;
      ULONG parameters_wow64, parameter_flags;
      ULONGLONG peb_native;
      ULONG peb_wow64;
      ULONGLONG manifest;
      ULONG manifest_size;
    } success;
  };
};
static_assert(sizeof(void *) == 8);
static_assert(sizeof(CreateInfo) == 88);
static_assert(offsetof(CreateInfo, initial) == 16);
static_assert(sizeof(Attribute) == 32);
using CreateParameters = LONG(NTAPI *)(RTL_USER_PROCESS_PARAMETERS **,
                                       UNICODE_STRING *, UNICODE_STRING *,
                                       UNICODE_STRING *, UNICODE_STRING *,
                                       void *, UNICODE_STRING *,
                                       UNICODE_STRING *, UNICODE_STRING *,
                                       UNICODE_STRING *, ULONG);
using DestroyParameters = void(NTAPI *)(RTL_USER_PROCESS_PARAMETERS *);
using NativeCreateProcess = LONG(NTAPI *)(HANDLE *, HANDLE *, ACCESS_MASK,
                                          ACCESS_MASK, OBJECT_ATTRIBUTES *,
                                          OBJECT_ATTRIBUTES *, ULONG, ULONG,
                                          RTL_USER_PROCESS_PARAMETERS *,
                                          CreateInfo *, Attributes *);

static void fail(const char *operation) {
  std::printf("FAIL operation=%s error=%lu\n", operation, GetLastError());
  ExitProcess(21);
}

static void read_exact(HANDLE process, uintptr_t address, void *data,
                       SIZE_T size) {
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void *>(address), data, size,
                         &got) ||
      got != size)
    fail("read-owned-child");
}

static uintptr_t discover(HANDLE process, uintptr_t base) {
  IMAGE_DOS_HEADER dos{};
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void *>(base), &dos,
                         sizeof(dos), &got) ||
      got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
      dos.e_lfanew < 0 || dos.e_lfanew > 4096)
    return 0;
  IMAGE_NT_HEADERS32 nt{};
  read_exact(process, base + static_cast<ULONG>(dos.e_lfanew), &nt, sizeof(nt));
  if (nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    return 0;
  const auto directory =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!directory.VirtualAddress ||
      directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
    return 0;
  IMAGE_EXPORT_DIRECTORY exports{};
  read_exact(process, base + directory.VirtualAddress, &exports,
             sizeof(exports));
  std::array<char, 10> module{};
  read_exact(process, base + exports.Name, module.data(), module.size());
  if (module.back() != 0 || _stricmp(module.data(), "ntdll.dll") != 0 ||
      exports.NumberOfNames > 8192 || exports.NumberOfFunctions > 8192)
    return 0;
  for (ULONG index = 0; index < exports.NumberOfNames; ++index) {
    ULONG name = 0;
    read_exact(process, base + exports.AddressOfNames + index * 4, &name, 4);
    std::array<char, 36> text{};
    read_exact(process, base + name, text.data(), text.size() - 1);
    if (std::strcmp(text.data(), "NtWow64CsrClientConnectToServer") != 0)
      continue;
    USHORT ordinal = 0;
    read_exact(process, base + exports.AddressOfNameOrdinals + index * 2,
               &ordinal, 2);
    if (ordinal >= exports.NumberOfFunctions)
      fail("export-ordinal");
    ULONG function = 0;
    read_exact(process, base + exports.AddressOfFunctions + ordinal * 4,
               &function, 4);
    if (function >= nt.OptionalHeader.SizeOfImage ||
        base + function > 0xFFFFFFFF)
      fail("export-range");
    return base + function;
  }
  return 0;
}

static uintptr_t native_peb = 0, wow_peb = 0;

static PROCESS_INFORMATION create_pure(wchar_t *path, HANDLE *debug_object) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto create_parameters = reinterpret_cast<CreateParameters>(
      GetProcAddress(ntdll, "RtlCreateProcessParametersEx"));
  auto destroy_parameters = reinterpret_cast<DestroyParameters>(
      GetProcAddress(ntdll, "RtlDestroyProcessParameters"));
  auto create = reinterpret_cast<NativeCreateProcess>(
      GetProcAddress(ntdll, "NtCreateUserProcess"));
  using ConnectDebug = LONG(NTAPI *)();
  using GetDebug = HANDLE(NTAPI *)();
  auto connect_debug = reinterpret_cast<ConnectDebug>(
      GetProcAddress(ntdll, "DbgUiConnectToDbg"));
  auto get_debug = reinterpret_cast<GetDebug>(
      GetProcAddress(ntdll, "DbgUiGetThreadDebugObject"));
  if (!create_parameters || !destroy_parameters || !create || !connect_debug ||
      !get_debug || connect_debug() < 0)
    fail("native-create-debug-exports");
  *debug_object = get_debug();
  if (!*debug_object)
    fail("native-debug-object");
  std::wstring image = L"\\??\\";
  image += path;
  std::wstring command = L"\"" + std::wstring(path) + L"\"";
  UNICODE_STRING image_string{};
  image_string.Length = static_cast<USHORT>(image.size() * 2);
  image_string.MaximumLength = image_string.Length + 2;
  image_string.Buffer = image.data();
  UNICODE_STRING command_string{};
  command_string.Length = static_cast<USHORT>(command.size() * 2);
  command_string.MaximumLength = command_string.Length + 2;
  command_string.Buffer = command.data();
  RTL_USER_PROCESS_PARAMETERS *parameters = nullptr;
  void *environment = GetEnvironmentStringsW();
  if (!environment)
    fail("environment-copy");
  const LONG parameter_status = create_parameters(
      &parameters, &image_string, nullptr, nullptr, &command_string,
      environment, nullptr, nullptr, nullptr, nullptr, 1);
  FreeEnvironmentStringsW(static_cast<wchar_t *>(environment));
  if (parameter_status < 0 || !parameters)
    fail("native-parameters");
  Attributes attributes{};
  attributes.size = sizeof(attributes);
  attributes.entries[0] = {0x60001, sizeof(HANDLE),
                           reinterpret_cast<ULONG_PTR>(*debug_object), nullptr};
  attributes.entries[1] = {0x20005, image_string.Length,
                           reinterpret_cast<ULONG_PTR>(image_string.Buffer),
                           nullptr};
  attributes.entries[2] = {0x6001a, sizeof(BOOLEAN), 0, nullptr};
  CreateInfo info{};
  info.size = sizeof(info);
  HANDLE process = nullptr, thread = nullptr;
  const LONG status =
      create(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr,
             nullptr, 0, 0, parameters, &info, &attributes);
  destroy_parameters(parameters);
  std::printf("CREATE status=%08lX state=%lu chpe=0\n", ULONG(status),
              info.state);
  if (status < 0 || info.state != 6 || !process || !thread)
    fail("native-create-pure-child");
  native_peb = static_cast<uintptr_t>(info.success.peb_native);
  wow_peb = info.success.peb_wow64;
  if (info.success.file)
    CloseHandle(info.success.file);
  if (info.success.section)
    CloseHandle(info.success.section);
  PROCESS_INFORMATION child{};
  child.hProcess = process;
  child.hThread = thread;
  child.dwProcessId = GetProcessId(process);
  child.dwThreadId = GetThreadId(thread);
  return child;
}

static void patch(HANDLE process, uintptr_t address, BYTE byte) {
  DWORD old = 0, ignored = 0;
  SIZE_T wrote = 0;
  if (!VirtualProtectEx(process, reinterpret_cast<void *>(address), 1,
                        PAGE_EXECUTE_READWRITE, &old) ||
      !WriteProcessMemory(process, reinterpret_cast<void *>(address), &byte, 1,
                          &wrote) ||
      wrote != 1 ||
      !VirtualProtectEx(process, reinterpret_cast<void *>(address), 1, old,
                        &ignored) ||
      !FlushInstructionCache(process, reinterpret_cast<void *>(address), 1))
    fail("patch-owned-child");
  BYTE actual = 0;
  read_exact(process, address, &actual, 1);
  if (actual != byte)
    fail("verify-owned-child-patch");
}

static void dump(HANDLE process, uintptr_t address, ULONG bytes,
                 const char *label) {
  std::array<BYTE, 1024> data{};
  SIZE_T got = 0;
  const SIZE_T size = std::min<SIZE_T>(bytes, data.size());
  const BOOL ok =
      address && ReadProcessMemory(process, reinterpret_cast<void *>(address),
                                   data.data(), size, &got);
  std::printf("DATA label=%s address=%08lX bytes=%lu ok=%u got=%zu hex=", label,
              static_cast<ULONG>(address), bytes, unsigned(ok), got);
  for (SIZE_T i = 0; i < got; ++i)
    std::printf("%02X", unsigned(data[i]));
  std::puts("");
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 2)
    return 2;
  setvbuf(stdout, nullptr, _IONBF, 0);
  HANDLE debug_object = nullptr;
  PROCESS_INFORMATION child = create_pure(argv[1], &debug_object);
  std::printf("CHILD pid=%lu tid=%lu chpe=0\n", child.dwProcessId,
              child.dwThreadId);
  uintptr_t entry = 0;
  std::array<BYTE, 32> local{};
  bool installed = false, pending = false, exited = false;
  ULONG entered = 0, returned = 0, base_calls = 0, exit_code = 0;
  uintptr_t resume = 0;
  BYTE return_original = 0;
  std::array<ULONG, 5> args{};
  std::array<BYTE, 0x800> native_before{};
  std::array<BYTE, 0x500> wow_before{};
  DWORD handles_before = 0;

  const ULONGLONG deadline = GetTickCount64() + 120000;
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
      const uintptr_t base = reinterpret_cast<uintptr_t>(
          event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT
              ? event.u.CreateProcessInfo.lpBaseOfImage
              : event.u.LoadDll.lpBaseOfDll);
      const uintptr_t candidate = discover(child.hProcess, base);
      if (candidate) {
        read_exact(child.hProcess, candidate, local.data(), local.size());
        if (local[0] != 0xB8 || local[12] != 0xC2 || local[13] != 20 ||
            local[14] != 0)
          fail("pure-leaf-ABI");
        entry = candidate;
        patch(child.hProcess, entry, 0xCC);
        installed = true;
        std::printf("INSTALLED event=%lu base=%llX rva=%llX machine=014C "
                    "ret-bytes=20\n",
                    event.dwDebugEventCode,
                    static_cast<unsigned long long>(base),
                    static_cast<unsigned long long>(entry - base));
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
      const ULONG exception = event.u.Exception.ExceptionRecord.ExceptionCode;
      const uintptr_t hit = reinterpret_cast<uintptr_t>(
          event.u.Exception.ExceptionRecord.ExceptionAddress);
      const bool breakpoint =
          exception == EXCEPTION_BREAKPOINT || exception == 0x4000001F;
      if (breakpoint && installed &&
          (hit == entry || (pending && hit == resume))) {
        if (event.dwThreadId != child.dwThreadId || entered >= 64)
          fail("single-thread-capture-bound");
        WOW64_CONTEXT context{};
        context.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(child.hThread, &context))
          fail("child-context");
        if (hit == entry) {
          if (pending)
            fail("nested-entry");
          ULONG return_word = 0;
          read_exact(child.hProcess, context.Esp, &return_word, 4);
          resume = return_word;
          read_exact(child.hProcess, context.Esp + 4, args.data(),
                     sizeof(args));
          std::printf("ENTRY ordinal=%lu sp=%08lX directory=%08lX server=%lu "
                      "buffer=%08lX bytes=%lu inside=%08lX\n",
                      entered, context.Esp, args[0], args[1], args[2], args[3],
                      args[4]);
          using QueryProcess =
              LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
          auto query = reinterpret_cast<QueryProcess>(GetProcAddress(
              GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
          if (!query)
            fail("process-query-export");
          PROCESS_BASIC_INFORMATION basic{};
          ULONG returned_bytes = 0;
          const LONG basic_status =
              query(child.hProcess, 0, &basic, sizeof(basic), &returned_bytes);
          ULONG_PTR wow_value = 0;
          const LONG wow_status = query(child.hProcess, 26, &wow_value,
                                        sizeof(wow_value), &returned_bytes);
          native_peb = reinterpret_cast<uintptr_t>(basic.PebBaseAddress);
          wow_peb = wow_value;
          std::printf("PEB_IDENTITIES status64=%08lX status32=%08lX "
                      "native=%llX wow=%llX\n",
                      ULONG(basic_status), ULONG(wow_status),
                      static_cast<unsigned long long>(native_peb),
                      static_cast<unsigned long long>(wow_peb));
          if (basic_status < 0 || wow_status < 0 || !native_peb || !wow_peb ||
              wow_peb > 0xFFFFFFFF)
            fail("stopped-peb-identities");
          read_exact(child.hProcess, native_peb, native_before.data(),
                     native_before.size());
          read_exact(child.hProcess, wow_peb, wow_before.data(),
                     wow_before.size());
          if (!GetProcessHandleCount(child.hProcess, &handles_before))
            fail("before-child-handles");
          if (args[1] == 1)
            ++base_calls;
          if (args[2])
            dump(child.hProcess, args[2], args[3], "before-buffer");
          if (args[4])
            dump(child.hProcess, args[4], 1, "before-inside");
          read_exact(child.hProcess, resume, &return_original, 1);
          patch(child.hProcess, entry, local[0]);
          patch(child.hProcess, resume, 0xCC);
          context.Eip = static_cast<ULONG>(entry);
          pending = true;
          ++entered;
        } else {
          std::printf("RETURN ordinal=%lu status=%08lX sp=%08lX\n", returned,
                      context.Eax, context.Esp);
          if (args[2])
            dump(child.hProcess, args[2], args[3], "after-buffer");
          if (args[4])
            dump(child.hProcess, args[4], 1, "after-inside");
          std::array<BYTE, 0x800> native_after{};
          std::array<BYTE, 0x500> wow_after{};
          read_exact(child.hProcess, native_peb, native_after.data(),
                     native_after.size());
          read_exact(child.hProcess, wow_peb, wow_after.data(),
                     wow_after.size());
          DWORD handles_after = 0;
          if (!GetProcessHandleCount(child.hProcess, &handles_after))
            fail("after-child-handles");
          unsigned native_changes = 0, wow_changes = 0;
          for (SIZE_T i = 0; i < native_after.size(); ++i)
            if (native_after[i] != native_before[i]) {
              ++native_changes;
              std::printf(
                  "PEB_CHANGE width=64 offset=%zu before=%02X after=%02X\n", i,
                  unsigned(native_before[i]), unsigned(native_after[i]));
            }
          for (SIZE_T i = 0; i < wow_after.size(); ++i)
            if (wow_after[i] != wow_before[i]) {
              ++wow_changes;
              std::printf(
                  "PEB_CHANGE width=32 offset=%zu before=%02X after=%02X\n", i,
                  unsigned(wow_before[i]), unsigned(wow_after[i]));
            }
          std::printf("PEB_DELTA bytes64=%zu bytes32=%zu changed64=%u "
                      "changed32=%u handles=%lu:%lu\n",
                      native_after.size(), wow_after.size(), native_changes,
                      wow_changes, handles_before, handles_after);
          patch(child.hProcess, resume, return_original);
          patch(child.hProcess, entry, 0xCC);
          context.Eip = static_cast<ULONG>(resume);
          pending = false;
          ++returned;
        }
        if (!Wow64SetThreadContext(child.hThread, &context))
          fail("restore-execution-context");
      } else if (!breakpoint) {
        std::printf("EXCEPTION code=%08lX first=%lu\n", exception,
                    event.u.Exception.dwFirstChance);
        disposition = DBG_EXCEPTION_NOT_HANDLED;
      }
    } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      exit_code = event.u.ExitProcess.dwExitCode;
      exited = true;
    }
    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition))
      fail("continue-child");
  }
  if (!exited)
    fail("observation-deadline");
  CloseHandle(child.hThread);
  CloseHandle(child.hProcess);
  CloseHandle(debug_object);
  std::printf("DONE installed=%u entered=%lu returned=%lu base-calls=%lu "
              "pending=%u exit=%lu\n",
              unsigned(installed), entered, returned, base_calls,
              unsigned(pending), exit_code);
  return installed && entered == returned && base_calls != 0 && !pending &&
                 exit_code == 0
             ? 0
             : 22;
}
