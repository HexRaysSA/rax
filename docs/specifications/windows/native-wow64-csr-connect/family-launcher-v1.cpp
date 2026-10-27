#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstddef>
#include <cstdio>
#include <string>
#include <windows.h>
#include <winternl.h>

// Native creation layouts from winsiderss/phnt ntpsapi.h, revision
// 53fbbdc5b5d2b08761db1c7b26bfa8c820924356. Only owned child processes
// receive the per-process CHPE attribute; no machine policy is changed.
struct Attribute {
  ULONG_PTR name;
  SIZE_T size;
  ULONG_PTR value;
  SIZE_T *returned;
};
struct Attributes {
  SIZE_T size;
  Attribute entries[2];
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

static UNICODE_STRING string(std::wstring &value) {
  UNICODE_STRING u{};
  u.Length = USHORT(value.size() * sizeof(wchar_t));
  u.MaximumLength = USHORT(u.Length + sizeof(wchar_t));
  u.Buffer = value.data();
  return u;
}

int wmain(int argc, wchar_t **argv) {
  if (argc != 3)
    return 30;
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto create_parameters = reinterpret_cast<CreateParameters>(
      GetProcAddress(ntdll, "RtlCreateProcessParametersEx"));
  auto destroy_parameters = reinterpret_cast<DestroyParameters>(
      GetProcAddress(ntdll, "RtlDestroyProcessParameters"));
  auto create = reinterpret_cast<NativeCreateProcess>(
      GetProcAddress(ntdll, "NtCreateUserProcess"));
  if (!create_parameters || !destroy_parameters || !create)
    return 31;
  bool failed = false;
  for (int mode : {-1, 1, 0}) {
    std::wstring image = L"\\??\\";
    image += argv[1];
    std::wstring output = argv[2];
    output += mode < 0 ? L"/default.log"
              : mode   ? L"/enabled.log"
                       : L"/disabled.log";
    std::wstring command = L"\"";
    command += argv[1];
    command += L"\" \"";
    command += output;
    command += L"\"";
    auto image_string = string(image);
    auto command_string = string(command);
    RTL_USER_PROCESS_PARAMETERS *parameters = nullptr;
    void *environment = GetEnvironmentStringsW();
    if (!environment)
      return 32;
    LONG s = create_parameters(&parameters, &image_string, nullptr, nullptr,
                               &command_string, environment, nullptr, nullptr,
                               nullptr, nullptr, 1);
    FreeEnvironmentStringsW(static_cast<wchar_t *>(environment));
    if (s < 0 || !parameters)
      return 33;
    Attributes attributes{};
    attributes.size =
        offsetof(Attributes, entries) + sizeof(Attribute) * (mode < 0 ? 1 : 2);
    attributes.entries[0] = {0x20005, image_string.Length,
                             reinterpret_cast<ULONG_PTR>(image_string.Buffer),
                             nullptr};
    if (mode >= 0)
      attributes.entries[1] = {0x6001a, sizeof(BOOLEAN), ULONG_PTR(mode),
                               nullptr};
    CreateInfo info{};
    info.size = sizeof(info);
    HANDLE process = nullptr, thread = nullptr;
    s = create(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
               nullptr, nullptr, 0, 0, parameters, &info, &attributes);
    destroy_parameters(parameters);
    printf("create mode=%d status=%08lX state=%lu peb_native=%llX "
           "peb_wow64=%08lX\n",
           mode, ULONG(s), info.state,
           info.state == 6 ? info.success.peb_native : 0,
           info.state == 6 ? info.success.peb_wow64 : 0);
    fflush(stdout);
    if (s >= 0) {
      if (!process || !thread || info.state != 6)
        return 34;
      if (info.success.file)
        CloseHandle(info.success.file);
      if (info.success.section)
        CloseHandle(info.success.section);
      DWORD wait = WaitForSingleObject(process, 30000);
      DWORD code = 0xffffffff;
      if (wait != WAIT_OBJECT_0) {
        // This handle names only the just-created diagnostic child.
        TerminateProcess(process, 35);
        WaitForSingleObject(process, 5000);
        failed = true;
      }
      if (!GetExitCodeProcess(process, &code))
        failed = true;
      printf("child mode=%d pid=%lu wait=%lu exit=%lu\n", mode,
             GetProcessId(process), wait, code);
      failed |= code != 0;
    } else {
      if (info.state == 2 && info.failure.file)
        CloseHandle(info.failure.file);
      failed = true;
    }
    if (thread)
      CloseHandle(thread);
    if (process)
      CloseHandle(process);
  }
  printf("done failed=%u\n", unsigned(failed));
  return failed ? 36 : 0;
}
