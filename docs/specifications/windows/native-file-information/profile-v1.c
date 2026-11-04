#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "runtime-v1.h"

typedef struct IoStatus {
  union { LONG status; void *pointer; } result;
  ULONG_PTR information;
} IoStatus;

typedef LONG (NTAPI *QueryFileFn)(HANDLE, IoStatus *, void *, ULONG, ULONG);
typedef LONG (NTAPI *VersionFn)(OSVERSIONINFOW *);

typedef struct Role {
  const char *name;
  HANDLE handle;
  DWORD error;
  BOOL owned;
} Role;

static QueryFileFn query_file;
static __declspec(align(16)) unsigned char output[528];
static const unsigned lengths[] = {0, 1, 4, 8, 16, 24, 40, 64, 256, 512};
static Role roles[20];
static unsigned role_count;

static void hex(const void *data, size_t bytes) {
  const unsigned char *p = data;
  control_char('"');
  for (size_t i = 0; i < bytes; ++i) control_print("%02x", (unsigned)p[i]);
  control_char('"');
}

static void add(const char *name, HANDLE handle, BOOL owned) {
  if (role_count == sizeof roles / sizeof roles[0]) ExitProcess(20);
  Role *role = &roles[role_count++];
  role->name = name;
  role->handle = handle;
  role->error = owned && (handle == INVALID_HANDLE_VALUE || handle == NULL) ? GetLastError() : 0;
  role->owned = owned && handle != INVALID_HANDLE_VALUE && handle != NULL;
}

static HANDLE disk(DWORD access, DWORD flags) {
  return CreateFileW(L"payload-v1.bin", access, 7, NULL, OPEN_EXISTING, flags, NULL);
}

static void observe(const Role *role, unsigned information_class, unsigned length) {
  IoStatus io;
  memset(&io, 0xA5, sizeof io);
  memset(output, 0xA5, sizeof output);
  LONG status = query_file(role->handle, &io, output, length, information_class);
  size_t changed = 0;
  unsigned past = 0;
  for (size_t i = 0; i < 512; ++i) {
    if (output[i] != 0xA5) changed = i + 1;
    if (i >= length && output[i] != 0xA5) ++past;
  }
  size_t kept = changed;
  if (io.information <= length && io.information > kept) kept = io.information;
  unsigned guard = 0;
  for (size_t i = 512; i < sizeof output; ++i) guard += output[i] != 0xA5;
  control_print("{\"role\":\"%s\",\"class\":%u,\"length\":%u,\"status\":%lu,\"io\":",
                role->name, information_class, length, (unsigned long)(ULONG)status);
  hex(&io, sizeof io);
  control_print(",\"changed_end\":%zu,\"past_length_changes\":%u,\"guard_changes\":%u,\"data\":",
                changed, past, guard);
  hex(output, kept);
  control_text("}\n");
}

void entry(void) {
  control_sink = GetStdHandle(STD_OUTPUT_HANDLE);
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  query_file = (QueryFileFn)(uintptr_t)GetProcAddress(module, "NtQueryInformationFile");
  VersionFn version = (VersionFn)(uintptr_t)GetProcAddress(module, "RtlGetVersion");
  if (!query_file || !version) ExitProcess(21);
  OSVERSIONINFOW os;
  memset(&os, 0, sizeof os);
  os.dwOSVersionInfoSize = sizeof os;
  if (version(&os) != 0) ExitProcess(22);
#if defined(_M_ARM64)
  const char *arch = "arm64";
#elif defined(_M_X64)
  const char *arch = "x64";
#elif defined(_M_IX86)
  const char *arch = "x86";
#else
#error unsupported control architecture
#endif
  control_print("{\"schema\":\"rax-native-file-information-profile-v1\",\"arch\":\"%s\",\"pointer_bytes\":%zu,\"build\":%lu,\"leaf\":",
                arch, sizeof(void *), (unsigned long)os.dwBuildNumber);
  hex((const void *)(uintptr_t)query_file, 32);
  control_text("}\n");

  HANDLE file = CreateFileW(L"payload-v1.bin", GENERIC_READ | GENERIC_WRITE, 7,
                            NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) ExitProcess(23);
  static const unsigned char payload[] = "native file-information control data\n";
  DWORD written = 0;
  if (!WriteFile(file, payload, sizeof payload - 1, &written, NULL) ||
      written != sizeof payload - 1) ExitProcess(24);
  LARGE_INTEGER seven;
  seven.QuadPart = 7;
  if (!SetFilePointerEx(file, seven, NULL, FILE_BEGIN)) ExitProcess(25);
  add("disk.sync.rw.position7", file, TRUE);
  add("disk.sync.read", disk(GENERIC_READ, FILE_ATTRIBUTE_NORMAL), TRUE);
  add("disk.sync.attributes", disk(FILE_READ_ATTRIBUTES, FILE_ATTRIBUTE_NORMAL), TRUE);
  add("disk.async.rw", disk(GENERIC_READ | GENERIC_WRITE, FILE_FLAG_OVERLAPPED), TRUE);
  add("disk.independent.rw.position0", disk(GENERIC_READ | GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL), TRUE);
  HANDLE duplicate = NULL;
  if (!DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &duplicate,
                       0, FALSE, DUPLICATE_SAME_ACCESS)) ExitProcess(26);
  add("disk.duplicate.same", duplicate, TRUE);
  duplicate = NULL;
  if (!DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &duplicate,
                       FILE_READ_ATTRIBUTES, FALSE, 0)) ExitProcess(27);
  add("disk.duplicate.attributes", duplicate, TRUE);
  add("directory.read", CreateFileW(L".", GENERIC_READ, 7, NULL, OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS, NULL), TRUE);
  add("null.rw", CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, 7, NULL,
                            OPEN_EXISTING, 0, NULL), TRUE);
  HANDLE read_pipe = NULL, write_pipe = NULL;
  if (!CreatePipe(&read_pipe, &write_pipe, NULL, 4096)) ExitProcess(28);
  add("pipe.read", read_pipe, TRUE);
  add("pipe.write", write_pipe, TRUE);
  BOOL allocated = FALSE;
  if (GetConsoleWindow() == NULL) allocated = AllocConsole();
  add("console.in", CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, 3,
                                NULL, OPEN_EXISTING, 0, NULL), TRUE);
  add("console.out", CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, 3,
                                 NULL, OPEN_EXISTING, 0, NULL), TRUE);
  add("event", CreateEventW(NULL, TRUE, FALSE, NULL), TRUE);
  add("invalid", (HANDLE)(uintptr_t)0x1234, FALSE);
  add("process.pseudo", GetCurrentProcess(), FALSE);
  add("thread.pseudo", GetCurrentThread(), FALSE);
  DWORD handles_before = 0, handles_after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before)) ExitProcess(29);
  for (unsigned role = 0; role < role_count; ++role) {
    const Role *item = &roles[role];
    control_print("{\"resource\":\"%s\",\"open_error\":%lu}\n", item->name,
                  (unsigned long)item->error);
    if (item->error && item->owned == FALSE && role < 14) continue;
    for (unsigned information_class = 0; information_class <= 90; ++information_class) {
      for (unsigned i = 0; i < sizeof lengths / sizeof lengths[0]; ++i)
        observe(item, information_class, lengths[i]);
    }
    observe(item, 0xFFFFFFFFu, 512);
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_after)) ExitProcess(30);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"roles\":%u}\n",
                (unsigned long)handles_before, (unsigned long)handles_after, role_count);
  for (unsigned role = 0; role < role_count; ++role)
    if (roles[role].owned && !CloseHandle(roles[role].handle)) ExitProcess(31);
  if (!DeleteFileW(L"payload-v1.bin")) ExitProcess(32);
  control_flush();
  if (allocated) FreeConsole();
  ExitProcess(0);
}
