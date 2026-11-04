#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <excpt.h>
#include "runtime-v1.h"

typedef struct IoStatus {
  union { LONG status; void *pointer; } result;
  ULONG_PTR information;
} IoStatus;
typedef LONG (NTAPI *QueryFn)(HANDLE, IoStatus *, void *, ULONG, ULONG);
typedef struct Role { const char *name; HANDLE handle; BOOL owned; } Role;
static QueryFn query_file;
static unsigned char *io_pages, *data_pages;
static const unsigned classes[] = {0,4,5,6,7,8,9,14,16,17,18,34,35,41,43,47,51,58,90,0xFFFFFFFFu};
static Role roles[7];

/* Keep the probe freestanding while using the installed exception dispatcher. */
#if defined(_M_IX86)
int __cdecl _except_handler3(void *record, void *frame, void *context, void *dispatch) {
  typedef int (__cdecl *Handler)(void *, void *, void *, void *);
  static Handler target;
  if (!target) target = (Handler)(uintptr_t)GetProcAddress(LoadLibraryW(L"msvcrt.dll"), "_except_handler3");
  if (!target) ExitProcess(80);
  return target(record, frame, context, dispatch);
}
#else
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(
    struct _EXCEPTION_RECORD *record, void *frame, struct _CONTEXT *context,
    struct _DISPATCHER_CONTEXT *dispatch) {
  typedef EXCEPTION_DISPOSITION (__cdecl *Handler)(struct _EXCEPTION_RECORD *, void *,
      struct _CONTEXT *, struct _DISPATCHER_CONTEXT *);
  static Handler target;
  if (!target) target = (Handler)(uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "__C_specific_handler");
  if (!target) ExitProcess(81);
  return target(record, frame, context, dispatch);
}
#endif

static void changes(const void *data, size_t bytes) {
  const unsigned char *p = data;
  BOOL comma = FALSE;
  control_char('{');
  for (size_t i = 0; i < bytes;) {
    if (p[i] == 0xA5) { ++i; continue; }
    if (comma) control_char(',');
    comma = TRUE;
    control_print("\"%u\":\"", (unsigned)i);
    do { control_print("%02x", (unsigned)p[i++]); } while (i < bytes && p[i] != 0xA5);
    control_char('"');
  }
  control_char('}');
}

static DWORD protection(void *address) {
  MEMORY_BASIC_INFORMATION information;
  if (!VirtualQuery(address, &information, sizeof information)) ExitProcess(82);
  return information.Protect;
}

static void observe(const Role *role, unsigned information_class, unsigned length, unsigned which) {
  DWORD prior;
  if (!VirtualProtect(io_pages, 8192, PAGE_READWRITE, &prior) ||
      !VirtualProtect(data_pages, 8192, PAGE_READWRITE, &prior)) ExitProcess(83);
  memset(io_pages, 0xA5, 8192);
  memset(data_pages, 0xA5, 8192);
  if (!VirtualProtect(io_pages + 4096, 4096, PAGE_NOACCESS, &prior) ||
      !VirtualProtect(data_pages + 4096, 4096, PAGE_NOACCESS, &prior)) ExitProcess(84);
  IoStatus *io = (IoStatus *)(void *)(io_pages + 64);
  void *data = data_pages + 64;
  switch (which) {
    case 1: io = NULL; break;
    case 2: data = NULL; break;
    case 3: io = NULL; data = NULL; break;
    case 4: io = (IoStatus *)(uintptr_t)1; break;
    case 5: data = (void *)(uintptr_t)1; break;
    case 6: io = (IoStatus *)(uintptr_t)1; data = (void *)(uintptr_t)1; break;
    case 7: io = (IoStatus *)(void *)(io_pages + 65); break;
    case 8: data = data_pages + 65; break;
    case 9: io = (IoStatus *)(void *)(io_pages + 4096 - 4); break;
    case 10: io = (IoStatus *)(void *)(io_pages + 4096 - sizeof(void *)); break;
    case 11: data = data_pages + 4096 - 4; break;
    case 12: if (!VirtualProtect(io_pages, 4096, PAGE_READWRITE | PAGE_GUARD, &prior)) ExitProcess(85); break;
    case 13: if (!VirtualProtect(data_pages, 4096, PAGE_READWRITE | PAGE_GUARD, &prior)) ExitProcess(86); break;
    case 14:
      if (!VirtualProtect(io_pages, 4096, PAGE_READWRITE | PAGE_GUARD, &prior) ||
          !VirtualProtect(data_pages, 4096, PAGE_READWRITE | PAGE_GUARD, &prior)) ExitProcess(87);
      break;
    case 15: if (!VirtualProtect(data_pages, 4096, PAGE_READONLY, &prior)) ExitProcess(88); break;
    case 16: if (!VirtualProtect(io_pages, 4096, PAGE_READONLY, &prior)) ExitProcess(89); break;
    case 17: data = io; break;
    case 18: data = (unsigned char *)io + sizeof(void *); break;
    case 19: data = (void *)(uintptr_t)(~(uintptr_t)0 - 3); break;
    case 20: io = (IoStatus *)(uintptr_t)(~(uintptr_t)0 - 3); break;
    case 21: io = (IoStatus *)(void *)(data_pages + 68); break;
  }
  LONG returned = (LONG)0xDEADBEEF;
  DWORD exception = 0;
  __try { returned = query_file(role->handle, io, data, length, information_class); }
  __except(EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); }
  if (returned == 0x103) ExitProcess(79);
  DWORD io_protection = protection(io_pages), data_protection = protection(data_pages);
  if (!VirtualProtect(io_pages, 8192, PAGE_READWRITE, &prior) ||
      !VirtualProtect(data_pages, 8192, PAGE_READWRITE, &prior)) ExitProcess(78);
  control_print("{\"role\":\"%s\",\"class\":%u,\"length\":%u,\"case\":%u,\"status\":%lu,\"exception\":%lu,\"io_protect\":%lu,\"data_protect\":%lu,\"io_base\":",
      role->name, information_class, length, which, (unsigned long)(ULONG)returned,
      (unsigned long)exception, (unsigned long)io_protection, (unsigned long)data_protection);
  changes(io_pages + 48, 64);
  control_text(",\"data_base\":"); changes(data_pages + 48, 160);
  control_text(",\"io_tail\":"); changes(io_pages + 4096 - 24, 48);
  control_text(",\"data_tail\":"); changes(data_pages + 4096 - 24, 64);
  control_text("}\n");
}

void entry(void) {
  control_sink = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD handles_before, handles_after;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before)) ExitProcess(70);
  query_file = (QueryFn)(uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile");
  if (!query_file) ExitProcess(77);
  io_pages = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  data_pages = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!io_pages || !data_pages) ExitProcess(76);
  BOOL allocated = FALSE;
  if (GetConsoleWindow() == NULL) allocated = AllocConsole();
  HANDLE file = CreateFileW(L"faults-v1.bin", GENERIC_READ | GENERIC_WRITE, 7, NULL,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE) ExitProcess(75);
  static const char payload[] = "file-information-buffer-fault-control";
  DWORD written;
  if (!WriteFile(file, payload, sizeof payload - 1, &written, NULL) ||
      written != sizeof payload - 1 || SetFilePointer(file, 7, NULL, FILE_BEGIN) != 7)
    ExitProcess(67);
  roles[0] = (Role){"file.sync", file, TRUE};
  roles[1] = (Role){"file.async", CreateFileW(L"faults-v1.bin", GENERIC_READ | GENERIC_WRITE, 7,
                    NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL), TRUE};
  roles[2] = (Role){"console.in", CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, 3,
                    NULL, OPEN_EXISTING, 0, NULL), TRUE};
  roles[3] = (Role){"null", CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, 7,
                    NULL, OPEN_EXISTING, 0, NULL), TRUE};
  HANDLE read_pipe = NULL, write_pipe = NULL;
  if (!CreatePipe(&read_pipe, &write_pipe, NULL, 4096)) ExitProcess(74);
  roles[4] = (Role){"pipe.read", read_pipe, TRUE};
  roles[5] = (Role){"event", CreateEventW(NULL, TRUE, FALSE, NULL), TRUE};
  roles[6] = (Role){"invalid", (HANDLE)(uintptr_t)0x1234, FALSE};
  for (unsigned i = 0; i < 6; ++i)
    if (roles[i].handle == NULL || roles[i].handle == INVALID_HANDLE_VALUE) ExitProcess(73);
  control_text("{\"schema\":\"rax-native-file-information-faults-v1\",\"pointer_bytes\":");
  control_number(sizeof(void *)); control_text(",\"payload_encoding\":\"a5-diff-runs\",\"query_entry\":\"");
  for (unsigned i = 0; i < 64; ++i)
    control_print("%02x", (unsigned)((const unsigned char *)(uintptr_t)query_file)[i]);
  control_text("\"}\n");
  DWORD before_queries, after_queries;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before_queries)) ExitProcess(66);
  for (unsigned role = 0; role < sizeof roles / sizeof roles[0]; ++role) {
    for (unsigned c = 0; c < sizeof classes / sizeof classes[0]; ++c) {
      for (unsigned length = 0; length <= 80; ++length) observe(&roles[role], classes[c], length, 0);
      for (unsigned which = 0; which <= 21; ++which) observe(&roles[role], classes[c], 512, which);
    }
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after_queries)) ExitProcess(65);
  for (unsigned i = 0; i < 6; ++i) if (!CloseHandle(roles[i].handle)) ExitProcess(72);
  if (!CloseHandle(write_pipe) || !DeleteFileW(L"faults-v1.bin")) ExitProcess(71);
  control_flush();
  if (allocated) FreeConsole();
  if (!VirtualFree(io_pages, 0, MEM_RELEASE) || !VirtualFree(data_pages, 0, MEM_RELEASE)) ExitProcess(69);
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_after)) ExitProcess(68);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"before_queries\":%lu,\"after_queries\":%lu,\"owned_handles_closed\":7}\n",
      (unsigned long)handles_before, (unsigned long)handles_after,
      (unsigned long)before_queries, (unsigned long)after_queries);
  control_flush();
  ExitProcess(0);
}
