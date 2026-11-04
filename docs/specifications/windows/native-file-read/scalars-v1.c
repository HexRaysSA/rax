#define WIN32_LEAN_AND_MEAN
#include "runtime-v1.h"
#include <stdint.h>
#include <windows.h>

typedef struct IoStatus {
  union {
    LONG status;
    void *pointer;
  } result;
  ULONG_PTR information;
} IoStatus;
typedef LONG(NTAPI *ReadFn)(HANDLE, HANDLE, void *, void *, IoStatus *, void *,
                            ULONG, LARGE_INTEGER *, ULONG *);
typedef LONG(NTAPI *InformationFn)(HANDLE, IoStatus *, void *, ULONG, ULONG);
static ReadFn read_file;
static InformationFn query_file;
static const char *roles[] = {
    "file.sync.rw",    "file.sync.read",      "file.sync.attributes",
    "file.async.read", "file.duplicate.read", "directory.read",
    "null.read",       "console.in",          "console.out",
    "pipe.read",       "pipe.write",          "event",
    "invalid",         "process.pseudo",      "thread.pseudo"};
static const int64_t offsets[] = {INT64_MIN, -3, -2, -1, 0, 2, 7, 8, 9};
static const unsigned lengths[] = {0, 1, 4, 16};
static const unsigned char payload[] = {0x41, 0x00, 0x42, 0x7f,
                                        0x80, 0xfe, 0xff, 0x5a};
typedef struct Resource {
  HANDLE h, parent, other, owned[6];
  unsigned count;
  BOOL file, directory;
} Resource;
static void hex(const void *p, size_t n) {
  const unsigned char *b = p;
  control_char('"');
  for (size_t i = 0; i < n; ++i)
    control_print("%02x", (unsigned)b[i]);
  control_char('"');
}
static HANDLE keep(Resource *r, HANDLE h) {
  if (h == NULL || h == INVALID_HANDLE_VALUE || r->count == 6)
    ExitProcess(20);
  r->owned[r->count++] = h;
  return h;
}
static void set_position(HANDLE h, LONGLONG value) {
  LARGE_INTEGER p;
  p.QuadPart = value;
  if (!SetFilePointerEx(h, p, NULL, FILE_BEGIN))
    ExitProcess(21);
}
static Resource acquire(unsigned role) {
  Resource r;
  memset(&r, 0, sizeof r);
  if (role < 5) {
    r.file = TRUE;
    HANDLE seed = CreateFileW(L"read-v1.bin", GENERIC_READ | GENERIC_WRITE, 7,
                              NULL, CREATE_ALWAYS, 0, NULL);
    if (seed == INVALID_HANDLE_VALUE)
      ExitProcess(22);
    DWORD written = 0;
    if (!WriteFile(seed, payload, sizeof payload, &written, NULL) ||
        written != sizeof payload)
      ExitProcess(23);
    if (role == 0) {
      r.h = keep(&r, seed);
      set_position(r.h, 2);
    } else {
      if (!CloseHandle(seed))
        ExitProcess(24);
      DWORD access = role == 2 ? FILE_READ_ATTRIBUTES : GENERIC_READ;
      HANDLE h =
          keep(&r, CreateFileW(L"read-v1.bin", access, 7, NULL, OPEN_EXISTING,
                               role == 3 ? FILE_FLAG_OVERLAPPED : 0, NULL));
      if (role != 3 && role != 2)
        set_position(h, 2);
      if (role == 4) {
        r.parent = h;
        HANDLE duplicate;
        if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
                             &duplicate, FILE_READ_DATA, 0, 0))
          ExitProcess(25);
        r.h = keep(&r, duplicate);
      } else
        r.h = h;
    }
    r.other = keep(&r, CreateFileW(L"read-v1.bin", GENERIC_READ, 7, NULL,
                                   OPEN_EXISTING, 0, NULL));
  } else
    switch (role) {
    case 5:
      r.directory = TRUE;
      if (!CreateDirectoryW(L"read-dir-v1", NULL))
        ExitProcess(26);
      r.h = keep(&r,
                 CreateFileW(L"read-dir-v1", GENERIC_READ, 7, NULL,
                             OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL));
      break;
    case 6:
      r.h = keep(&r, CreateFileW(L"NUL", GENERIC_READ, 7, NULL, OPEN_EXISTING,
                                 0, NULL));
      break;
    case 7: {
      r.h = keep(&r, CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, 3,
                                 NULL, OPEN_EXISTING, 0, NULL));
      if (!FlushConsoleInputBuffer(r.h) || !SetConsoleMode(r.h, 0))
        ExitProcess(27);
      INPUT_RECORD inputs[16];
      memset(inputs, 0, sizeof inputs);
      for (unsigned i = 0; i < 16; ++i) {
        inputs[i].EventType = KEY_EVENT;
        inputs[i].Event.KeyEvent.bKeyDown = TRUE;
        inputs[i].Event.KeyEvent.wRepeatCount = 1;
        inputs[i].Event.KeyEvent.wVirtualKeyCode = 'R';
        inputs[i].Event.KeyEvent.uChar.UnicodeChar = L'R';
      }
      DWORD count;
      if (!WriteConsoleInputW(r.h, inputs, 16, &count) || count != 16)
        ExitProcess(28);
      break;
    }
    case 8:
      r.h = keep(&r, CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, 3,
                                 NULL, OPEN_EXISTING, 0, NULL));
      break;
    case 9:
    case 10: {
      HANDLE a, b;
      if (!CreatePipe(&a, &b, NULL, 4096))
        ExitProcess(29);
      DWORD n;
      if (!WriteFile(b, payload, sizeof payload, &n, NULL) ||
          n != sizeof payload)
        ExitProcess(30);
      if (role == 9) {
        r.h = keep(&r, a);
        if (!CloseHandle(b))
          ExitProcess(31);
      } else {
        keep(&r, a);
        r.h = keep(&r, b);
      }
      break;
    }
    case 11:
      r.h = keep(&r, CreateEventW(NULL, TRUE, FALSE, NULL));
      break;
    case 12:
      r.h = (HANDLE)(uintptr_t)0x1234;
      break;
    case 13:
      r.h = GetCurrentProcess();
      break;
    case 14:
      r.h = GetCurrentThread();
      break;
    }
  return r;
}
static void release(Resource *r) {
  for (unsigned i = 0; i < r->count; ++i)
    if (!CloseHandle(r->owned[i]))
      ExitProcess(32);
  if (r->file && !DeleteFileW(L"read-v1.bin"))
    ExitProcess(33);
  if (r->directory && !RemoveDirectoryW(L"read-dir-v1"))
    ExitProcess(34);
}
static void position(HANDLE h) {
  __declspec(align(16)) unsigned char data[8];
  IoStatus io;
  memset(data, 0xa5, sizeof data);
  memset(&io, 0xa5, sizeof io);
  LONG s = query_file(h, &io, data, 8, 14);
  if (s == 0x103)
    ExitProcess(35);
  control_print("[%lu,", (unsigned long)(ULONG)s);
  hex(data, sizeof data);
  control_char(']');
}
static void observe(unsigned role, unsigned off, unsigned length) {
  Resource r = acquire(role);
  HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL);
  if (!event)
    ExitProcess(36);
  __declspec(align(16)) unsigned char buffer[32];
  IoStatus io;
  LARGE_INTEGER offset;
  offset.QuadPart = offsets[off];
  memset(buffer, 0xa5, sizeof buffer);
  memset(&io, 0xa5, sizeof io);
  SetLastError(0x6a1b2c3d);
  LONG initial = read_file(r.h, event, NULL, NULL, &io, buffer, length,
                           off == 0 ? NULL : &offset, NULL);
  DWORD error = GetLastError();
  BOOL pending = initial == 0x103;
  DWORD wait = WaitForSingleObject(event, pending ? 5000 : 0);
  if (pending && wait != WAIT_OBJECT_0) {
    CancelIoEx(r.h, NULL);
    WaitForSingleObject(event, 5000);
    ExitProcess(37);
  }
  control_print(
      "{\"role\":\"%s\",\"offset_case\":%u,\"length\":%u,\"initial_status\":%"
      "lu,\"pending\":%u,\"event_wait\":%lu,\"last_error\":%lu,\"io\":",
      roles[role], off, length, (unsigned long)(ULONG)initial,
      (unsigned)pending, (unsigned long)wait, (unsigned long)error);
  hex(&io, sizeof io);
  control_text(",\"buffer\":");
  hex(buffer, sizeof buffer);
  control_text(",\"position\":");
  position(r.h);
  if (r.parent) {
    control_text(",\"parent_position\":");
    position(r.parent);
  }
  if (r.other) {
    control_text(",\"independent_position\":");
    position(r.other);
  }
  control_text("}\n");
  if (!CloseHandle(event))
    ExitProcess(38);
  release(&r);
}
void entry(void) {
  control_sink = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD kind = GetFileType(control_sink);
  if (kind != FILE_TYPE_PIPE && kind != FILE_TYPE_DISK)
    ExitProcess(39);
  // Detach only this disposable probe process, then allocate its own console.
  // All injected input and all console reads belong to this fresh console.
  FreeConsole();
  if (!AllocConsole())
    ExitProcess(40);
  DWORD processes[4];
  DWORD count = GetConsoleProcessList(processes, 4);
  if (count != 1 || processes[0] != GetCurrentProcessId())
    ExitProcess(41);
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  read_file = (ReadFn)(uintptr_t)GetProcAddress(module, "NtReadFile");
  query_file = (InformationFn)(uintptr_t)GetProcAddress(
      module, "NtQueryInformationFile");
  if (!read_file || !query_file)
    ExitProcess(42);
  control_print("{\"schema\":\"rax-native-file-read-scalars-v1\",\"pointer_"
                "bytes\":%zu,\"read_leaf\":",
                sizeof(void *));
  hex((const void *)(uintptr_t)read_file, 64);
  control_text("}\n");
  for (unsigned role = 0; role < sizeof roles / sizeof roles[0]; ++role) {
    Resource r = acquire(role);
    release(&r);
  }
  DWORD before, after;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    ExitProcess(43);
  unsigned rows = 0;
  for (unsigned role = 0; role < sizeof roles / sizeof roles[0]; ++role)
    for (unsigned off = 0; off < sizeof offsets / sizeof offsets[0]; ++off)
      for (unsigned len = 0; len < sizeof lengths / sizeof lengths[0]; ++len) {
        observe(role, off, lengths[len]);
        ++rows;
      }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    ExitProcess(44);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"rows\":%u}\n",
                (unsigned long)before, (unsigned long)after, rows);
  control_flush();
  FreeConsole();
  ExitProcess(0);
}
