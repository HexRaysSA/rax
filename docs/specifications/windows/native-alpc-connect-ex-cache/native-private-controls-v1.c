#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

/* All connection names are unique private missing names or this process's event.
 * No call addresses a system-service port or another process's endpoint. */
typedef struct {
  ULONG Flags;
  SECURITY_QUALITY_OF_SERVICE SecurityQos;
  SIZE_T MaxMessageLength, MemoryBandwidth, MaxPoolUsage, MaxSectionSize,
      MaxViewSize, MaxTotalSectionSize;
  ULONG DupObjectTypes;
#if defined(_WIN64)
  ULONG Reserved;
#endif
} PortAttributes;
typedef LONG(NTAPI *ConnectEx)(PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
                             PortAttributes *, ULONG, PSECURITY_DESCRIPTOR,
                             void *, SIZE_T *, void *, void *, LARGE_INTEGER *);
typedef LONG(NTAPI *CreateEventFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG,
                               BOOLEAN);
typedef struct {
  HANDLE *out;
  OBJECT_ATTRIBUTES *connection, *client;
  PortAttributes *port;
  ULONG flags;
  PSECURITY_DESCRIPTOR security;
  void *message;
  SIZE_T *length;
  void *out_attributes, *in_attributes;
  LARGE_INTEGER *timeout;
} Arguments;

static ConnectEx connect_ex;
static BYTE *arena;
static HANDLE output;
static SIZE_T length;
static OBJECT_ATTRIBUTES connection;
static UNICODE_STRING name;
static PortAttributes port;
static __declspec(align(16)) BYTE message[128], receive_attributes[128];
static unsigned calls;

static void fail(unsigned code) { ExitProcess(code); }

static Arguments prepare(wchar_t *path) {
  DWORD old;
  if (!VirtualProtect(arena, 16384, PAGE_READWRITE, &old)) fail(11);
  ZeroMemory(arena, 16384);
  if (!VirtualProtect(arena + 4096, 4096, PAGE_READONLY, &old) ||
      !VirtualProtect(arena + 8192, 4096, PAGE_NOACCESS, &old) ||
      !VirtualProtect(arena + 12288, 4096, PAGE_READWRITE | PAGE_GUARD, &old))
    fail(12);
  ZeroMemory(&connection, sizeof(connection));
  name.Buffer = path;
  name.Length = (USHORT)(wcslen(path) * sizeof(wchar_t));
  name.MaximumLength = name.Length + sizeof(wchar_t);
  connection.Length = sizeof(connection);
  connection.ObjectName = &name;
  connection.Attributes = 0x40;
  ZeroMemory(&port, sizeof(port));
  port.Flags = 0x80000;
  port.SecurityQos.Length = sizeof(port.SecurityQos);
  port.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
  port.SecurityQos.EffectiveOnly = TRUE;
  port.MaxMessageLength = 80;
  port.MaxPoolUsage = port.MaxSectionSize = port.MaxViewSize =
      port.MaxTotalSectionSize = UINT32_MAX;
  port.DupObjectTypes = 0x80;
  ZeroMemory(message, sizeof(message));
  ZeroMemory(receive_attributes, sizeof(receive_attributes));
  *(USHORT *)(void *)message = 40;
#if defined(_WIN64)
  length = 80;
  *(ULONG *)(void *)(message + 48) = 7;
#else
  length = 64;
  *(ULONG *)(void *)(message + 32) = 7;
#endif
  *(USHORT *)(void *)(message + 2) = (USHORT)length;
  *(ULONG *)(void *)receive_attributes = 0x10000000;
  output = (HANDLE)(uintptr_t)0x51515151;
  return (Arguments){&output, &connection, NULL, &port, 0x20000, NULL,
                     message, &length, NULL, receive_attributes, NULL};
}

static void invoke(unsigned target, unsigned parameter, unsigned variant,
                   Arguments a) {
  DWORD status = 0xDEADBEEF, exception = 0;
  MEMORY_BASIC_INFORMATION information;
  __try {
    status = (DWORD)connect_ex(a.out, a.connection, a.client, a.port, a.flags,
                              a.security, a.message, a.length, a.out_attributes,
                              a.in_attributes, a.timeout);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  if (!VirtualQuery(arena + 12288, &information, sizeof(information))) fail(13);
  printf("CALL target=%u parameter=%u variant=%u flags=%08lX status=%08lX "
         "exception=%08lX out=%llu length=%llu guard=%u message=",
         target, parameter, variant, a.flags, status, exception,
         (unsigned long long)(uintptr_t)output, (unsigned long long)length,
         (unsigned)((information.Protect & PAGE_GUARD) != 0));
  for (unsigned i = 0; i < 80; ++i) printf("%02X", (unsigned)message[i]);
  printf(" attributes=");
  for (unsigned i = 0; i < 80; ++i) printf("%02X", (unsigned)receive_attributes[i]);
  putchar('\n');
  ++calls;
  /* Both private targets must fail. Preserve any unexpected kernel result in
   * stdout, close a returned handle if present, then stop the producer. */
  if (status < 0x80000000 && exception == 0) {
    if (output && output != (HANDLE)(uintptr_t)0x51515151) CloseHandle(output);
    fail(14);
  }
}

int main(void) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  CreateEventFn create_event = (CreateEventFn)GetProcAddress(ntdll, "NtCreateEvent");
  connect_ex = (ConnectEx)GetProcAddress(ntdll, "NtAlpcConnectPortEx");
  if (!create_event || !connect_ex || setvbuf(stdout, NULL, _IONBF, 0)) fail(15);
  arena = VirtualAlloc(NULL, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!arena) fail(16);
  wchar_t paths[2][160];
  for (unsigned i = 0; i < 2; ++i)
    if (swprintf_s(paths[i], 160, L"\\BaseNamedObjects\\assist-alpc-ex-%lu-%llu-%u",
                   GetCurrentProcessId(), GetTickCount64(), i) < 0) fail(17);
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) fail(18);
  Arguments baseline = prepare(paths[1]);
  HANDLE event = NULL;
  LONG created = create_event(&event, EVENT_ALL_ACCESS, baseline.connection, 0, FALSE);
  printf("PROFILE pointer_bytes=%zu port_attributes_bytes=%zu object_attributes_bytes=%zu "
         "entry=", sizeof(void *), sizeof(port), sizeof(connection));
  for (unsigned i = 0; i < 32; ++i)
    printf("%02X", ((const BYTE *)(uintptr_t)connect_ex)[i]);
  printf("\nCREATE status=%08lX owned=%u\n", (DWORD)created, (unsigned)(event != NULL));
  if (created < 0 || !event) fail(19);
  static const ULONG flags[] = {0, 1, 2, 4, 0x10000, 0x20000, 0x40000,
                               0x80000, 0x100000, 0x200000, 0x80000000, UINT32_MAX};
  for (unsigned target = 0; target < 2; ++target) {
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
      Arguments a = prepare(paths[target]);
      a.flags = flags[i];
      invoke(target, 4, i, a);
    }
    for (unsigned parameter = 0; parameter < 11; ++parameter) {
      if (parameter == 4) continue;
      for (unsigned variant = 0; variant < 5; ++variant) {
        Arguments a = prepare(paths[target]);
        void *pointer = variant == 0 ? NULL : variant == 1 ? arena + 4096 :
                        variant == 2 ? arena + 8192 : variant == 3 ? arena + 12288 :
                        (void *)(uintptr_t)UINTPTR_MAX;
        switch (parameter) {
        case 0: a.out = pointer; break;
        case 1: a.connection = pointer; break;
        case 2: a.client = pointer; break;
        case 3: a.port = pointer; break;
        case 5: a.security = pointer; break;
        case 6: a.message = pointer; break;
        case 7: a.length = pointer; break;
        case 8: a.out_attributes = pointer; break;
        case 9: a.in_attributes = pointer; break;
        case 10: a.timeout = pointer; break;
        default: fail(20);
        }
        invoke(target, parameter, variant, a);
      }
    }
  }
  if (!CloseHandle(event) || !GetProcessHandleCount(GetCurrentProcess(), &after)) fail(21);
  if (!VirtualFree(arena, 0, MEM_RELEASE)) fail(22);
  printf("SUMMARY calls=%u handles_before=%lu handles_after=%lu\n", calls, before, after);
  return calls == 124 && before == after ? 0 : 23;
}
