/* Independent current-process NT/Win32 cache controls. No generated code runs.
 */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

typedef LONG(NTAPI *Flush)(HANDLE, const void *, SIZE_T);
typedef ULONG(NTAPI *DosError)(LONG);
typedef LONG(NTAPI *QueryObject)(HANDLE, ULONG, void *, ULONG, ULONG *);

typedef struct {
  const char *kind;
  HANDLE value;
  DWORD requested, granted, tag, query_status, query_bytes;
  BOOL owned;
} Handle;

static Handle handles[64];
static unsigned handle_count;
static BYTE *pages, *reserved, *hole;
static Flush flush;
static DosError dos;
static QueryObject query_object;
static const DWORD guard_offsets[] = {12288, 24576, 28672};
#if defined(_WIN64)
#define USER_PROBE ((uintptr_t)0x7fffffff0000ULL)
#else
#define USER_PROBE ((uintptr_t)0x7fff0000)
#endif

__declspec(noreturn) static void fail(unsigned code) { ExitProcess(code); }

static void add(const char *kind, HANDLE value, DWORD requested, DWORD tag,
                BOOL owned) {
  __declspec(align(8)) BYTE basic[56] = {0};
  ULONG returned = 0;
  DWORD granted = 0, status = 0;
  if (handle_count == sizeof(handles) / sizeof(handles[0]))
    fail(11);
  if (owned || tag != 0) {
    status = (DWORD)query_object(value, 0, basic, sizeof(basic), &returned);
    if (status == 0)
      CopyMemory(&granted, basic + sizeof(DWORD), sizeof(granted));
  }
  handles[handle_count++] =
      (Handle){kind, value, requested, granted, tag, status, returned, owned};
}

static void prepare_handles(void) {
  static const DWORD rights[] = {
      0,      1,       2,       4,       8,       0x10,     0x20,
      0x40,   0x80,    0x100,   0x200,   0x400,   0x800,    0x1000,
      0x2000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x1fffff};
  HANDLE process = GetCurrentProcess(), value = NULL;
  add("pseudo_process", process, 0, 0, FALSE);
  add("null", NULL, 0, 0, FALSE);
  add("pseudo_thread", GetCurrentThread(), 0, 0, FALSE);
  add("invalid", (HANDLE)(uintptr_t)0x10000000, 0, 0, FALSE);
  value = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!value)
    fail(13);
  add("event", value, EVENT_ALL_ACCESS, 0, TRUE);
  if (!DuplicateHandle(process, GetCurrentThread(), process, &value, 0, FALSE,
                       DUPLICATE_SAME_ACCESS))
    fail(14);
  add("thread", value, 0, 0, TRUE);
  for (unsigned i = 0; i < sizeof(rights) / sizeof(rights[0]); i++) {
    if (!DuplicateHandle(process, process, process, &value, rights[i], FALSE,
                         0))
      fail(15);
    add("process", value, rights[i], 0, TRUE);
    if (rights[i] == 0x1fffff) {
      for (DWORD tag = 1; tag <= 3; tag++)
        add("process", (HANDLE)((uintptr_t)value | tag), rights[i], tag, FALSE);
#if defined(_WIN64)
      add("process_high_carrier",
          (HANDLE)((uintptr_t)value | ((uintptr_t)1 << 32)), rights[i], 0,
          FALSE);
#endif
    }
  }
  value = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!value || !CloseHandle(value))
    fail(16);
  add("closed", value, 0, 0, FALSE);
}

static const void *address(unsigned kind) {
  switch (kind) {
  case 0:
    return NULL;
  case 1:
    return (const void *)(uintptr_t)1;
  case 2:
    return pages + 128;
  case 3:
    return pages + 8192;
  case 4:
    return hole;
  case 5:
    return reserved;
  case 6:
    return pages + 12288;
  case 7:
    return pages + 20480;
  case 8:
    return pages + 16384;
  case 9:
    return pages + 8191;
  case 10:
    return (const void *)UINTPTR_MAX;
#if defined(_WIN64)
  case 11:
    return (const void *)(uintptr_t)0x7fffffff0000ULL;
  case 12:
    return (const void *)(uintptr_t)0x800000000000ULL;
  case 13:
    return (const void *)(uintptr_t)0x1000000000000ULL;
  case 14:
    return (const void *)(uintptr_t)0xffff800000000000ULL;
#else
  case 11:
    return (const void *)(uintptr_t)0x7fff0000;
  case 12:
    return (const void *)(uintptr_t)0x80000000;
  case 13:
    return (const void *)(uintptr_t)0xffff0000;
  case 14:
    return (const void *)(uintptr_t)0xfffffffe;
#endif
  case 15:
    return (const void *)(USER_PROBE - 1);
  case 16:
    return (const void *)(USER_PROBE - 2);
  case 17:
    return (const void *)(USER_PROBE - 64);
  case 18:
    return (const void *)(USER_PROBE - 4096);
  case 19:
    return pages + 16383;
  case 20:
    return pages + 24576;
  case 21:
    return pages + 28672;
  case 22:
    return pages + 12287;
  case 23:
    return pages + 24575;
  default:
    fail(17);
  }
}

static void prepare_memory(void) {
  DWORD old;
  pages = VirtualAlloc(NULL, 32768, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  reserved = VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_NOACCESS);
  hole = VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_NOACCESS);
  if (!pages || !reserved || !hole)
    fail(18);
  FillMemory(pages, 32768, 0xa5);
  if (!VirtualProtect(pages + 8192, 4096, PAGE_NOACCESS, &old) ||
      !VirtualProtect(pages + 16384, 4096, PAGE_EXECUTE_READ, &old) ||
      !VirtualProtect(pages + 20480, 4096, PAGE_READONLY, &old))
    fail(19);
}

int main(void) {
  static const SIZE_T lengths[] = {0,    1,     2,     63,    64,
                                   65,   4095,  4096,  4097,  8192,
                                   8193, 12288, 16384, 20480, UINTPTR_MAX};
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  FARPROC entry = GetProcAddress(ntdll, "NtFlushInstructionCache");
  flush = (Flush)entry;
  dos = (DosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
  query_object = (QueryObject)GetProcAddress(ntdll, "NtQueryObject");
  if (!flush || !dos || !query_object)
    fail(20);
  prepare_memory();
  prepare_handles();
  if (setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
      !VirtualFree(hole, 0, MEM_RELEASE))
    fail(28);
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    fail(21);
  printf("{\"schema\":\"rax-native-instruction-cache-v1\",\"pointer_bytes\":%u,"
         "\"entry_hex\":\"",
         (unsigned)sizeof(void *));
  for (unsigned i = 0; i < 64; i++)
    printf("%02x", (unsigned)((const BYTE *)entry)[i]);
  printf("\",\"handles\":[");
  for (unsigned i = 0; i < handle_count; i++) {
    Handle *h = &handles[i];
    printf("%s{\"kind\":\"%s\",\"requested\":%u,\"granted\":%u,\"tag\":%u,"
           "\"query_status\":%u,\"query_bytes\":%u}",
           i ? "," : "", h->kind, (unsigned)h->requested, (unsigned)h->granted,
           (unsigned)h->tag, (unsigned)h->query_status,
           (unsigned)h->query_bytes);
  }
  printf("],\"lengths_hex\":[");
  for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
    printf("%s\"0x%llx\"", i ? "," : "", (unsigned long long)lengths[i]);
  printf("],\"rows\":[");
  unsigned count = 0;
  for (unsigned h = 0; h < handle_count; h++) {
    for (unsigned kind = 0; kind <= 23; kind++) {
      for (unsigned size = 0; size < sizeof(lengths) / sizeof(lengths[0]);
           size++) {
        for (unsigned api = 0; api < 2; api++) {
          DWORD old = 0;
          MEMORY_BASIC_INFORMATION info;
          for (unsigned g = 0;
               g < sizeof(guard_offsets) / sizeof(guard_offsets[0]); g++) {
            if (!VirtualProtect(pages + guard_offsets[g], 4096,
                                PAGE_READWRITE | PAGE_GUARD, &old))
              fail(22);
          }
          SetLastError(0x12345678);
          DWORD result =
              api == 0
                  ? (DWORD)flush(handles[h].value, address(kind), lengths[size])
                  : (DWORD)FlushInstructionCache(handles[h].value,
                                                 address(kind), lengths[size]);
          DWORD last = GetLastError();
          DWORD error = api == 0 ? dos((LONG)result) : last;
          unsigned guards = 0;
          for (unsigned g = 0;
               g < sizeof(guard_offsets) / sizeof(guard_offsets[0]); g++) {
            if (VirtualQuery(pages + guard_offsets[g], &info, sizeof(info)) !=
                sizeof(info))
              fail(23);
            if (info.Protect & PAGE_GUARD)
              guards |= 1u << g;
          }
          printf("%s[%u,%u,%u,%u,%u,%u,%u,%u]", count ? "," : "", h, kind, size,
                 api, (unsigned)result, (unsigned)error, (unsigned)last,
                 guards);
          count++;
        }
      }
    }
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    fail(24);
  printf("],\"rows_count\":%u,\"handles_before\":%u,\"handles_after\":%u}\n",
         count, (unsigned)before, (unsigned)after);
  for (unsigned i = 0; i < handle_count; i++)
    if (handles[i].owned && !CloseHandle(handles[i].value))
      fail(25);
  if (!VirtualFree(pages, 0, MEM_RELEASE) ||
      !VirtualFree(reserved, 0, MEM_RELEASE))
    fail(26);
  return ferror(stdout) ? 27 : 0;
}
