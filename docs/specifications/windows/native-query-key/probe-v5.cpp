#include <cstdio>
#include <cstring>
#include <windows.h>
#include <winternl.h>

// Read-only fixed-key query; buffers, guards and handles belong to this probe.
using Open = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Close = LONG(NTAPI *)(HANDLE);
static Query query;
static LONG invoke(HANDLE key, void *out, ULONG length, ULONG *returned,
                   ULONG *exception) {
  __try {
    return query(key, 7, out, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *exception = GetExceptionCode();
    return LONG(0xE0000001);
  }
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  auto n = GetModuleHandleW(L"ntdll.dll");
  auto open = reinterpret_cast<Open>(GetProcAddress(n, "NtOpenKey"));
  query = reinterpret_cast<Query>(GetProcAddress(n, "NtQueryKey"));
  auto close = reinterpret_cast<Close>(GetProcAddress(n, "NtClose"));
  if (!open || !query || !close)
    return 1;
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  if (system.dwPageSize != 4096)
    return 2;
  auto pages = static_cast<unsigned char *>(
      VirtualAlloc(nullptr, 12288, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!pages)
    return 3;
  USHORT pm = 0, nm = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &pm, &nm))
    return 4;
  printf("{\"kind\":\"machine\",\"pointer_bytes\":%zu,\"native_machine\":%u,"
         "\"process_machine\":%u}\n",
         sizeof(void *), nm, pm);
  wchar_t path[] = L"\\Registry\\User\\.DEFAULT";
  UNICODE_STRING name{};
  name.Buffer = path;
  name.Length = USHORT(wcslen(path) * 2);
  name.MaximumLength = name.Length + 2;
  OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  attributes.ObjectName = &name;
  attributes.Attributes = 0x240;
  HANDLE key = nullptr;
  LONG opened = open(&key, 0x20019, &attributes);
  printf("{\"kind\":\"open\",\"status\":%lu}\n", ULONG(opened));
  if (opened < 0)
    return 5;
  const ULONG prefixes[] = {1,   3,   4,    5,    7,    9,    12,  20,
                            28,  36,  60,   68,   124,  132,  252, 260,
                            508, 516, 1020, 1028, 2044, 2052, 4092};
  const ULONG lengths[] = {0,   1,   2,   3,   4,   5,    7,    8,    9,
                           12,  15,  16,  17,  20,  24,   31,   32,   33,
                           40,  48,  63,  64,  65,  96,   127,  128,  129,
                           192, 255, 256, 257, 512, 1024, 2048, 4096, 8192};
  for (ULONG prefix : prefixes)
    for (ULONG length : lengths)
      for (unsigned guard = 0; guard < 2; ++guard)
        for (unsigned valid = 0; valid < 2; ++valid) {
          DWORD old;
          if (!VirtualProtect(pages, 12288, PAGE_READWRITE, &old))
            return 6;
          memset(pages, 0xA5, 12288);
          if (!VirtualProtect(
                  pages + 4096, 4096,
                  guard ? PAGE_READWRITE | PAGE_GUARD : PAGE_NOACCESS, &old))
            return 7;
          auto output = pages + 4096 - prefix;
          ULONG returned = 0xA5A5A5A5, exception = 0;
          SetLastError(0x12345678);
          LONG status = invoke(valid ? key : nullptr, output, length, &returned,
                               &exception);
          DWORD error = GetLastError();
          MEMORY_BASIC_INFORMATION region{};
          if (VirtualQuery(pages + 4096, &region, sizeof(region)) !=
              sizeof(region))
            return 8;
          if (!VirtualProtect(pages, 12288, PAGE_READWRITE, &old))
            return 9;
          printf("{\"kind\":\"copy_boundary\",\"prefix\":%lu,\"length\":%lu,"
                 "\"guard\":%u,\"valid\":%u,\"status\":%lu,\"exception\":%lu,"
                 "\"returned\":%lu,\"last_error\":%lu,\"page1_protect\":%lu,"
                 "\"head\":\"",
                 prefix, length, guard, valid, ULONG(status), exception,
                 returned, error, region.Protect);
          for (unsigned i = 0; i < 32; ++i)
            printf("%02x", output[i]);
          printf("\",\"boundary\":\"");
          for (unsigned i = 0; i < 64; ++i)
            printf("%02x", pages[4096 - 32 + i]);
          printf("\",\"page2\":\"");
          for (unsigned i = 0; i < 32; ++i)
            printf("%02x", pages[8192 + i]);
          printf("\"}\n");
        }
  if (close(key) < 0)
    return 10;
  VirtualFree(pages, 0, MEM_RELEASE);
  return 0;
}
