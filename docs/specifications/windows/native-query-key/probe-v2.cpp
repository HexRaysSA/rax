#include <cstdio>
#include <cstring>
#include <windows.h>
#include <winternl.h>

// Only read/query operations on fixed existing registry keys and private
// handles.
using QueryKey = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using OpenKey = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using Close = LONG(NTAPI *)(HANDLE);
static QueryKey query_key;
static unsigned char *pages;
static ULONG page_size;

static DWORD protection(unsigned page) {
  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(pages + page * page_size, &info, sizeof(info)) !=
      sizeof(info))
    return 0;
  return info.Protect;
}
static LONG call(HANDLE key, ULONG cls, void *out, ULONG length,
                 ULONG *returned, ULONG *exception) {
  __try {
    return query_key(key, cls, out, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *exception = GetExceptionCode();
    return LONG(0xE0000001);
  }
}
static void observe(const char *label, HANDLE key, ULONG access, ULONG cls,
                    ULONG length, unsigned role) {
  DWORD old;
  VirtualProtect(pages, page_size * 3, PAGE_READWRITE, &old);
  memset(pages, 0xA5, page_size * 3);
  auto out = pages + 128;
  auto returned = reinterpret_cast<ULONG *>(pages + 64);
  switch (role) {
  case 1:
    out += 1;
    break;
  case 2:
    out = nullptr;
    break;
  case 3:
    out = reinterpret_cast<unsigned char *>(1);
    break;
  case 4:
    returned = nullptr;
    break;
  case 5:
    returned = reinterpret_cast<ULONG *>(1);
    break;
  case 6:
    returned = reinterpret_cast<ULONG *>(pages + 65);
    break;
  case 7:
    out = pages + page_size;
    VirtualProtect(out, page_size, PAGE_READONLY, &old);
    break;
  case 8:
    returned = reinterpret_cast<ULONG *>(pages + page_size);
    VirtualProtect(returned, page_size, PAGE_READONLY, &old);
    break;
  case 9:
    out = pages + page_size;
    VirtualProtect(out, page_size, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 10:
    returned = reinterpret_cast<ULONG *>(pages + page_size);
    VirtualProtect(returned, page_size, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 11:
    out = pages + page_size - 1;
    VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old);
    break;
  case 12:
    returned = reinterpret_cast<ULONG *>(pages + page_size - 1);
    VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old);
    break;
  case 13:
    out = pages + page_size - 4;
    VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old);
    break;
  case 14:
    returned = reinterpret_cast<ULONG *>(out);
    break;
  case 15:
    returned = reinterpret_cast<ULONG *>(out + 1);
    break;
  case 16:
    out = pages + page_size - 4;
    VirtualProtect(pages + page_size, page_size, PAGE_READWRITE | PAGE_GUARD,
                   &old);
    break;
  }
  ULONG exception = 0;
  SetLastError(0x12345678);
  LONG status = call(key, cls, out, length, returned, &exception);
  DWORD last_error = GetLastError();
  DWORD guard_after = protection(1);
  VirtualProtect(pages, page_size * 3, PAGE_READWRITE, &old);
  printf("{\"kind\":\"query\",\"handle\":\"%s\",\"access\":%lu,\"class\":%lu,"
         "\"length\":%lu,\"role\":%u,\"status\":%lu,\"exception\":%lu,\"last_"
         "error\":%lu,\"page1_protect\":%lu,\"output\":\"",
         label, access, cls, length, role, ULONG(status), exception, last_error,
         guard_after);
  for (unsigned i = 0; i < 32; ++i)
    printf("%02x", pages[128 + i]);
  printf("\",\"result\":\"");
  for (unsigned i = 0; i < 16; ++i)
    printf("%02x", pages[64 + i]);
  printf("\",\"boundary\":\"");
  for (unsigned i = 0; i < 16; ++i)
    printf("%02x", pages[page_size - 8 + i]);
  printf("\"}\n");
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  HMODULE n = GetModuleHandleW(L"ntdll.dll");
  query_key = reinterpret_cast<QueryKey>(GetProcAddress(n, "NtQueryKey"));
  auto open_key = reinterpret_cast<OpenKey>(GetProcAddress(n, "NtOpenKey"));
  auto close = reinterpret_cast<Close>(GetProcAddress(n, "NtClose"));
  if (!query_key || !open_key || !close)
    return 1;
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  page_size = system.dwPageSize;
  if (page_size != 4096)
    return 2;
  pages = static_cast<unsigned char *>(VirtualAlloc(
      nullptr, page_size * 3, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!pages)
    return 3;
  USHORT process_machine = 0, native_machine = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    return 4;
  printf("{\"kind\":\"machine\",\"pointer_bytes\":%zu,\"native_machine\":%u,"
         "\"process_machine\":%u}\n",
         sizeof(void *), native_machine, process_machine);
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
  LONG opened = open_key(&key, 0x20019, &attributes);
  printf("{\"kind\":\"open\",\"status\":%lu}\n", ULONG(opened));
  if (opened < 0)
    return 5;
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!event)
    return 6;
  const ULONG accesses[] = {0x20019, 0, 1, 8, 0x10, 0x20000};
  const ULONG lengths[] = {0, 1, 3, 4, 5, 8, 4096, 8193};
  const ULONG classes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xffffffff};
  for (unsigned handle_case = 0; handle_case < 12; ++handle_case) {
    HANDLE current = key;
    ULONG access = 0x20019;
    char label[32];
    if (handle_case < 6) {
      access = accesses[handle_case];
      if (!DuplicateHandle(GetCurrentProcess(), key, GetCurrentProcess(),
                           &current, access, FALSE, 0))
        return 7;
      sprintf_s(label, "access-%lx", access);
    } else {
      switch (handle_case) {
      case 6:
        current = nullptr;
        break;
      case 7:
        current = reinterpret_cast<HANDLE>(ULONG_PTR(0xdeadbee0));
        break;
      case 8:
        current = GetCurrentProcess();
        break;
      case 9:
        current = GetCurrentThread();
        break;
      case 10:
        current = event;
        break;
      case 11:
        current = reinterpret_cast<HANDLE>(ULONG_PTR(key) | 3);
        break;
      }
      sprintf_s(label, "special-%u", handle_case);
    }
    for (ULONG length : lengths) {
      for (unsigned role = 0; role < 17; ++role)
        observe(label, current, access, 7, length, role);
      for (ULONG cls : classes)
        if (cls != 7)
          observe(label, current, access, cls, length, 0);
    }
    if (handle_case < 6 && close(current) < 0)
      return 8;
  }
  if (close(event) < 0 || close(key) < 0)
    return 9;
  VirtualFree(pages, 0, MEM_RELEASE);
  return 0;
}
