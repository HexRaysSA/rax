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
  auto n = GetModuleHandleW(L"ntdll.dll");
  query_key = reinterpret_cast<QueryKey>(GetProcAddress(n, "NtQueryKey"));
  auto open_key = reinterpret_cast<OpenKey>(GetProcAddress(n, "NtOpenKey"));
  auto close = reinterpret_cast<Close>(GetProcAddress(n, "NtClose"));
  if (!query_key || !open_key || !close)
    return 1;
  USHORT pm = 0, nm = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &pm, &nm))
    return 2;
  printf("{\"kind\":\"machine\",\"pointer_bytes\":%zu,\"native_machine\":%u,"
         "\"process_machine\":%u}\n",
         sizeof(void *), nm, pm);
  wchar_t path[] = L"\\Registry\\User\\.DEFAULT";
  UNICODE_STRING name{};
  name.Buffer = path;
  name.Length = USHORT(wcslen(path) * 2);
  name.MaximumLength = name.Length + 2;
  OBJECT_ATTRIBUTES attrs{};
  attrs.Length = sizeof(attrs);
  attrs.ObjectName = &name;
  attrs.Attributes = 0x240;
  const ULONG accesses[] = {1,       8,          0x10,     0x20000,
                            0x20019, 0x80000000, 0x2000000};
  const ULONG views[] = {0, 0x100, 0x200, 0x300};
  for (ULONG access : accesses)
    for (ULONG view : views) {
      HANDLE key = nullptr;
      LONG status = open_key(&key, access | view, &attrs);
      ULONG value = 0xA5A5A5A5, returned = 0xA5A5A5A5;
      LONG queried = status < 0 ? LONG(0xE0000001)
                                : query_key(key, 7, &value, 4, &returned);
      printf("{\"kind\":\"view\",\"access\":%lu,\"view\":%lu,\"open_status\":%"
             "lu,\"query_status\":%lu,\"tags\":%lu,\"returned\":%lu}\n",
             access, view, ULONG(status), ULONG(queried), value, returned);
      if (status >= 0) {
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), key, GetCurrentProcess(),
                             &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
          return 3;
        value = returned = 0xA5A5A5A5;
        queried = query_key(duplicate, 7, &value, 4, &returned);
        printf("{\"kind\":\"duplicate\",\"access\":%lu,\"view\":%lu,\"query_"
               "status\":%lu,\"tags\":%lu,\"returned\":%lu}\n",
               access, view, ULONG(queried), value, returned);
        if (close(duplicate) < 0 || close(key) < 0)
          return 4;
      }
    }
  return 0;
}
