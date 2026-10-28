#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <windows.h>
#include <winternl.h>

// Fixed existing keys and private pages/handles only. No registry writes.
using Open = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using OpenEx = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, ULONG);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Close = LONG(NTAPI *)(HANDLE);
using Current = LONG(NTAPI *)(ACCESS_MASK, HANDLE *);
static Open open_key;
static OpenEx open_ex;
static Query query_key;
static Query query_object;
static Close close_key;
static unsigned char *pages;
static ULONG page_size;
static HANDLE current_user;
static HANDLE wrong_type;
static unsigned case_ordinal;

static DWORD protection() {
  MEMORY_BASIC_INFORMATION i{};
  return VirtualQuery(pages + page_size, &i, sizeof(i)) == sizeof(i) ? i.Protect
                                                                     : 0;
}
static LONG invoke(bool extended, HANDLE *out, ULONG access,
                   OBJECT_ATTRIBUTES *attrs, ULONG options, ULONG *exception) {
  __try {
    return extended ? open_ex(out, access, attrs, options)
                    : open_key(out, access, attrs);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *exception = GetExceptionCode();
    return LONG(0xE0000001);
  }
}
static void hex(const unsigned char *p, unsigned n) {
  for (unsigned i = 0; i < n; ++i)
    printf("%02x", p[i]);
}
static void observe(bool extended, ULONG options, unsigned role, ULONG access,
                    unsigned path_kind) {
  DWORD old;
  VirtualProtect(pages, page_size * 3, PAGE_READWRITE, &old);
  memset(pages, 0xA5, page_size * 3);
  auto out = reinterpret_cast<HANDLE *>(pages + 128);
  auto attrs = reinterpret_cast<OBJECT_ATTRIBUTES *>(pages + 256);
  auto name = reinterpret_cast<UNICODE_STRING *>(pages + 384);
  auto text = reinterpret_cast<wchar_t *>(pages + 512);
  const wchar_t *paths[] = {
      L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage",
      L"Software\\Policies\\Microsoft\\Windows\\System",
      L"Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System",
      L"Software\\Policies\\Microsoft\\Windows\\RaxMissing4275878552"};
  wcscpy_s(text, 512, paths[path_kind]);
  *name = {};
  name->Buffer = text;
  name->Length = USHORT(wcslen(text) * 2);
  name->MaximumLength = name->Length + 2;
  *attrs = {};
  attrs->Length = sizeof(*attrs);
  attrs->Attributes = 0x40;
  attrs->ObjectName = name;
  attrs->RootDirectory = path_kind == 0 ? nullptr : current_user;
  switch (role) {
  case 1:
    out = nullptr;
    break;
  case 2:
    out = reinterpret_cast<HANDLE *>(1);
    break;
  case 3:
    out = reinterpret_cast<HANDLE *>(pages + 129);
    break;
  case 4:
  case 5:
    out = reinterpret_cast<HANDLE *>(pages + page_size);
    VirtualProtect(out, page_size,
                   role == 4 ? PAGE_READONLY : PAGE_READWRITE | PAGE_GUARD,
                   &old);
    break;
  case 6:
  case 7:
    out = reinterpret_cast<HANDLE *>(pages + page_size - (role == 6 ? 1 : 4));
    VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS, &old);
    break;
  case 8:
    attrs = nullptr;
    break;
  case 9:
    attrs = reinterpret_cast<OBJECT_ATTRIBUTES *>(1);
    break;
  case 10:
    memmove(pages + 257, attrs, sizeof(*attrs));
    attrs = reinterpret_cast<OBJECT_ATTRIBUTES *>(pages + 257);
    break;
  case 11:
    attrs->Length = 0;
    break;
  case 12:
    attrs->Length = sizeof(*attrs) - 1;
    break;
  case 13:
    attrs->Attributes = 0x80000000;
    break;
  case 14:
    attrs->ObjectName = nullptr;
    break;
  case 15:
    attrs->ObjectName = reinterpret_cast<UNICODE_STRING *>(1);
    break;
  case 16:
    name->Length |= 1;
    break;
  case 17:
    name->Buffer = nullptr;
    break;
  case 18:
    name->Buffer = reinterpret_cast<wchar_t *>(1);
    break;
  case 19:
    attrs->RootDirectory = reinterpret_cast<HANDLE *>(0xDEADBEE0);
    break;
  case 20:
    attrs->RootDirectory = wrong_type;
    break;
  case 21:
    out = reinterpret_cast<HANDLE *>(attrs);
    break;
  case 22:
    out = reinterpret_cast<HANDLE *>(name);
    break;
  case 23:
    out = reinterpret_cast<HANDLE *>(text);
    break;
  case 24:
    attrs = nullptr;
    out = nullptr;
    break;
  case 25:
    attrs->Length = 0;
    out = nullptr;
    break;
  case 26:
    name->Length |= 1;
    out = nullptr;
    break;
  case 27:
  case 28:
    memcpy(pages + page_size, attrs, sizeof(*attrs));
    attrs = reinterpret_cast<OBJECT_ATTRIBUTES *>(pages + page_size);
    VirtualProtect(pages + page_size, page_size,
                   role == 27 ? PAGE_NOACCESS : PAGE_READWRITE | PAGE_GUARD,
                   &old);
    break;
  case 29:
    attrs->SecurityDescriptor = reinterpret_cast<void *>(1);
    break;
  }
  DWORD handle_before = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handle_before))
    ExitProcess(8);
  ULONG exception = 0;
  SetLastError(0x12345678);
  LONG status = invoke(extended, out, access, attrs, options, &exception);
  DWORD last_error = GetLastError();
  DWORD guard_after = protection();
  VirtualProtect(pages, page_size * 3, PAGE_READWRITE, &old);
  ULONG tags = 0xA5A5A5A5, returned = 0xA5A5A5A5;
  ULONG basic[14]{};
  ULONG basic_returned = 0xA5A5A5A5;
  LONG basic_status = LONG(0xE0000001);
  LONG query_status = LONG(0xE0000001);
  if (status >= 0 && exception == 0) {
    HANDLE key;
    memcpy(&key, out, sizeof(key));
    query_status = query_key(key, 7, &tags, sizeof(tags), &returned);
    basic_status = query_object(key, 0, basic, sizeof(basic), &basic_returned);
    if (close_key(key) < 0)
      ExitProcess(7);
  }
  DWORD handle_after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handle_after))
    ExitProcess(9);
  printf("{\"kind\":\"open\",\"extended\":%u,\"options\":%lu,\"role\":%u,"
         "\"access\":%lu,\"path_kind\":%u,\"status\":%lu,\"exception\":%lu,"
         "\"last_error\":%lu,\"page1_protect\":%lu,\"query_status\":%lu,"
         "\"tags\":%lu,\"returned\":%lu,\"basic_status\":%lu,\"granted_"
         "access\":%lu,\"output\":\"",
         unsigned(extended), options, role, access, path_kind, ULONG(status),
         exception, last_error, guard_after, ULONG(query_status), tags,
         returned, ULONG(basic_status), basic[1]);
  hex(pages + 128, 24);
  printf("\",\"attributes\":\"");
  hex(pages + 256, 64);
  printf("\",\"name\":\"");
  hex(pages + 384, 24);
  printf("\",\"boundary\":\"");
  hex(pages + page_size - 8, 24);
  printf("\"}\n");
  printf("{\"kind\":\"handle_delta\",\"ordinal\":%u,\"before\":%lu,\"after\":%"
         "lu}\n",
         case_ordinal++, handle_before, handle_after);
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  auto module = GetModuleHandleW(L"ntdll.dll");
  open_key = reinterpret_cast<Open>(GetProcAddress(module, "NtOpenKey"));
  open_ex = reinterpret_cast<OpenEx>(GetProcAddress(module, "NtOpenKeyEx"));
  query_key = reinterpret_cast<Query>(GetProcAddress(module, "NtQueryKey"));
  query_object =
      reinterpret_cast<Query>(GetProcAddress(module, "NtQueryObject"));
  close_key = reinterpret_cast<Close>(GetProcAddress(module, "NtClose"));
  auto current =
      reinterpret_cast<Current>(GetProcAddress(module, "RtlOpenCurrentUser"));
  if (!open_key || !open_ex || !query_key || !query_object || !close_key ||
      !current)
    return 1;
  USHORT pm = 0, nm = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &pm, &nm))
    return 2;
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  page_size = system.dwPageSize;
  pages = static_cast<unsigned char *>(VirtualAlloc(
      nullptr, page_size * 3, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  wrong_type = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!pages || !wrong_type || current(0x20019, &current_user) < 0)
    return 3;
  printf(
      "{\"kind\":\"machine\",\"pointer_bytes\":%zu,\"native_machine\":%u,"
      "\"process_machine\":%u,\"page_bytes\":%lu,\"memory_base\":%llu,\"root_"
      "handle\":%llu,\"wrong_type_handle\":%llu}\n",
      sizeof(void *), nm, pm, page_size,
      static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(pages)),
      static_cast<unsigned long long>(
          reinterpret_cast<uintptr_t>(current_user)),
      static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(wrong_type)));
  const ULONG options[] = {0,  1,  2,  3,  4,  5,  8,          12,
                           16, 20, 24, 28, 32, 64, 0x80000000, 0xFFFFFFFF};
  for (bool extended : {false, true}) {
    for (ULONG option : options)
      for (unsigned role = 0; role < 30; ++role)
        observe(extended, option, role, 0x20019, 0);
    for (ULONG option : {0ul, 4ul, 8ul, 16ul, 28ul, 1ul})
      for (ULONG access :
           {0ul, 1ul, 8ul, 0x20000ul, 0x20019ul, 0x80000000ul, 0x02000000ul})
        for (ULONG view : {0ul, 0x100ul, 0x200ul, 0x300ul})
          observe(extended, option, 0, access | view, 0);
    for (ULONG option : options)
      for (unsigned role = 0; role < 30; ++role) {
        observe(extended, option, role, 0x20019, 1);
        observe(extended, option, role, 0, 0);
      }
    for (unsigned path = 1; path <= 3; ++path)
      for (ULONG option : options)
        observe(extended, option, 0, 0x20019, path);
  }
  if (close_key(current_user) < 0 || !CloseHandle(wrong_type))
    return 4;
  if (!VirtualFree(pages, 0, MEM_RELEASE))
    return 5;
  return 0;
}
