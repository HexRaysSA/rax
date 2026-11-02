#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <vector>
#include <windows.h>
#include <winternl.h>

// Read fixed existing keys. Only a duplicated private token is adjusted.
using OpenEx = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, ULONG);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using QueryValue = LONG(NTAPI *)(HANDLE, UNICODE_STRING *, ULONG, void *, ULONG,
                                 ULONG *);
using Close = LONG(NTAPI *)(HANDLE);
static OpenEx open_ex;
static Query query_key;
static Query query_object;
static QueryValue query_value;
static Close close_key;

static void hex(const void *pointer, ULONG length) {
  auto p = static_cast<const unsigned char *>(pointer);
  for (ULONG i = 0; i < length; ++i)
    printf("%02x", p[i]);
}
static UNICODE_STRING name(wchar_t *text) {
  UNICODE_STRING result{};
  result.Buffer = text;
  result.Length = USHORT(wcslen(text) * 2);
  result.MaximumLength = result.Length + 2;
  return result;
}
static ULONG privilege(HANDLE token, ULONG luid) {
  DWORD bytes = 0;
  GetTokenInformation(token, TokenPrivileges, nullptr, 0, &bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0 ||
      bytes > 65536)
    ExitProcess(10);
  std::vector<unsigned char> buffer(bytes);
  if (!GetTokenInformation(token, TokenPrivileges, buffer.data(), bytes,
                           &bytes))
    ExitProcess(11);
  auto privileges = reinterpret_cast<const TOKEN_PRIVILEGES *>(buffer.data());
  if (sizeof(DWORD) + privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES) >
      bytes)
    ExitProcess(12);
  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
    if (privileges->Privileges[i].Luid.HighPart == 0 &&
        privileges->Privileges[i].Luid.LowPart == luid)
      return privileges->Privileges[i].Attributes;
  return 0xFFFFFFFF;
}
static void observe(unsigned profile, unsigned path, ULONG options,
                    ULONG access, ULONG view) {
  wchar_t codepage[] =
      L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
  wchar_t control[] = L"\\Registry\\Machine\\System\\CurrentControlSet";
  auto text = name(path == 0 ? codepage : control);
  OBJECT_ATTRIBUTES attrs{};
  attrs.Length = sizeof(attrs);
  attrs.Attributes = 0x40;
  attrs.ObjectName = &text;
  HANDLE key = nullptr;
  SetLastError(0x12345678);
  LONG status = open_ex(&key, access | view, &attrs, options);
  DWORD error = GetLastError();
  ULONG basic[14]{}, basic_length = 0;
  ULONG key_name[1024]{}, name_length = 0;
  ULONG value[1024]{}, value_length = 0;
  LONG basic_status = LONG(0xE0000001), name_status = basic_status,
       value_status = basic_status;
  if (status >= 0) {
    basic_status = query_object(key, 0, basic, sizeof(basic), &basic_length);
    name_status = query_key(key, 3, key_name, sizeof(key_name), &name_length);
    wchar_t symbolic[] = L"SymbolicLinkValue";
    auto value_name = name(symbolic);
    value_status =
        query_value(key, &value_name, 2, value, sizeof(value), &value_length);
    if (basic_status != 0 || name_status != 0 || name_length > sizeof(key_name))
      ExitProcess(13);
    if (close_key(key) < 0)
      ExitProcess(14);
  }
  printf(
      "{\"kind\":\"open_profile\",\"profile\":%u,\"path\":%u,\"options\":%lu,"
      "\"access\":%lu,\"view\":%lu,\"status\":%lu,\"last_error\":%lu,\"basic_"
      "status\":%lu,\"granted_access\":%lu,\"name_status\":%lu,\"name\":\"",
      profile, path, options, access, view, ULONG(status), error,
      ULONG(basic_status), basic[1], ULONG(name_status));
  if (name_status == 0)
    hex(key_name, name_length);
  printf("\",\"value_status\":%lu,\"value\":\"", ULONG(value_status));
  if (value_status == 0) {
    if (value_length > sizeof(value))
      ExitProcess(15);
    hex(value, value_length);
  }
  printf("\"}\n");
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  open_ex = reinterpret_cast<OpenEx>(GetProcAddress(ntdll, "NtOpenKeyEx"));
  query_key = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryKey"));
  query_object =
      reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryObject"));
  query_value =
      reinterpret_cast<QueryValue>(GetProcAddress(ntdll, "NtQueryValueKey"));
  close_key = reinterpret_cast<Close>(GetProcAddress(ntdll, "NtClose"));
  if (!open_ex || !query_key || !query_object || !query_value || !close_key)
    return 1;
  USHORT pm = 0, nm = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &pm, &nm))
    return 2;
  HANDLE original = nullptr, controlled = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
                        &original))
    return 3;
  if (!DuplicateTokenEx(original, TOKEN_ALL_ACCESS, nullptr,
                        SecurityImpersonation, TokenImpersonation, &controlled))
    return 4;
  ULONG before_backup = privilege(original, 17),
        before_restore = privilege(original, 18);
  printf("{\"kind\":\"machine\",\"pointer_bytes\":%zu,\"native_machine\":%u,"
         "\"process_machine\":%u,\"original_backup\":%lu,\"original_restore\":%"
         "lu}\n",
         sizeof(void *), nm, pm, before_backup, before_restore);
  for (unsigned profile = 0; profile < 4; ++profile) {
    struct {
      DWORD count;
      LUID_AND_ATTRIBUTES values[2];
    } adjustment{};
    adjustment.count = 2;
    for (unsigned i = 0; i < 2; ++i) {
      adjustment.values[i].Luid.LowPart = 17 + i;
      adjustment.values[i].Attributes =
          profile & (1u << i) ? SE_PRIVILEGE_ENABLED : 0;
    }
    SetLastError(0);
    if (!AdjustTokenPrivileges(
            controlled, FALSE,
            reinterpret_cast<TOKEN_PRIVILEGES *>(&adjustment), 0, nullptr,
            nullptr))
      return 5;
    DWORD adjusted = GetLastError();
    if (!SetThreadToken(nullptr, controlled))
      return 6;
    printf("{\"kind\":\"privileges\",\"profile\":%u,\"adjust_error\":%lu,"
           "\"backup\":%lu,\"restore\":%lu}\n",
           profile, adjusted, privilege(controlled, 17),
           privilege(controlled, 18));
    for (unsigned path = 0; path < 2; ++path)
      for (ULONG options : {0ul, 4ul, 8ul, 12ul, 16ul, 20ul, 24ul, 28ul})
        for (ULONG access : {0ul, 1ul, 2ul, 8ul, 16ul, 0x20000ul, 0x20019ul,
                             0x80000000ul, 0x02000000ul, 0xF003Ful})
          for (ULONG view : {0ul, 0x100ul, 0x200ul, 0x300ul})
            observe(profile, path, options, access, view);
    if (!RevertToSelf())
      return 7;
  }
  if (privilege(original, 17) != before_backup ||
      privilege(original, 18) != before_restore)
    return 8;
  if (!CloseHandle(controlled) || !CloseHandle(original))
    return 9;
  return 0;
}
