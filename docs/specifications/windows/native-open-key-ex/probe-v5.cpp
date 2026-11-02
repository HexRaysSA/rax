#include <cstdio>
#include <cstring>
#include <filesystem>
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
    ULONG tags = 0xA5A5A5A5, returned = 0xA5A5A5A5;
    LONG tagged = query_key(key, 7, &tags, sizeof(tags), &returned);
    printf("{\"kind\":\"profile_tags\",\"profile\":%u,\"path\":%u,\"options\":%"
           "lu,\"access\":%lu,\"view\":%lu,\"status\":%lu,\"tags\":%lu,"
           "\"returned\":%lu}\n",
           profile, path, options, access, view, ULONG(tagged), tags, returned);
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

static void controlled_link() {
  wchar_t executable[32768]{};
  DWORD count = GetModuleFileNameW(nullptr, executable, 32768);
  if (count == 0 || count >= 32768)
    ExitProcess(20);
  auto path =
      std::filesystem::path(executable).parent_path() / L"link-fixture.hiv";
  if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
    ExitProcess(21);
  HKEY hive = nullptr, target = nullptr, source = nullptr;
  LONG loaded = RegLoadAppKeyW(path.c_str(), &hive, KEY_ALL_ACCESS,
                               REG_PROCESS_APPKEY, 0);
  printf("{\"kind\":\"link_fixture_load\",\"status\":%ld}\n", loaded);
  if (loaded != ERROR_SUCCESS)
    ExitProcess(22);
  DWORD disposition = 0, marker = 42;
  LONG created = RegCreateKeyExW(hive, L"Target", 0, nullptr, 0, KEY_ALL_ACCESS,
                                 nullptr, &target, &disposition);
  if (created != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY)
    ExitProcess(23);
  if (RegSetValueExW(target, L"Marker", 0, REG_DWORD,
                     reinterpret_cast<const BYTE *>(&marker),
                     sizeof(marker)) != ERROR_SUCCESS)
    ExitProcess(24);
  ULONG target_name[1024]{}, target_length = 0;
  LONG named =
      query_key(target, 3, target_name, sizeof(target_name), &target_length);
  if (named != 0 || target_length > sizeof(target_name) ||
      target_name[0] + 4 > target_length || target_name[0] % 2)
    ExitProcess(25);
  created = RegCreateKeyExW(hive, L"Source", 0, nullptr, REG_OPTION_CREATE_LINK,
                            KEY_ALL_ACCESS, nullptr, &source, &disposition);
  printf("{\"kind\":\"link_fixture_create\",\"status\":%ld,\"disposition\":%lu,"
         "\"target\":\"",
         created, disposition);
  hex(target_name, target_length);
  printf("\"}\n");
  if (created != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY)
    ExitProcess(26);
  for (unsigned nul = 0; nul < 2; ++nul) {
    LONG assigned =
        RegSetValueExW(source, L"SymbolicLinkValue", 0, REG_LINK,
                       reinterpret_cast<const BYTE *>(target_name + 1),
                       target_name[0] + nul * 2);
    printf("{\"kind\":\"link_fixture_set\",\"nul\":%u,\"status\":%ld}\n", nul,
           assigned);
    if (assigned != ERROR_SUCCESS)
      continue;
    for (ULONG option : {0ul, 8ul, 16ul, 24ul}) {
      wchar_t relative[] = L"Source";
      auto text = name(relative);
      OBJECT_ATTRIBUTES attrs{};
      attrs.Length = sizeof(attrs);
      attrs.RootDirectory = hive;
      attrs.ObjectName = &text;
      attrs.Attributes = 0x40;
      HANDLE key = nullptr;
      LONG opened = open_ex(&key, 0x20019, &attrs, option);
      ULONG named_key[1024]{}, named_bytes = 0, value[1024]{}, value_bytes = 0;
      LONG named_status = LONG(0xE0000001), value_status = named_status;
      if (opened >= 0) {
        named_status =
            query_key(key, 3, named_key, sizeof(named_key), &named_bytes);
        wchar_t variable[] = L"SymbolicLinkValue";
        auto v = name(variable);
        value_status =
            query_value(key, &v, 2, value, sizeof(value), &value_bytes);
        if (close_key(key) < 0)
          ExitProcess(27);
      }
      printf("{\"kind\":\"link_fixture_open\",\"nul\":%u,\"options\":%lu,"
             "\"status\":%lu,\"name_status\":%lu,\"name\":\"",
             nul, option, ULONG(opened), ULONG(named_status));
      if (named_status == 0) {
        if (named_bytes > sizeof(named_key))
          ExitProcess(28);
        hex(named_key, named_bytes);
      }
      printf("\",\"value_status\":%lu,\"value\":\"", ULONG(value_status));
      if (value_status == 0) {
        if (value_bytes > sizeof(value))
          ExitProcess(29);
        hex(value, value_bytes);
      }
      printf("\"}\n");
    }
  }
  if (RegCloseKey(source) != ERROR_SUCCESS ||
      RegCloseKey(target) != ERROR_SUCCESS ||
      RegCloseKey(hive) != ERROR_SUCCESS)
    ExitProcess(30);
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
  controlled_link();
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
