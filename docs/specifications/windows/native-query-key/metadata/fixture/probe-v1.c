/* NtQueryKey controls on four task-owned volatile registry fixture keys. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <winternl.h>

typedef LONG(NTAPI *QueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *Version)(PRTL_OSVERSIONINFOW);
static QueryKey query_key;
static int fixture_warmup;

static void hex(const unsigned char *p, size_t n) {
  static const char digits[] = "0123456789abcdef";
  char output[2048];
  if (n > sizeof output / 2)
    return;
  for (size_t i = 0; i < n; ++i) {
    output[2 * i] = digits[p[i] >> 4];
    output[2 * i + 1] = digits[p[i] & 15];
  }
  fwrite(output, 2, n, stdout);
}
static int identity(HMODULE module) {
  FARPROC function = GetProcAddress(module, "RtlGetVersion");
  Version version;
  if (!function || sizeof function != sizeof version)
    return 0;
  memcpy(&version, &function, sizeof version);
  RTL_OSVERSIONINFOW info = {0};
  info.dwOSVersionInfoSize = (ULONG)sizeof info;
  if (version(&info) != 0)
    return 0;
  USHORT process = 0, native = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &process, &native))
    return 0;
  WCHAR mapped[32768];
  DWORD units = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 32768);
  if (!units || units >= 32768)
    return 0;
  printf("{\"kind\":\"host\",\"schema\":\"rax-native-key-query-fixture-v2\","
         "\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],"
         "\"process_machine\":%u,\"native_machine\":%u,\"mapped_provider_"
         "utf16\":\"",
         sizeof(void *), info.dwMajorVersion, info.dwMinorVersion,
         info.dwBuildNumber, (unsigned)process, (unsigned)native);
  for (DWORD i = 0; i < units; ++i)
    printf("%02x%02x", (unsigned)(mapped[i] & 255), (unsigned)(mapped[i] >> 8));
  puts("\"}");
  return 1;
}
static int sample(HANDLE key, ULONG view, ULONG cls, ULONG length, int alias,
                  unsigned poison, unsigned long index, unsigned subject) {
  __declspec(align(16)) unsigned char bytes[1024];
  ULONG returned = 0x7f7f7f7f;
  memset(bytes, (int)poison, sizeof bytes);
  PULONG result = alias < 0 ? &returned : (PULONG)(bytes + alias);
  LONG status = query_key(key, cls, bytes, length, result);
  ULONG observed;
  memcpy(&observed, result, sizeof observed);
  if (fixture_warmup)
    return 1;
  printf("{\"kind\":\"case\",\"index\":%lu,\"subject\":%u,\"view\":%lu,"
         "\"class\":%lu,"
         "\"length\":%lu,\"alias\":%d,\"poison\":%u,\"status\":%lu,"
         "\"returned\":%lu,\"bytes\":\"",
         index, subject, view, cls, length, alias, poison, (ULONG)status,
         observed);
  hex(bytes, sizeof bytes);
  puts("\"}");
  return 1;
}

struct Owner {
  DWORD pid;
  FILETIME created;
  DWORD marker;
};

static int create_new(HKEY parent, WCHAR *name, WCHAR *class_name, HKEY *key) {
  DWORD disposition = 0;
  LSTATUS status = RegCreateKeyExW(
      parent, name, 0, class_name, REG_OPTION_VOLATILE,
      KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, NULL, key, &disposition);
  if (status != ERROR_SUCCESS)
    return 0;
  if (disposition != REG_CREATED_NEW_KEY) {
    RegCloseKey(*key);
    *key = NULL;
    return 0;
  }
  return 1;
}

static int values(HKEY key, const struct Owner *owner) {
  const BYTE data[] = {0x11, 0x00, 0xff, 0x88, 0x33, 0x55, 0x99};
  const WCHAR text[] = L"v\xD83D\xDE80";
  return RegSetValueExW(key, L"__RAX_OWNER", 0, REG_BINARY, (const BYTE *)owner,
                        (DWORD)sizeof *owner) == ERROR_SUCCESS &&
         RegSetValueExW(key, L"Binary", 0, REG_BINARY, data,
                        (DWORD)sizeof data) == ERROR_SUCCESS &&
         RegSetValueExW(key, L"\x03A9Name", 0, REG_SZ, (const BYTE *)text,
                        (DWORD)sizeof text) == ERROR_SUCCESS;
}

static int full(HKEY key, unsigned subject, ULONG cls, ULONG *required) {
  __declspec(align(16)) unsigned char first[1024], second[1024];
  ULONG a = 0x7f7f7f7f, b = 0x7f7f7f7f;
  memset(first, 165, sizeof first);
  memset(second, 90, sizeof second);
  if (query_key(key, cls, first, (ULONG)sizeof first, &a) != 0 ||
      query_key(key, cls, second, (ULONG)sizeof second, &b) != 0 || a != b ||
      a > 512 || a < 4)
    return 0;
  *required = a;
  if (fixture_warmup)
    return 1;
  printf("{\"kind\":\"record\",\"subject\":%u,\"class\":%lu,"
         "\"required\":%lu,\"bytes\":\"",
         subject, cls, a);
  hex(first, a);
  printf("\",\"opposite\":\"");
  hex(second, b);
  puts("\"}");
  return 1;
}

static int fixture_matrix(HKEY key, unsigned subject, unsigned long *index) {
  const int aliases[] = {-1, 0, 4, 8, 12, 16, 32};
  for (ULONG cls = 0; cls < 13; ++cls) {
    ULONG required = 64;
    if (cls < 9 && !full(key, subject, cls, &required))
      return 0;
    ULONG limit = cls < 9 ? required + 3 : 64;
    if (limit >= 511)
      return 0;
    for (ULONG n = 0; n <= limit + 2; ++n) {
      ULONG length = n <= limit ? n : n == limit + 1 ? 511 : 512;
      for (size_t a = 0; a < sizeof aliases / sizeof aliases[0]; ++a)
        for (unsigned p = 0; p < 2; ++p)
          if (!sample(key, KEY_WOW64_64KEY, cls, length, aliases[a],
                      p ? 90 : 165, (*index)++, subject))
            return 0;
    }
  }
  return 1;
}

static int owned(HKEY key, const struct Owner *owner) {
  struct Owner actual = {0};
  DWORD bytes = (DWORD)sizeof actual, type = 0;
  return RegQueryValueExW(key, L"__RAX_OWNER", NULL, &type, (BYTE *)&actual,
                          &bytes) == ERROR_SUCCESS &&
         type == REG_BINARY && bytes == sizeof actual &&
         memcmp(&actual, owner, sizeof actual) == 0;
}
static int fixture_run(int warmup) {
  fixture_warmup = warmup;
  WCHAR parent_name[] = L"Software";
  WCHAR ascii_name[] = L"Plain";
  WCHAR unicode_name[] = L"\x03A9\x6F22\xD83D\xDE80";
  WCHAR latin1_name[] = L"caf\x00E9";
  WCHAR empty_class[] = L"";
  WCHAR root_class[] = L"RootClass\x03A9\x6F22\xD83D\xDE80";
  WCHAR ascii_class[] = L"ASCII-class";
  WCHAR unicode_class[] = L"\x03BB\x6F22\xD83D\xDE80";
  WCHAR root_name[128];
  HKEY parent = NULL, keys[4] = {NULL, NULL, NULL, NULL};
  int created[4] = {0, 0, 0, 0}, populated[4] = {0, 0, 0, 0};
  struct Owner owner = {0};
  owner.pid = GetCurrentProcessId();
  owner.marker = 0x514B5241;
  GetSystemTimeAsFileTime(&owner.created);
  if (_snwprintf_s(root_name, sizeof root_name / sizeof root_name[0], _TRUNCATE,
                   L"RaxNativeKeyInformation_%08lx_%08lx%08lx", owner.pid,
                   owner.created.dwHighDateTime,
                   owner.created.dwLowDateTime) < 0)
    return 20;
  /* Open an existing parent. The probe never creates ancestor keys. Prime the
     process-local predefined-key cache before its handle-count baseline. */
  if (RegOpenKeyExW(HKEY_CURRENT_USER, parent_name, 0,
                    KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
                    &parent) != ERROR_SUCCESS)
    return 21;
  if (RegCloseKey(parent) != ERROR_SUCCESS)
    return 22;
  parent = NULL;
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 23;
  int ok = 0, cleanup_ok = 1;
  unsigned long index = 0;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, parent_name, 0,
                    KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
                    &parent) != ERROR_SUCCESS)
    goto done;
  if (!create_new(parent, root_name, root_class, &keys[0]))
    goto done;
  created[0] = 1;
  printf("{\"kind\":\"owned_fixture\",\"parent\":\"HKCU\\\\Software\","
         "\"root_utf16\":\"");
  hex((const unsigned char *)root_name, wcslen(root_name) * sizeof(WCHAR));
  printf("\",\"owner\":\"");
  hex((const unsigned char *)&owner, sizeof owner);
  printf("\",\"volatile\":true,\"view\":256,\"warmup\":%s}\n",
         warmup ? "true" : "false");
  if (fflush(stdout) != 0)
    goto done;
  if (!values(keys[0], &owner))
    goto done;
  populated[0] = 1;
  if (!create_new(keys[0], ascii_name, ascii_class, &keys[1]))
    goto done;
  created[1] = 1;
  if (!values(keys[1], &owner))
    goto done;
  populated[1] = 1;
  if (!create_new(keys[0], unicode_name, unicode_class, &keys[2]))
    goto done;
  created[2] = 1;
  if (!values(keys[2], &owner))
    goto done;
  populated[2] = 1;
  if (!create_new(keys[0], latin1_name, empty_class, &keys[3]))
    goto done;
  created[3] = 1;
  if (!values(keys[3], &owner))
    goto done;
  populated[3] = 1;
  for (unsigned subject = 0; subject < 4; ++subject)
    if (!fixture_matrix(keys[subject], subject, &index))
      goto done;
  ok = 1;
done:
  /* Only the keys proved new in this process are eligible for deletion.
     No recursive deletion is used. Unknown descendants keep the root alive. */
  for (int i = 3; i >= 1; --i) {
    if (keys[i]) {
      if (populated[i] && !owned(keys[i], &owner))
        cleanup_ok = 0;
      if (RegCloseKey(keys[i]) != ERROR_SUCCESS)
        cleanup_ok = 0;
      keys[i] = NULL;
    }
    if (created[i] && cleanup_ok &&
        RegDeleteKeyExW(keys[0],
                        i == 1   ? ascii_name
                        : i == 2 ? unicode_name
                                 : latin1_name,
                        KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
      cleanup_ok = 0;
  }
  if (keys[0]) {
    if (populated[0] && !owned(keys[0], &owner))
      cleanup_ok = 0;
    if (RegCloseKey(keys[0]) != ERROR_SUCCESS)
      cleanup_ok = 0;
    keys[0] = NULL;
  }
  if (created[0] && cleanup_ok) {
    if (RegDeleteKeyExW(parent, root_name, KEY_WOW64_64KEY, 0) != ERROR_SUCCESS)
      cleanup_ok = 0;
    else {
      HKEY check = NULL;
      LSTATUS status = RegOpenKeyExW(parent, root_name, 0,
                                     KEY_READ | KEY_WOW64_64KEY, &check);
      if (check)
        RegCloseKey(check);
      if (status != ERROR_FILE_NOT_FOUND)
        cleanup_ok = 0;
    }
  }
  if (parent && RegCloseKey(parent) != ERROR_SUCCESS)
    cleanup_ok = 0;
  int counts_valid = GetProcessHandleCount(GetCurrentProcess(), &after) != 0;
  int handles_equal = counts_valid && before == after;
  printf("{\"kind\":\"%s\",\"records\":%lu,\"complete\":%s,"
         "\"fixture_removed\":%s,\"handles_equal\":%s,\"handles_before\":%lu,"
         "\"handles_after\":%lu}\n",
         warmup ? "warmup_finished" : "finished", index, ok ? "true" : "false",
         cleanup_ok ? "true" : "false", handles_equal ? "true" : "false",
         before, after);
  return ok && cleanup_ok && counts_valid && (warmup || handles_equal) &&
                 fflush(stdout) == 0 && !ferror(stdout)
             ? 0
             : 24;
}
int main(int argc, char **argv) {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  if (!module)
    return 10;
#define LOAD(target, name)                                                     \
  do {                                                                         \
    FARPROC f = GetProcAddress(module, name);                                  \
    if (!f || sizeof f != sizeof target)                                       \
      return 11;                                                               \
    memcpy(&target, &f, sizeof target);                                        \
  } while (0)
  LOAD(query_key, "NtQueryKey");
  if (!identity(module))
    return 12;
  if (argc == 2 && strcmp(argv[1], "--identity") == 0)
    return 0;
  if (argc != 1)
    return 13;

  if (fixture_run(1) != 0)
    return 24;
  return fixture_run(0);
}
