#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef NTSTATUS(NTAPI *QueryFn)(HANDLE, PKEY_VALUE_ENTRY, ULONG, PVOID, PULONG,
                                 PULONG);
int main(int argc, char **argv) {
  if (argc != 2 || strlen(argv[1]) != 16 ||
      strspn(argv[1], "0123456789abcdef") != 16)
    return 1;
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  RTL_OSVERSIONINFOW os = {sizeof(os)};
  typedef LONG(NTAPI * VersionFn)(PRTL_OSVERSIONINFOW);
  VersionFn version = (VersionFn)GetProcAddress(module, "RtlGetVersion");
  WCHAR mapped[1024];
  DWORD mapped_units =
      GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
  if (!version || version(&os) || !mapped_units || mapped_units >= 1024)
    return 6;
  printf("{\"kind\":\"host\",\"pointer_bytes\":%zu,\"entry_bytes\":%zu,"
         "\"kernel\":[%lu,%lu,%lu],\"mapped_provider_utf16\":\"",
         sizeof(void *), sizeof(KEY_VALUE_ENTRY), os.dwMajorVersion,
         os.dwMinorVersion, os.dwBuildNumber);
  for (DWORD i = 0; i < mapped_units * 2; ++i)
    printf("%02x", ((BYTE *)mapped)[i]);
  printf("\"}\n");
  fflush(stdout);
  WCHAR path[256], owner[17];
  HKEY key = NULL;
  DWORD disposition = 0;
  for (unsigned i = 0; i <= 16; ++i)
    owner[i] = (WCHAR)argv[1][i];
  for (unsigned attempt = 0; attempt < 8; ++attempt) {
    if (swprintf_s(path, 256, L"Software\\RaxQmvOverflow_20261101_%lu_%llu_%u",
                   GetCurrentProcessId(), (unsigned long long)GetTickCount64(),
                   attempt) < 0)
      return 2;
    LONG result =
        RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &key, &disposition);
    if (result)
      return 3;
    if (disposition == REG_CREATED_NEW_KEY)
      break;
    RegCloseKey(key);
    key = NULL;
  }
  if (!key || disposition != REG_CREATED_NEW_KEY)
    return 4;
  if (RegSetValueExW(key, L"_RaxProbeOwner", 0, REG_SZ, (BYTE *)owner,
                     sizeof(owner))) {
    RegCloseKey(key);
    RegDeleteKeyW(HKEY_CURRENT_USER, path);
    return 5;
  }
  printf("{\"kind\":\"owned_key\",\"marker\":\"%s\",\"path\":\"", argv[1]);
  for (size_t i = 0; i < wcslen(path); ++i)
    printf("%04x", (unsigned)path[i]);
  printf("\"}\n");
  fflush(stdout);
  unsigned char *payload = calloc(1, 1u << 20);
  KEY_VALUE_ENTRY *entries = malloc(4098 * sizeof(*entries));
  QueryFn query = (QueryFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                          "NtQueryMultipleValueKey");
  int failed = !payload || !entries || !query;
  if (!failed)
    failed = RegSetValueExW(key, L"Large", 0, REG_BINARY, payload, 1u << 20) !=
             ERROR_SUCCESS;
  WCHAR text[] = L"Large";
  UNICODE_STRING name = {10, 12, text};
  const ULONG counts[] = {1, 2, 4094, 4095, 4096, 4097};
  const ULONG capacities[] = {0, 1, 1048575, 1048576, 1048577, 2097152};
  unsigned char *output = VirtualAlloc(NULL, 2097152 + 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  DWORD prior = 0;
  if (!output || !VirtualProtect(output + 2097152, 4096, PAGE_NOACCESS, &prior))
    failed = 1;
  if (!failed)
    for (unsigned c = 0; c < 6; ++c)
    for (unsigned cap = 0; cap < 6; ++cap) {
      memset(entries, 0xA5, 4098 * sizeof(*entries));
      for (unsigned i = 0; i < 4098; ++i)
        entries[i].ValueName = &name;
      memset(output, 0xA5, 2097152);
      ULONG length = capacities[cap], required = 0xA5A5A5A5;
      LONG status = 0, exception = 0;
      __try {
        status = query(key, entries, counts[c], output, &length, &required);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        exception = GetExceptionCode();
      }
      printf("{\"kind\":\"case\",\"pointer_bytes\":%zu,\"entry_bytes\":%zu,"
             "\"count\":%lu,\"capacity\":%lu,\"value_bytes\":1048576,\"status\":%lu,"
             "\"exception\":%lu,\"length\":%lu,\"required\":%lu,\"data_runs\":[",
             sizeof(void *), sizeof(KEY_VALUE_ENTRY), counts[c], capacities[cap],
             (ULONG)status, (ULONG)exception, length, required);
      size_t begin = 0;
      unsigned runs = 0;
      while (begin < 2097152) {
        size_t end = begin + 1;
        while (end < 2097152 && output[end] == output[begin])
          ++end;
        printf("%s[%u,%zu]", runs++ ? "," : "", (unsigned)output[begin], end - begin);
        begin = end;
      }
      printf("]");
      int pointers_unchanged = 1, padding_unchanged = 1;
      printf(",\"fields\":[");
      for (unsigned i = 0; i < 4098; ++i) {
        printf("%s[%lu,%lu,%lu]", i ? "," : "", entries[i].DataLength,
               entries[i].DataOffset, entries[i].Type);
        if (entries[i].ValueName != &name)
          pointers_unchanged = 0;
        for (size_t j = offsetof(KEY_VALUE_ENTRY, Type) + sizeof(ULONG);
             j < sizeof(KEY_VALUE_ENTRY); ++j)
          if (((BYTE *)&entries[i])[j] != 0xA5)
            padding_unchanged = 0;
      }
      printf("],\"pointers_unchanged\":%s,\"padding_unchanged\":%s}\n",
             pointers_unchanged ? "true" : "false",
             padding_unchanged ? "true" : "false");
      fflush(stdout);
    }
  if (output)
    VirtualFree(output, 0, MEM_RELEASE);
  free(entries);
  free(payload);
  LONG closed = RegCloseKey(key);
  LONG deleted = RegDeleteKeyW(HKEY_CURRENT_USER, path);
  HKEY check = NULL;
  LONG absent =
      RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_QUERY_VALUE, &check);
  if (check)
    RegCloseKey(check);
  printf("{\"kind\":\"finished\",\"failed\":%d,\"closed\":%ld,\"deleted\":%ld,"
         "\"absence\":%ld}\n",
         failed, closed, deleted, absent);
  return failed || closed || deleted || absent != ERROR_FILE_NOT_FOUND;
}
