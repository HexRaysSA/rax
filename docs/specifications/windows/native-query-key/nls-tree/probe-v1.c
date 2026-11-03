/* Read-only fixed NLS subtree; no registry mutation or caller-selected root. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef LONG(NTAPI *QueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *Version)(PRTL_OSVERSIONINFOW);
static QueryFn query_key;
static int emit;
static unsigned case_index, subject_index;
static char stdout_buffer[1 << 20];
static const ULONG headers[9] = {16, 24, 44, 4, 40, 12, 4, 4, 4};
static const ULONG classes[] = {0, 1, 2, 3, 4, 5, 6, 8};
#define MAX_BYTES (128 * 1024)
#define MAX_KEYS 1024
static __declspec(align(16)) unsigned char first[MAX_BYTES], second[MAX_BYTES],
    output[MAX_BYTES];
#include "handle-snapshot-v3.h"
static void hex(const unsigned char *p, size_t n) {
  static const char digits[] = "0123456789abcdef";
  char text[2048];
  while (n) {
    size_t count = n > sizeof text / 2 ? sizeof text / 2 : n;
    for (size_t i = 0; i < count; ++i) {
      text[2 * i] = digits[p[i] >> 4];
      text[2 * i + 1] = digits[p[i] & 15];
    }
    if (fwrite(text, 2, count, stdout) != count)
      ExitProcess(40);
    p += count;
    n -= count;
  }
}
static int identity(const char *kind, HMODULE module) {
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
  DWORD units = GetMappedFileNameW(GetCurrentProcess(),
                                   (LPVOID)(uintptr_t)query_key, mapped, 32768);
  if (!units || units >= 32768)
    return 0;
  printf("{\"kind\":\"%s\",\"schema\":\"rax-native-nls-tree-v1\","
         "\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],"
         "\"process_machine\":%u,\"native_machine\":%u,\"mapped_provider_"
         "utf16\":\"",
         kind, sizeof(void *), info.dwMajorVersion, info.dwMinorVersion,
         info.dwBuildNumber, (unsigned)process, (unsigned)native);
  for (DWORD i = 0; i < units; ++i)
    printf("%02x%02x", (unsigned)(mapped[i] & 255), (unsigned)(mapped[i] >> 8));
  puts("\"}");
  return 1;
}

static int sample(HKEY key, ULONG view, ULONG cls, ULONG length, int alias,
                  unsigned poison, unsigned capacity, unsigned subject) {
  if (length > capacity || capacity > MAX_BYTES ||
      (alias >= 0 && (unsigned)alias + 4 > capacity))
    return 0;
  ULONG returned = 0x7f7f7f7f;
  memset(output, (int)poison, capacity);
  PULONG result = alias < 0 ? &returned : (PULONG)(output + alias);
  LONG status = query_key(key, cls, output, length, result);
  ULONG observed;
  memcpy(&observed, result, 4);
  if (emit) {
    printf("{\"kind\":\"case\",\"index\":%u,\"subject\":%u,\"view\":%lu,"
           "\"class\":%lu,\"length\":%lu,\"alias\":%d,\"poison\":%u,\"status\":"
           "%lu,\"returned\":%lu,\"bytes\":\"",
           case_index, subject, view, cls, length, alias, poison, (ULONG)status,
           observed);
    hex(output, capacity);
    puts("\"}");
  }
  ++case_index;
  return 1;
}
static int matrix(HKEY key, ULONG view, unsigned subject) {
  for (unsigned c = 0; c < sizeof classes / sizeof classes[0]; ++c) {
    ULONG cls = classes[c], a = 0x7f7f7f7f, b = 0x7f7f7f7f;
    memset(first, 165, sizeof first);
    memset(second, 90, sizeof second);
    if (query_key(key, cls, first, sizeof first, &a) != 0 ||
        query_key(key, cls, second, sizeof second, &b) != 0 || a != b ||
        a < headers[cls] || a > MAX_BYTES - 16 || memcmp(first, second, a))
      return 0;
    if (emit) {
      printf("{\"kind\":\"record\",\"subject\":%u,\"view\":%lu,\"class\":%lu,"
             "\"required\":%lu,\"bytes\":\"",
             subject, view, cls, a);
      hex(first, a);
      printf("\",\"opposite\":\"");
      hex(second, b);
      puts("\"}");
    }
    unsigned capacity = (a + 11) & ~3u;
    int aliases[7] = {-1,
                      0,
                      4,
                      (int)(headers[cls] - 4),
                      (int)((a - 4) & ~3u),
                      (int)((a + 3) & ~3u),
                      (int)(capacity - 4)};
    for (ULONG length = 0; length <= a + 1; ++length) {
      int boundary = length == 0 || length == headers[cls] - 1 ||
                     length == headers[cls] || length == headers[cls] + 1 ||
                     length + 1 == a || length == a || length == a + 1;
      int name_cut =
          cls <= 1 && length > headers[cls] && ((length - headers[cls]) & 1);
      if (!boundary && !name_cut)
        continue;
      for (unsigned i = 0; i < sizeof aliases / sizeof aliases[0]; ++i) {
        int duplicate = 0;
        for (unsigned j = 0; j < i; ++j)
          if (aliases[j] == aliases[i])
            duplicate = 1;
        if (duplicate)
          continue;
        for (unsigned p = 0; p < 2; ++p)
          if (!sample(key, view, cls, length, aliases[i], p ? 90 : 165,
                      capacity, subject))
            return 0;
      }
    }
  }
  return 1;
}
struct Path {
  WCHAR *text;
  unsigned depth;
};
struct Info {
  DWORD children, max_name, values, max_value_name, max_value_data;
  FILETIME stamp;
};
static int info(HKEY key, struct Info *result) {
  memset(result, 0, sizeof *result);
  return RegQueryInfoKeyW(key, NULL, NULL, NULL, &result->children,
                          &result->max_name, NULL, &result->values,
                          &result->max_value_name, &result->max_value_data,
                          NULL, &result->stamp) == 0;
}
static unsigned long long ticks(FILETIME f) {
  return ((unsigned long long)f.dwHighDateTime << 32) | f.dwLowDateTime;
}
static int walk(ULONG view) {
  static const WCHAR root[] = L"System\\CurrentControlSet\\Control\\Nls";
  struct Path paths[MAX_KEYS] = {0};
  unsigned count = 1, index = 0;
  size_t path_bytes = sizeof root, value_bytes = 0, value_count = 0;
  paths[0].text = _wcsdup(root);
  paths[0].depth = 0;
  int ok = paths[0].text != NULL;
  HKEY key = NULL;
  while (ok && index < count) {
    struct Path *path = &paths[index];
    struct Info before, after;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path->text, 0,
                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | view,
                      &key) != 0 ||
        !info(key, &before)) {
      ok = 0;
      break;
    }
    unsigned subject = subject_index++;
    if (before.children > MAX_KEYS - count || before.max_name > 32767 ||
        before.values > 4096 - value_count || before.max_value_name > 32767 ||
        before.max_value_data > (1 << 20)) {
      ok = 0;
      break;
    }
    if (emit) {
      printf("{\"kind\":\"key\",\"subject\":%u,\"view\":%lu,\"path_utf16\":\"",
             subject, view);
      static const WCHAR prefix[] = L"\\Registry\\Machine\\";
      hex((const unsigned char *)prefix, sizeof prefix - 2);
      hex((const unsigned char *)path->text, wcslen(path->text) * 2);
      printf("\",\"children\":%lu,\"values\":%lu,\"last_write\":%llu}\n",
             before.children, before.values, ticks(before.stamp));
    }
    for (DWORD i = 0; ok && i < before.values; ++i) {
      WCHAR *name = calloc((size_t)before.max_value_name + 2, sizeof(WCHAR));
      BYTE *data = malloc((size_t)before.max_value_data + 1);
      DWORD n = before.max_value_name + 1, bytes = before.max_value_data + 1,
            type = 0;
      if (!name || !data) {
        free(name);
        free(data);
        ok = 0;
        break;
      }
      LSTATUS status =
          RegEnumValueW(key, i, name, &n, NULL, &type, data, &bytes);
      value_bytes += (size_t)n * 2 + bytes;
      value_count++;
      if (status != 0 || n > before.max_value_name ||
          bytes > before.max_value_data || value_bytes > (16 << 20))
        ok = 0;
      if (ok && emit) {
        printf("{\"kind\":\"value\",\"subject\":%u,\"index\":%lu,\"name_"
               "utf16\":\"",
               subject, i);
        hex((const unsigned char *)name, (size_t)n * 2);
        printf("\",\"type\":%lu,\"data\":\"", type);
        hex(data, bytes);
        puts("\"}");
      }
      free(name);
      free(data);
    }
    for (DWORD i = 0; ok && i < before.children; ++i) {
      WCHAR *name = calloc((size_t)before.max_name + 2, sizeof(WCHAR));
      DWORD n = before.max_name + 1;
      FILETIME stamp;
      if (!name) {
        ok = 0;
        break;
      }
      LSTATUS status =
          RegEnumKeyExW(key, i, name, &n, NULL, NULL, NULL, &stamp);
      if (status != 0 || n == 0 || n > before.max_name || wcschr(name, L'\\') ||
          wcslen(name) != n || path->depth >= 32) {
        free(name);
        ok = 0;
        break;
      }
      size_t parent = wcslen(path->text), units = parent + 1 + n;
      path_bytes += (units + 1) * 2;
      if (units > 32767 || path_bytes > (1 << 20)) {
        free(name);
        ok = 0;
        break;
      }
      WCHAR *next = calloc(units + 1, sizeof(WCHAR));
      if (!next) {
        free(name);
        ok = 0;
        break;
      }
      memcpy(next, path->text, parent * 2);
      next[parent] = L'\\';
      memcpy(next + parent + 1, name, (size_t)n * 2);
      paths[count].text = next;
      paths[count].depth = path->depth + 1;
      ++count;
      if (emit) {
        printf("{\"kind\":\"child\",\"subject\":%u,\"index\":%lu,\"name_"
               "utf16\":\"",
               subject, i);
        hex((const unsigned char *)name, (size_t)n * 2);
        printf("\",\"last_write\":%llu}\n", ticks(stamp));
      }
      free(name);
    }
    if (ok && (!matrix(key, view, subject) || !info(key, &after) ||
               memcmp(&before, &after, sizeof before)))
      ok = 0;
    if (RegCloseKey(key) != 0)
      ok = 0;
    key = NULL;
    if (ok && emit)
      printf("{\"kind\":\"end_key\",\"subject\":%u,\"stable\":true}\n",
             subject);
    ++index;
  }
  if (key)
    RegCloseKey(key);
  for (unsigned i = 0; i < count; ++i)
    free(paths[i].text);
  if (emit)
    printf("{\"kind\":\"view_finished\",\"view\":%lu,\"keys\":%u,\"value_"
           "count\":%zu,\"value_bytes\":%zu,\"complete\":%s}\n",
           view, index, value_count, value_bytes, ok ? "true" : "false");
  return ok;
}
static int campaign(int emitting) {
  emit = emitting;
  case_index = subject_index = 0;
  const ULONG views[] = {0, KEY_WOW64_64KEY, KEY_WOW64_32KEY};
  for (unsigned i = 0; i < 3; ++i)
    if (!walk(views[i]))
      return 0;
  return 1;
}
int main(int argc, char **argv) {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  query_key = (QueryFn)GetProcAddress(module, "NtQueryKey");
  if (!query_key ||
      setvbuf(stdout, stdout_buffer, _IOFBF, sizeof stdout_buffer))
    return 10;
  if (argc == 2 && strcmp(argv[1], "--identity") == 0)
    return identity("identity", module) ? 0 : 11;
  if (argc != 1 || !identity("host", module))
    return 12;
  if (handle_snapshot("initial") || !campaign(0) || fflush(stdout) ||
      handle_snapshot("before"))
    return 13;
  if (!campaign(1) || fflush(stdout) || handle_snapshot("after"))
    return 14;
  printf("{\"kind\":\"finished\",\"keys\":%u,\"cases\":%u}\n", subject_index,
         case_index);
  return fflush(stdout) || ferror(stdout) ? 15 : 0;
}
