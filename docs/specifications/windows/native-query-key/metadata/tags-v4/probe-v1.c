#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Read-only fixed-key controls. Declared output spans stay within a private
 * reservation with inaccessible enclosing bands; fixed invalid pointers are
 * deliberate fault inputs. Handle snapshots query only this process. */
typedef LONG(NTAPI *QueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);
static QueryFn query;
static HKEY selected_key;
static ULONG information_class;
static int emit_records;
static unsigned char *pages;
static unsigned char *reservation;
static unsigned records;
static char stdout_buffer[1 << 20];

#include "handle-snapshot-v3.h"

static void protect(void *address, SIZE_T size, DWORD flags) {
  DWORD previous;
  if (!VirtualProtect(address, size, flags, &previous))
    ExitProcess(16);
}

static int identity(const char *kind, HMODULE module,
                    const RTL_OSVERSIONINFOW *os) {
  wchar_t logical[1024], mapped[1024];
  DWORD logical_length = GetModuleFileNameW(module, logical, 1024);
  DWORD mapped_length = GetMappedFileNameW(
      GetCurrentProcess(), (LPVOID)(uintptr_t)query, mapped, 1024);
  typedef BOOL(WINAPI * MachineFn)(HANDLE, USHORT *, USHORT *);
  MachineFn machines = (MachineFn)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
  USHORT process_machine = 0, native_machine = 0;
  if (!machines ||
      !machines(GetCurrentProcess(), &process_machine, &native_machine))
    return 26;
  if (!logical_length || logical_length >= 1024 || !mapped_length ||
      mapped_length >= 1024)
    return 18;
  printf("{\"kind\":\"%s\",\"schema\":\"rax-native-key-metadata-tags-v4\","
         "\"pointer_bytes\":%zu,\"process_machine\":%u,\"native_machine\":%u,"
         "\"kernel\":[%lu,%lu,%lu],"
         "\"provider_utf16\":\"",
         kind, sizeof(void *), (unsigned)process_machine,
         (unsigned)native_machine, os->dwMajorVersion, os->dwMinorVersion,
         os->dwBuildNumber);
  for (DWORD i = 0; i < logical_length; ++i)
    printf("%02x%02x", logical[i] & 255, logical[i] >> 8);
  printf("\",\"mapped_provider_utf16\":\"");
  for (DWORD i = 0; i < mapped_length; ++i)
    printf("%02x%02x", mapped[i] & 255, mapped[i] >> 8);
  printf("\"}\n");
  return 0;
}

static int observe(unsigned output_role, unsigned returned_role, ULONG length,
                   unsigned char poison) {
  unsigned output_offset = 0, returned_offset = 8192;
  unsigned char *output;
  ULONG *returned;
  LONG status = (LONG)0xDEADBEEF, exception = 0;
  MEMORY_BASIC_INFORMATION regions[4];
  DWORD last_error;
  const unsigned watched[] = {0, 4096, 8192, 12288};
  protect(pages, 65536, PAGE_READWRITE);
  memset(pages, poison, 65536);
  output = pages;
  switch (output_role) {
  case 1:
    output = NULL;
    break;
  case 2:
    output = (void *)(uintptr_t)1;
    break;
  case 3:
    output_offset = 1;
    output = pages + output_offset;
    break;
  case 4:
    output_offset = 4;
    output = pages + output_offset;
    break;
  case 5:
    protect(pages, 4096, PAGE_READONLY);
    break;
  case 6:
    protect(pages, 4096, PAGE_READWRITE | PAGE_GUARD);
    break;
  case 7:
    protect(pages, 4096, PAGE_NOACCESS);
    break;
  case 8:
  case 9:
  case 10:
    output_offset = 4092;
    output = pages + output_offset;
    protect(pages + 4096, 4096,
            output_role == 8   ? PAGE_NOACCESS
            : output_role == 9 ? PAGE_READWRITE | PAGE_GUARD
                               : PAGE_READONLY);
    break;
  case 11:
    protect(pages, 4096, PAGE_READONLY | PAGE_GUARD);
    break;
  case 12:
    output = (void *)(UINTPTR_MAX - 15);
    break;
  case 13:
    output_offset = 2;
    output = pages + output_offset;
    break;
  }
  returned = (ULONG *)(pages + returned_offset);
  switch (returned_role) {
  case 1:
    returned = NULL;
    break;
  case 2:
    returned = (ULONG *)(uintptr_t)1;
    break;
  case 3:
    returned_offset = 8193;
    returned = (ULONG *)(pages + returned_offset);
    break;
  case 4:
    protect(pages + 8192, 4096, PAGE_READONLY);
    break;
  case 5:
    protect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD);
    break;
  case 6:
    protect(pages + 8192, 4096, PAGE_NOACCESS);
    break;
  case 7:
  case 8:
  case 9:
  case 10:
    returned_offset = output_offset + (returned_role == 7   ? 0
                                       : returned_role == 8 ? 4
                                       : returned_role == 9 ? 28
                                                            : 32);
    returned = (ULONG *)(pages + returned_offset);
    break;
  case 11:
    returned_offset = 12286;
    returned = (ULONG *)(pages + returned_offset);
    protect(pages + 12288, 4096, PAGE_NOACCESS);
    break;
  case 12:
    protect(pages + 8192, 4096, PAGE_READONLY | PAGE_GUARD);
    break;
  }
  SetLastError(0x12345678);
  __try {
    status = query(selected_key, information_class, output, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = (LONG)GetExceptionCode();
  }
  last_error = GetLastError();
  for (unsigned i = 0; i < 4; ++i) {
    if (!VirtualQuery(pages + watched[i], &regions[i], sizeof(regions[i])))
      return 5;
  }
  protect(pages, 65536, PAGE_READWRITE);
  if (emit_records) {
    printf("{\"kind\":\"case\",\"index\":%u,\"class\":%lu,\"output\":%u,"
           "\"returned\":%u,\"length\":%lu,"
           "\"poison\":%u,\"status\":%lu,\"exception\":%lu,\"last_error\":%lu,"
           "\"protections\":[%lu,%lu,%lu,%lu],"
           "\"bytes\":\"",
           records, information_class, output_role, returned_role, length,
           poison, (ULONG)status, (ULONG)exception, last_error,
           regions[0].Protect, regions[1].Protect, regions[2].Protect,
           regions[3].Protect);
    for (unsigned i = 0; i < 256; ++i)
      printf("%02x", pages[output_offset + i]);
    printf("\",\"returned_bytes\":\"");
    for (unsigned i = 0; i < 8; ++i)
      printf("%02x", pages[returned_offset + i]);
    printf("\"}\n");
  }
  ++records;
  return 0;
}

static int campaign(void) {
  const ULONG lengths[] = {0,   1,   3,    4,    7,    8,    11,  12,  15,
                           16,  23,  24,   31,   32,   39,   40,  43,  44,
                           47,  48,  63,   64,   127,  128,  129, 130, 131,
                           255, 256, 4095, 4096, 4097, 65535};
  for (information_class = 0; information_class <= 10; ++information_class) {
    for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l) {
      for (unsigned output = 0; output < 14; ++output) {
        for (unsigned returned = 0; returned < 13; ++returned) {
          int result = observe(output, returned, lengths[l], 0xA5);
          if (result)
            return result;
        }
      }
    }
    for (unsigned i = 0; i < 4; ++i) {
      int result = observe(0, 0, 256, i & 2 ? 0x5A : 0xA5);
      if (result)
        return result;
    }
  }
  return 0;
}


static int metadata_tags(void) {
  typedef LONG(NTAPI *SetFn)(HANDLE, ULONG, PVOID, ULONG);
  SetFn set = (SetFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationKey");
  wchar_t mapped[1024];
  DWORD mapped_length = GetMappedFileNameW(GetCurrentProcess(), (LPVOID)(uintptr_t)set, mapped, 1024);
  if (!set || !mapped_length || mapped_length >= 1024) return 46;
  printf("{\"kind\":\"setter\",\"mapped_provider_utf16\":\"");
  for (DWORD j = 0; j < mapped_length; ++j) printf("%02x%02x", mapped[j] & 255, mapped[j] >> 8);
  printf("\"}\n");
  HKEY key = NULL;
  const ULONG inputs[] = {0, 1, 0x400, 0x600, 0xffff, 0x10000, 0x12345678, 0xffffffff};
  if (!set || RegOpenKeyExW(HKEY_LOCAL_MACHINE,
      L"System\\CurrentControlSet\\Control\\Nls\\CustomLocale", 0,
      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key) != ERROR_SUCCESS)
    return 40;
  unsigned char original[9][256];
  ULONG required[9];
  for (ULONG cls = 0; cls <= 8; ++cls) {
    __declspec(align(16)) unsigned char data[256];
    memset(data, 0xA5, sizeof(data));
    required[cls] = 0;
    LONG status = query(key, cls, data, sizeof(data), &required[cls]);
    printf("{\"kind\":\"tags_before\",\"class\":%lu,\"status\":%lu,\"required\":%lu,\"bytes\":\"",
      cls, (ULONG)status, required[cls]);
    if (status != 0 || required[cls] > sizeof(data)) { RegCloseKey(key); return 41; }
    memcpy(original[cls], data, required[cls]);
    for (ULONG j = 0; j < required[cls]; ++j) printf("%02x", data[j]);
    printf("\"}\n");
  }
  for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
    ULONG input = inputs[i];
    LONG set_status = set(key, 5, &input, sizeof(input));
    for (ULONG cls = 0; cls <= 8; ++cls) {
      __declspec(align(16)) unsigned char data[256];
      ULONG length = 0;
      memset(data, 0xA5, sizeof(data));
      LONG status = query(key, cls, data, sizeof(data), &length);
      printf("{\"kind\":\"tags_after\",\"input\":%lu,\"set_status\":%lu,\"class\":%lu,\"status\":%lu,\"required\":%lu,\"bytes\":\"",
        input, (ULONG)set_status, cls, (ULONG)status, length);
      if (set_status != 0 || status != 0 || length > sizeof(data)) { RegCloseKey(key); return 42; }
      for (ULONG j = 0; j < length; ++j) printf("%02x", data[j]);
      printf("\",\"same_as_before\":%s}\n", length == required[cls] && memcmp(data, original[cls], length) == 0 ? "true" : "false");
    }
  }
  if (RegCloseKey(key) != ERROR_SUCCESS) return 43;
  printf("{\"kind\":\"tags_finished\",\"inputs\":8,\"before_queries\":9,\"after_queries\":72}\n");
  return fflush(stdout) ? 44 : 0;
}

int main(int argc, char **argv) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
  RTL_OSVERSIONINFOW os = {sizeof(os)};
  DWORD handles_before = 0, handles_after = 0;
  if (setvbuf(stdout, stdout_buffer, _IOFBF, sizeof(stdout_buffer)))
    return 27;
  query = (QueryFn)GetProcAddress(ntdll, "NtQueryKey");
  if (!version || !query || version(&os) < 0)
    return 10;
  if (argc == 2 && strcmp(argv[1], "--identity") == 0)
    return identity("identity", ntdll, &os);
  if (argc == 2 && strcmp(argv[1], "--handles-idle") == 0) {
    if (identity("host", ntdll, &os))
      return 35;
    for (unsigned i = 0; i < 7; ++i) {
      char phase[32];
      snprintf(phase, sizeof(phase), "idle-%u", i);
      int result = handle_snapshot(phase);
      if (result)
        return result;
      if (i < 6)
        Sleep(30000);
    }
    printf("{\"kind\":\"finished\",\"mode\":\"idle\",\"snapshots\":7}\n");
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--tag-records") == 0) {
    if (identity("host", ntdll, &os)) return 45;
    return metadata_tags();
  }
  if (argc != 1 || identity("host", ntdll, &os))
    return 11;
  if (fflush(stdout))
    return 28;
  if (handle_snapshot("initial"))
    return 36;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"System\\CurrentControlSet\\Control\\Nls\\CustomLocale", 0,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    &selected_key) != ERROR_SUCCESS)
    return 19;
  reservation = VirtualAlloc(NULL, 3 * 65536, MEM_RESERVE, PAGE_NOACCESS);
  pages = reservation ? VirtualAlloc(reservation + 65536, 65536, MEM_COMMIT,
                                     PAGE_READWRITE)
                      : NULL;
  if (!pages || pages != reservation + 65536) {
    if (reservation)
      VirtualFree(reservation, 0, MEM_RELEASE);
    RegCloseKey(selected_key);
    return 12;
  }
  /* Warm the identical query/protection paths before measuring handle lifetime.
   */
  emit_records = 0;
  if (campaign())
    return 20;
  records = 0;
  if (handle_snapshot("before"))
    return 37;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before))
    return 21;
  emit_records = 1;
  if (campaign())
    return 22;
  if (fflush(stdout))
    return 29;
  if (handle_snapshot("after"))
    return 38;
  if (!GetProcessHandleCount(GetCurrentProcess(), &handles_after))
    return 23;
  if (RegCloseKey(selected_key) != ERROR_SUCCESS)
    return 24;
  if (!VirtualFree(reservation, 0, MEM_RELEASE))
    return 13;
  printf("{\"kind\":\"finished\",\"records\":%u,\"handles_before\":%lu,"
         "\"handles_after\":%lu}\n",
         records, handles_before, handles_after);
  return handles_before == handles_after ? 0 : 25;
}
