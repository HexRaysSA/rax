#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef NTSTATUS(NTAPI *QueryFn)(HANDLE, PKEY_VALUE_ENTRY, ULONG, PVOID, PULONG,
                                 PULONG);
typedef LONG(NTAPI *VersionFn)(PRTL_OSVERSIONINFOW);
typedef LONG(NTAPI *GetStatusFn)(void);
typedef VOID(NTAPI *SetStatusFn)(LONG);
_Static_assert(sizeof(WCHAR) == 2, "native UTF-16 units");
_Static_assert(sizeof(KEY_VALUE_ENTRY) == (sizeof(void *) == 8 ? 24 : 16),
               "SDK entry width");
_Static_assert(offsetof(KEY_VALUE_ENTRY, DataLength) == sizeof(void *),
               "SDK data length");

enum { ARENA = 65536, DATA = 32768, LENGTH = 49152, REQUIRED = 53248 };
static unsigned char *pages, *model;
static HANDLE handles[8];
static WCHAR key_path[256];
static int created;
static QueryFn query;
static GetStatusFn get_status;
static SetStatusFn set_status;
static ULONG records;
static unsigned name_role, name_slot, data_alias, custom_count;
static ULONG requested_count;
static unsigned input_layout, second_name_role, second_name_slot;
static char output_buffer[65536];
static const WCHAR *names[] = {L"",     L"One",   L"Three", L"Five",  L"Dword",
                               L"Text", L"Qword", L"Multi", L"Absent"};
static const unsigned char payloads[][8] = {{0},
                                            {0x11},
                                            {0x21, 0x22, 0x23},
                                            {0x31, 0x32, 0x33, 0x34, 0x35},
                                            {0x41, 0x42, 0x43, 0x44},
                                            {0x41, 0, 0, 0},
                                            {1, 2, 3, 4, 5, 6, 7, 8},
                                            {0x41, 0, 0, 0, 0, 0}};
static const DWORD sizes[] = {0, 1, 3, 5, 4, 4, 8, 6};
static const DWORD kinds[] = {REG_NONE,  REG_BINARY, REG_BINARY, REG_BINARY,
                              REG_DWORD, REG_SZ,     REG_QWORD,  REG_MULTI_SZ};
struct Plan {
  ULONG count;
  unsigned ids[3];
};
static const struct Plan plans[] = {
    {0, {0, 0, 0}}, {1, {1, 0, 0}}, {1, {2, 0, 0}}, {1, {3, 0, 0}},
    {2, {1, 2, 0}}, {2, {2, 1, 0}}, {3, {1, 2, 3}}, {3, {3, 1, 2}},
    {3, {1, 1, 1}}, {3, {1, 8, 3}}, {3, {8, 1, 2}}, {3, {1, 2, 8}},
    {3, {0, 1, 0}}, {3, {4, 5, 6}}, {3, {7, 3, 1}}};

static void hex(const unsigned char *p, size_t n) {
  static const char digits[] = "0123456789abcdef";
  char encoded[512];
  while (n) {
    size_t take = n < 256 ? n : 256;
    for (size_t i = 0; i < take; ++i) {
      encoded[2 * i] = digits[p[i] >> 4];
      encoded[2 * i + 1] = digits[p[i] & 15];
    }
    fwrite(encoded, 1, take * 2, stdout);
    p += take;
    n -= take;
  }
}
static int identity(const char *kind, HMODULE module, RTL_OSVERSIONINFOW *os) {
  WCHAR logical[1024], mapped[1024];
  DWORD a = GetModuleFileNameW(module, logical, 1024);
  DWORD b = GetMappedFileNameW(GetCurrentProcess(), module, mapped, 1024);
  if (!a || a >= 1024 || !b || b >= 1024)
    return 10;
  printf("{\"kind\":\"%s\",\"schema\":\"rax-native-query-multiple-values-v6\","
         "\"pointer_bytes\":%zu,\"entry_bytes\":%zu,\"layout_offsets\":[%zu,%"
         "zu,%zu,%zu],"
         "\"kernel\":[%lu,%lu,%lu],\"arena_base\":%llu,\"arena\":%u,"
         "\"provider_utf16\":\"",
         kind, sizeof(void *), sizeof(KEY_VALUE_ENTRY),
         offsetof(KEY_VALUE_ENTRY, ValueName),
         offsetof(KEY_VALUE_ENTRY, DataLength),
         offsetof(KEY_VALUE_ENTRY, DataOffset), offsetof(KEY_VALUE_ENTRY, Type),
         os->dwMajorVersion, os->dwMinorVersion, os->dwBuildNumber,
         (unsigned long long)(uintptr_t)pages, ARENA);
  hex((const unsigned char *)logical, a * 2);
  printf("\",\"mapped_provider_utf16\":\"");
  hex((const unsigned char *)mapped, b * 2);
  printf("\",\"key_path_utf16\":\"");
  hex((const unsigned char *)key_path, wcslen(key_path) * 2);
  printf("\"}\n");
  return 0;
}

static int create_key(const char *nonce) {
  HKEY key = NULL;
  DWORD disposition = 0;
  for (unsigned attempt = 0; attempt < 8; ++attempt) {
    if (swprintf_s(key_path, 256,
                   L"Software\\RaxNativeQmv_20261030_%lu_%llu_%u",
                   GetCurrentProcessId(), (unsigned long long)GetTickCount64(),
                   attempt) < 0)
      return 11;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, key_path, 0, NULL,
                                  REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL,
                                  &key, &disposition);
    if (result != ERROR_SUCCESS)
      return 12;
    if (disposition == REG_CREATED_NEW_KEY)
      break;
    RegCloseKey(key);
    key = NULL;
  }
  if (!key || disposition != REG_CREATED_NEW_KEY)
    return 13;
  created = 1;
  handles[0] = (HANDLE)key;
  WCHAR owner[33];
  size_t n = strlen(nonce);
  if (n != 16 || strspn(nonce, "0123456789abcdef") != n)
    return 14;
  for (size_t i = 0; i <= n; ++i)
    owner[i] = (WCHAR)nonce[i];
  if (RegSetValueExW(key, L"_RaxProbeOwner", 0, REG_SZ, (BYTE *)owner,
                     (DWORD)(2 * (n + 1))))
    return 15;
  /* Flush the exact owned leaf and marker before any native query. */
  printf("{\"kind\":\"owned_key\",\"marker\":\"%s\",\"key_path_utf16\":\"",
         nonce);
  hex((const unsigned char *)key_path, wcslen(key_path) * 2);
  printf("\"}\n");
  fflush(stdout);
  for (unsigned i = 0; i < 8; ++i)
    if (RegSetValueExW(key, names[i], 0, kinds[i],
                       sizes[i] ? payloads[i] : NULL, sizes[i]))
      return 16;
  if (RegSetValueExW(key, L"\u00c4bc", 0, REG_BINARY, payloads[3], sizes[3]))
    return 41;
  handles[1] = NULL;
  handles[2] = (HANDLE)(uintptr_t)0xDEADBEEF;
  handles[3] = CreateEventW(NULL, FALSE, FALSE, NULL);
  handles[4] = GetCurrentProcess();
  if (!handles[3] ||
      !DuplicateHandle(GetCurrentProcess(), handles[0], GetCurrentProcess(),
                       &handles[5], 0, FALSE, 0))
    return 17;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, key_path, 0, KEY_QUERY_VALUE, &key))
    return 18;
  handles[6] = (HANDLE)key;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, key_path, 0, KEY_SET_VALUE, &key))
    return 19;
  handles[7] = (HANDLE)key;
  return 0;
}

static int cleanup(void) {
  int error = 0;
  const unsigned keys[] = {0, 5, 6, 7};
  for (unsigned i = 0; i < 4; ++i)
    if (handles[keys[i]]) {
      if (RegCloseKey((HKEY)handles[keys[i]]))
        error = 20;
      handles[keys[i]] = NULL;
    }
  if (handles[3] && !CloseHandle(handles[3]))
    error = 21;
  handles[3] = NULL;
  if (created) {
    if (RegDeleteKeyW(HKEY_CURRENT_USER, key_path))
      error = 22;
    HKEY check = NULL;
    LONG result =
        RegOpenKeyExW(HKEY_CURRENT_USER, key_path, 0, KEY_QUERY_VALUE, &check);
    if (check)
      RegCloseKey(check);
    if (result != ERROR_FILE_NOT_FOUND)
      error = 23;
  }
  if (pages && !VirtualFree(pages, 0, MEM_RELEASE))
    error = 24;
  free(model);
  return error;
}

struct Change {
  ULONG offset;
  DWORD flags;
};
static void change(struct Change *list, unsigned *count, ULONG offset,
                   DWORD flags) {
  list[(*count)++] = (struct Change){offset, flags};
}
static int observe(unsigned plan, ULONG capacity, unsigned er, unsigned dr,
                   unsigned lr, unsigned rr, unsigned handle, unsigned boundary,
                   unsigned char poison, const char *phase) {
  DWORD previous;
  if (!VirtualProtect(pages, ARENA, PAGE_READWRITE, &previous))
    return 32;
  memset(pages, poison, ARENA);
  struct Change changes[8];
  unsigned changed = 0;
  ULONG ew = 0, dw = DATA, lw = LENGTH, rw = REQUIRED;
  const unsigned edge = boundary ? boundary : 4;
  uintptr_t ep = (uintptr_t)pages, dp = (uintptr_t)(pages + DATA);
  uintptr_t lp = (uintptr_t)(pages + LENGTH),
            rp = (uintptr_t)(pages + REQUIRED);
  switch (er) {
  case 0:
    break;
  case 1:
    ep = 0;
    break;
  case 2:
    ep = 1;
    break;
  case 3:
  case 4:
  case 5:
    ew = er == 3 ? 1 : er == 4 ? 4 : 8;
    ep = (uintptr_t)(pages + ew);
    break;
  case 6:
  case 7:
  case 8:
  case 12:
    change(changes, &changed, 0,
           er == 6    ? PAGE_READONLY
           : er == 7  ? PAGE_READWRITE | PAGE_GUARD
           : er == 12 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_NOACCESS);
    break;
  case 9:
  case 10:
  case 11:
  case 15:
    ew = 4096 - edge;
    ep = (uintptr_t)(pages + ew);
    change(changes, &changed, 4096,
           er == 9    ? PAGE_NOACCESS
           : er == 10 ? PAGE_READWRITE | PAGE_GUARD
           : er == 15 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_READONLY);
    break;
  case 13:
    ep = UINTPTR_MAX - 15;
    break;
  case 14:
    ew = 4096 - 3 * (ULONG)sizeof(KEY_VALUE_ENTRY) + 4;
    ep = (uintptr_t)(pages + ew);
    change(changes, &changed, 4096, PAGE_NOACCESS);
    break;
  default:
    return 33;
  }
  switch (dr) {
  case 0:
    break;
  case 1:
    dp = 0;
    break;
  case 2:
    dp = 1;
    break;
  case 3:
  case 4:
  case 5:
    dw += dr == 3 ? 1 : dr == 4 ? 2 : 4;
    dp = (uintptr_t)(pages + dw);
    break;
  case 6:
  case 7:
  case 8:
  case 12:
    change(changes, &changed, DATA,
           dr == 6    ? PAGE_READONLY
           : dr == 7  ? PAGE_READWRITE | PAGE_GUARD
           : dr == 12 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_NOACCESS);
    break;
  case 9:
  case 10:
  case 11:
  case 15:
    dw = DATA + 4096 - edge;
    dp = (uintptr_t)(pages + dw);
    change(changes, &changed, DATA + 4096,
           dr == 9    ? PAGE_NOACCESS
           : dr == 10 ? PAGE_READWRITE | PAGE_GUARD
           : dr == 15 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_READONLY);
    break;
  case 13:
    dp = UINTPTR_MAX - 15;
    break;
  case 14:
    change(changes, &changed, DATA + 4096, PAGE_NOACCESS);
    break;
  default:
    return 34;
  }
  switch (data_alias) {
  case 0:
    break;
  case 1:
    dw = ew;
    break;
  case 2:
    dw = ew + (ULONG)sizeof(void *);
    break;
  case 3:
    dw = LENGTH;
    break;
  case 4:
    dw = REQUIRED;
    break;
  case 5:
    dw = 8192;
    break;
  case 6:
    dw = 12288;
    break;
  case 7:
    dw = ew + (ULONG)sizeof(KEY_VALUE_ENTRY);
    break;
  default:
    return 42;
  }
  if (data_alias)
    dp = (uintptr_t)(pages + dw);
  switch (lr) {
  case 0:
    break;
  case 1:
    lp = 0;
    break;
  case 2:
    lp = 1;
    break;
  case 3:
    lw += 1;
    lp = (uintptr_t)(pages + lw);
    break;
  case 4:
  case 5:
  case 6:
  case 11:
    change(changes, &changed, LENGTH,
           lr == 4    ? PAGE_READONLY
           : lr == 5  ? PAGE_READWRITE | PAGE_GUARD
           : lr == 11 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_NOACCESS);
    break;
  case 7:
    lw = dw;
    lp = (uintptr_t)(pages + lw);
    break;
  case 8:
  case 9:
    lw = ew + (ULONG)sizeof(void *) + (lr == 9 ? 4 : 0);
    lp = (uintptr_t)(pages + lw);
    break;
  case 10:
    lw = LENGTH + 4094;
    lp = (uintptr_t)(pages + lw);
    change(changes, &changed, REQUIRED, PAGE_NOACCESS);
    break;
  case 12:
    lw = 8192;
    lp = (uintptr_t)(pages + lw);
    break;
  default:
    return 35;
  }
  switch (rr) {
  case 0:
    break;
  case 1:
    rp = 0;
    break;
  case 2:
    rp = 1;
    break;
  case 3:
    rw += 1;
    rp = (uintptr_t)(pages + rw);
    break;
  case 4:
  case 5:
  case 6:
  case 12:
    change(changes, &changed, REQUIRED,
           rr == 4    ? PAGE_READONLY
           : rr == 5  ? PAGE_READWRITE | PAGE_GUARD
           : rr == 12 ? PAGE_READONLY | PAGE_GUARD
                      : PAGE_NOACCESS);
    break;
  case 7:
    rw = lw;
    rp = lp;
    break;
  case 8:
    rw = dw;
    rp = (uintptr_t)(pages + rw);
    break;
  case 9:
    rw = ew + (ULONG)sizeof(void *);
    rp = (uintptr_t)(pages + rw);
    break;
  case 10:
    rw = ew;
    rp = (uintptr_t)(pages + rw);
    break;
  case 11:
    rw = REQUIRED + 4094;
    rp = (uintptr_t)(pages + rw);
    change(changes, &changed, REQUIRED + 4096, PAGE_NOACCESS);
    break;
  default:
    return 36;
  }
  ULONG entry_count = custom_count ? requested_count : plans[plan].count;
  unsigned initialized = input_layout == 5   ? 3
                         : entry_count > 256 ? 256
                         : entry_count < 3   ? 3
                                             : entry_count;
  for (unsigned i = 0; i < initialized; ++i) {
    UNICODE_STRING name;
    KEY_VALUE_ENTRY entry;
    memset(&name, poison, sizeof(name));
    memset(&entry, poison, sizeof(entry));
    WCHAR *buffer = (WCHAR *)(pages + (input_layout == 5 ? 20480 + 4096 * i
                                                         : 12288 + 64 * i));
    const WCHAR *text = names[i < 3 ? plans[plan].ids[i] : 1];
    size_t n = wcslen(text);
    memcpy(buffer, text, 2 * (n + 1));
    name.Length = (USHORT)(2 * n);
    name.MaximumLength = (USHORT)(2 * (n + 1));
    name.Buffer = buffer;
    memcpy(pages + 8192 + i * (input_layout == 5 ? 4096 : sizeof(name)), &name,
           sizeof(name));
    entry.ValueName =
        (UNICODE_STRING *)(pages + 8192 +
                           i * (input_layout == 5 ? 4096 : sizeof(name)));
    memcpy(pages + ew + i * sizeof(entry), &entry, sizeof(entry));
  }
  for (unsigned which = 0; which < 2; ++which) {
    unsigned applied_role = which ? second_name_role : name_role;
    unsigned applied_slot = which ? second_name_slot : name_slot;
    if (applied_role) {
      ULONG descriptor_at =
          8192 + applied_slot *
                     (input_layout == 5 ? 4096 : (ULONG)sizeof(UNICODE_STRING));
      UNICODE_STRING name;
      memcpy(&name, pages + descriptor_at, sizeof(name));
      uintptr_t descriptor = (uintptr_t)(pages + descriptor_at);
      ULONG text_at = input_layout == 5 ? 20480 + applied_slot * 4096 : 16384;
      switch (applied_role) {
      case 1:
        descriptor = 0;
        break;
      case 2:
        descriptor = 1;
        break;
      case 3:
        descriptor_at =
            8192 + (input_layout == 5 ? applied_slot * 4096 : 0) + 1025;
        descriptor = (uintptr_t)(pages + descriptor_at);
        break;
      case 4:
      case 5:
      case 6:
      case 7:
        change(changes, &changed,
               8192 + (input_layout == 5 ? applied_slot * 4096 : 0),
               applied_role == 4   ? PAGE_READONLY
               : applied_role == 5 ? PAGE_READWRITE | PAGE_GUARD
               : applied_role == 7 ? PAGE_READONLY | PAGE_GUARD
                                   : PAGE_NOACCESS);
        break;
      case 8:
      case 9:
        descriptor_at = 40960 + 4096 - 4;
        descriptor = (uintptr_t)(pages + descriptor_at);
        change(changes, &changed, 45056,
               applied_role == 8 ? PAGE_NOACCESS : PAGE_READWRITE | PAGE_GUARD);
        break;
      case 10:
        name.MaximumLength = 0;
        break;
      case 11:
        name.Length = 1;
        name.Buffer = NULL;
        break;
      case 12:
        name.Length = 3;
        break;
      case 13:
        name.Length = 0;
        name.Buffer = (WCHAR *)(uintptr_t)1;
        break;
      case 14:
        name.Length = 6;
        name.Buffer = NULL;
        break;
      case 15:
        text_at += 1;
        memcpy(pages + text_at, L"One", 8);
        name.Length = 6;
        name.Buffer = (WCHAR *)(pages + text_at);
        break;
      case 16:
      case 17:
      case 18:
      case 19:
        memcpy(pages + text_at, L"One", 8);
        name.Length = 6;
        name.Buffer = (WCHAR *)(pages + text_at);
        change(changes, &changed,
               input_layout == 5 ? 20480 + applied_slot * 4096 : 16384,
               applied_role == 16   ? PAGE_READONLY
               : applied_role == 17 ? PAGE_READWRITE | PAGE_GUARD
               : applied_role == 19 ? PAGE_READONLY | PAGE_GUARD
                                    : PAGE_NOACCESS);
        break;
      case 20:
      case 21:
      case 22:
        text_at = 16384 + 4096 - 2;
        memcpy(pages + text_at, L"One", 8);
        name.Length = 6;
        name.Buffer = (WCHAR *)(pages + text_at);
        change(changes, &changed, 20480,
               applied_role == 20   ? PAGE_NOACCESS
               : applied_role == 21 ? PAGE_READWRITE | PAGE_GUARD
                                    : PAGE_READONLY);
        break;
      case 23:
        memcpy(pages + text_at, L"oNe", 8);
        name.Length = 6;
        name.Buffer = (WCHAR *)(pages + text_at);
        break;
      case 24:
        memcpy(pages + text_at, L"One\0tail", 18);
        name.Length = 16;
        name.Buffer = (WCHAR *)(pages + text_at);
        break;
      case 25:
        name.MaximumLength = 1;
        break;
      case 26:
        memcpy(pages + text_at, L"\u00e4bc", 8);
        name.Length = 6;
        name.Buffer = (WCHAR *)(pages + text_at);
        break;
      case 27:
        name.Length = 0xFFFE;
        break;
      case 28:
        name.Length = 0xFFFF;
        break;
      case 29:
        name.Length = 6;
        name.Buffer = (WCHAR *)(UINTPTR_MAX - 15);
        break;
      case 30:
        descriptor = UINTPTR_MAX - 15;
        break;
      default:
        return 43;
      }
      memcpy(pages + descriptor_at, &name, sizeof(name));
      memcpy(pages + ew + applied_slot * sizeof(KEY_VALUE_ENTRY), &descriptor,
             sizeof(descriptor));
    }
  }
  memcpy(pages + lw, &capacity, 4);
  memcpy(model, pages, ARENA);
  for (unsigned i = 0; i < changed; ++i)
    if (!VirtualProtect(pages + changes[i].offset, 4096, changes[i].flags,
                        &previous))
      return 37;
  LONG status = (LONG)0xDEADBEEF, exception = 0;
  set_status((LONG)0xC0000034);
  SetLastError(0x12345678);
  __try {
    status = query(handles[handle], (PKEY_VALUE_ENTRY)ep, entry_count,
                   (PVOID)dp, (PULONG)lp, (PULONG)rp);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = (LONG)GetExceptionCode();
  }
  DWORD last_error = GetLastError();
  LONG last_status = get_status();
  DWORD protections[17];
  for (unsigned i = 0; i < 17; ++i) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(pages + 4096 * i, &info, sizeof(info)))
      return 38;
    protections[i] = info.Protect;
  }
  if (!VirtualProtect(pages, ARENA, PAGE_READWRITE, &previous))
    return 39;
  memcpy(model + ew, pages + ew, initialized * sizeof(KEY_VALUE_ENTRY));
  memcpy(model + dw, pages + dw, input_layout == 2 ? 128 : 2048);
  memcpy(model + lw, pages + lw, 8);
  memcpy(model + rw, pages + rw, 8);
  if (entry_count > 256)
    memcpy(model, pages, ARENA);
  if (memcmp(model, pages, ARENA)) {
    ULONG at = 0;
    while (at < ARENA && model[at] == pages[at])
      ++at;
    fprintf(stderr, "unrepresented store at=%lu case=%lu phase=%s\n", at,
            records, phase);
    return 40;
  }
  printf("{\"kind\":\"case\",\"index\":%lu,\"phase\":\"%s\",\"plan\":%u,"
         "\"count\":%lu,\"capacity\":%lu,"
         "\"entry_role\":%u,\"data_role\":%u,\"length_role\":%u,\"required_"
         "role\":%u,\"handle\":%u,\"boundary\":%u,"
         "\"poison\":%u,\"status\":%lu,\"exception\":%lu,\"last_error\":%lu,"
         "\"last_status\":%lu,"
         "\"arena_reconstruction_verified\":true,\"watch_offsets\":[%lu,%lu,%"
         "lu,%lu],\"arguments\":[%llu,%llu,%llu,%llu],\"protections\":[",
         records, phase, plan, entry_count, capacity, er, dr, lr, rr, handle,
         boundary, poison, (ULONG)status, (ULONG)exception, last_error,
         (ULONG)last_status, ew, dw, lw, rw, (unsigned long long)ep,
         (unsigned long long)dp, (unsigned long long)lp,
         (unsigned long long)rp);
  for (unsigned i = 0; i < 17; ++i)
    printf("%s%lu", i ? "," : "", protections[i]);
  printf("],\"entries\":\"");
  hex(pages + ew, initialized * sizeof(KEY_VALUE_ENTRY));
  printf("\",\"data\":\"");
  hex(pages + dw, input_layout == 2 ? 128 : 2048);
  printf("\",\"length\":\"");
  hex(pages + lw, 8);
  printf("\",\"required\":\"");
  hex(pages + rw, 8);
  printf("\",\"name_role\":%u,\"name_slot\":%u,\"data_alias\":%u,\"initialized_"
         "entries\":%u",
         name_role, name_slot, data_alias, initialized);
  printf(",\"input_layout\":%u,\"second_name_role\":%u,\"second_name_slot\":%u",
         input_layout, second_name_role, second_name_slot);
  if (entry_count > 256) {
    printf(",\"arena_after\":\"");
    hex(pages, ARENA);
    printf("\"");
  }
  printf("}\n");
  ++records;
  if (records % 1024 == 0)
    fflush(stdout);
  return 0;
}

static int run(HMODULE ntdll, RTL_OSVERSIONINFOW *os, const char *nonce) {
  const uintptr_t bases[] = {0x30000000, 0x31000000, 0x32000000, 0x33000000,
                             0x34000000};
  for (unsigned i = 0; i < 5 && !pages; ++i)
    pages = VirtualAlloc((void *)bases[i], ARENA + 4096,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!pages)
    return 26;
  model = malloc(ARENA);
  if (!model)
    return 27;
  DWORD previous;
  if (!VirtualProtect(pages + ARENA, 4096, PAGE_NOACCESS, &previous))
    return 28;
  int result = create_key(nonce);
  if (result)
    return result;
  if ((result = identity("host", ntdll, os)))
    return result;
  input_layout = 2;
  {
    for (unsigned plan = 0; plan < 15; ++plan)
      for (ULONG c = 0; c < 29; ++c) {
        ULONG capacity = c < 25    ? c
                         : c == 25 ? 31
                         : c == 26 ? 32
                         : c == 27 ? 63
                                   : 64;
        for (unsigned r = 0; r < 3; ++r)
          for (unsigned poison = 0; poison < 2; ++poison)
            if ((result = observe(plan, capacity, 0, 0, 0, r == 2 ? 7 : r, 0, 0,
                                  poison ? 0x5A : 0xA5, "packing")))
              return result;
      }
    const unsigned selected[] = {0, 1, 6, 9};
    const ULONG sizes[] = {0, 1, 12, 13, 64};
    for (unsigned h = 0; h < 8; ++h)
      for (unsigned p = 0; p < 4; ++p)
        for (unsigned n = 0; n < 5; ++n)
          for (unsigned r = 0; r < 3; ++r)
            if ((result = observe(selected[p], sizes[n], 0, 0, 0,
                                  r == 2 ? 7 : r, h, 0, 0xA5, "handles")))
              return result;
    const unsigned roles[] = {16, 16, 13, 13, 8};
    const ULONG capacities[] = {0, 1, 13, 64};
    for (unsigned a = 0; a < 5; ++a)
      for (unsigned b = a + 1; b < 5; ++b)
        for (unsigned x = 0; x < roles[a]; ++x)
          for (unsigned y = 0; y < roles[b]; ++y)
            for (unsigned p = 0; p < 4; ++p)
              for (unsigned n = 0; n < 4; ++n) {
                unsigned r[5] = {0};
                r[a] = x;
                r[b] = y;
                if ((result =
                         observe(selected[p], capacities[n], r[0], r[1], r[2],
                                 r[3], r[4], 0, 0xA5, "pointer_pairs")))
                  return result;
              }
    const unsigned bad[] = {9, 10, 11, 15}, returns[] = {0, 1, 4, 5, 7};
    const ULONG lengths[] = {1, 7, 13, 15};
    for (unsigned boundary = 1; boundary <= 17; ++boundary)
      for (unsigned protection = 0; protection < 4; ++protection)
        for (unsigned p = 6; p <= 7; ++p)
          for (unsigned n = 0; n < 4; ++n)
            for (unsigned r = 0; r < 5; ++r)
              if ((result =
                       observe(p, lengths[n], 0, bad[protection], 0, returns[r],
                               0, boundary, 0xA5, "data_boundaries")))
                return result;
    const unsigned pair_l[] = {0, 4, 5}, pair_r[] = {0, 0, 5};
    const unsigned entry_plans[] = {1, 6};
    const ULONG entry_caps[] = {0, 64};
    for (unsigned boundary = 1; boundary < 3 * sizeof(KEY_VALUE_ENTRY);
         ++boundary)
      for (unsigned protection = 0; protection < 4; ++protection)
        for (unsigned pair = 0; pair < 3; ++pair)
          for (unsigned p = 0; p < 2; ++p)
            for (unsigned n = 0; n < 2; ++n)
              if ((result =
                       observe(entry_plans[p], entry_caps[n], bad[protection],
                               0, pair_l[pair], pair_r[pair], 0, boundary, 0xA5,
                               "entry_boundaries")))
                return result;
    const ULONG huge[] = {8192, 0xFFFFFFFF};
    for (unsigned p = 0; p < 4; ++p)
      for (unsigned n = 0; n < 2; ++n)
        for (unsigned tail = 0; tail < 2; ++tail)
          if ((result = observe(selected[p], huge[n], 0, tail ? 14 : 0, 0, 0, 0,
                                0, 0xA5, "large_capacity")))
            return result;
  }
  input_layout = 4;
  {
    const unsigned selected[] = {0, 1, 6, 9, 10, 11};
    const ULONG capacities[] = {0, 13, 64};
    for (unsigned p = 0; p < 6; ++p)
      for (name_slot = 0; name_slot < 3; ++name_slot)
        for (name_role = 0; name_role < 31; ++name_role)
          for (unsigned n = 0; n < 3; ++n)
            for (unsigned h = 0; h < 2; ++h)
              if ((result = observe(selected[p], capacities[n], 0, 0, 0, 0,
                                    h ? 2 : 0, 0, 0xA5, "names")))
                return result;
    const unsigned length_roles[] = {0, 4, 5}, required_roles[] = {0, 4, 5};
    for (name_slot = 0; name_slot < 3; ++name_slot)
      for (name_role = 0; name_role < 31; ++name_role)
        for (unsigned n = 0; n < 2; ++n)
          for (unsigned l = 0; l < 3; ++l)
            for (unsigned r = 0; r < 3; ++r)
              if ((result = observe(6, capacities[n], 0, 0, length_roles[l],
                                    required_roles[r], 0, 0, 0xA5,
                                    "name_fault_order")))
                return result;
    name_role = 0;
    name_slot = 0;
    const ULONG alias_capacities[] = {0, 1, 4, 7, 13, 64};
    const unsigned aliases[] = {0, 7, 8};
    for (unsigned p = 0; p < 15; ++p)
      for (data_alias = 0; data_alias < 8; ++data_alias)
        for (unsigned n = 0; n < 6; ++n)
          for (unsigned l = 0; l < 3; ++l)
            for (unsigned r = 0; r < 3; ++r)
              if ((result = observe(p, alias_capacities[n], 0, 0, aliases[l],
                                    aliases[r], 0, 0, 0xA5, "aliases")))
                return result;
    data_alias = 0;
    custom_count = 1;
    const ULONG counts[] = {0, 1, 2, 3, 4, 16, 64, 256};
    const ULONG count_capacities[] = {0, 1, 13, 1021, 1024, 2048};
    const unsigned count_handles[] = {0, 2, 5, 6}, count_required[] = {0, 1, 7};
    for (unsigned n = 0; n < 8; ++n) {
      requested_count = counts[n];
      for (unsigned s = 0; s < 6; ++s)
        for (unsigned h = 0; h < 4; ++h)
          for (unsigned r = 0; r < 3; ++r)
            if ((result =
                     observe(8, count_capacities[s], 0, 0, 0, count_required[r],
                             count_handles[h], 0, 0xA5, "counts")))
              return result;
    }
    const ULONG huge_counts[] = {257, 4096, 0x10000000, 0xFFFFFFFF};
    const unsigned entry_roles[] = {0, 7, 8};
    for (unsigned n = 0; n < 4; ++n) {
      requested_count = huge_counts[n];
      for (unsigned s = 0; s < 2; ++s)
        for (unsigned h = 0; h < 2; ++h)
          for (unsigned e = 0; e < 3; ++e)
            if ((result = observe(8, s ? 64 : 0, entry_roles[e], 0, 0, 0,
                                  h ? 2 : 0, 0, 0xA5, "count_boundaries")))
              return result;
    }
  }
  input_layout = 5;
  custom_count = 0;
  {
    const unsigned roles[] = {1, 2, 5, 6, 11, 14, 15, 17, 18};
    for (name_slot = 0; name_slot < 3; ++name_slot)
      for (second_name_slot = name_slot + 1; second_name_slot < 3;
           ++second_name_slot)
        for (unsigned a = 0; a < 9; ++a)
          for (unsigned b = 0; b < 9; ++b) {
            name_role = roles[a];
            second_name_role = roles[b];
            for (unsigned n = 0; n < 2; ++n)
              for (unsigned h = 0; h < 2; ++h)
                if ((result = observe(6, n ? 13 : 0, 0, 0, 0, 0, h ? 2 : 0, 0,
                                      0xA5, "name_pairs")))
                  return result;
          }
    name_role = 0;
    second_name_role = 0;
    name_slot = 0;
    second_name_slot = 0;
    custom_count = 1;
    const ULONG huge[] = {0x10000000, 0xFFFFFFFF};
    const unsigned length_roles[] = {0, 1, 4, 5, 6, 10, 11},
                   required_roles[] = {0, 5, 6};
    for (unsigned n = 0; n < 2; ++n) {
      requested_count = huge[n];
      for (unsigned l = 0; l < 7; ++l)
        for (unsigned r = 0; r < 3; ++r)
          for (unsigned e = 0; e < 2; ++e)
            for (unsigned h = 0; h < 2; ++h)
              if ((result = observe(8, 13, e ? 7 : 0, 0, length_roles[l],
                                    required_roles[r], h ? 2 : 0, 0, 0xA5,
                                    "resource_order")))
                return result;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, output_buffer, _IOFBF, sizeof(output_buffer));
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  RTL_OSVERSIONINFOW os = {sizeof(os)};
  VersionFn version = (VersionFn)GetProcAddress(ntdll, "RtlGetVersion");
  query = (QueryFn)GetProcAddress(ntdll, "NtQueryMultipleValueKey");
  get_status = (GetStatusFn)GetProcAddress(ntdll, "RtlGetLastNtStatus");
  set_status = (SetStatusFn)GetProcAddress(
      ntdll, "RtlSetLastWin32ErrorAndNtStatusFromNtStatus");
  if (!version || !query || !get_status || !set_status || version(&os))
    return 29;
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  if (info.dwPageSize != 4096)
    return 30;
  if (argc == 2 && !strcmp(argv[1], "--identity"))
    return identity("identity", ntdll, &os);
  if (argc != 3 || strcmp(argv[1], "--run"))
    return 31;
  int result = run(ntdll, &os, argv[2]);
  int cleaned = cleanup();
  printf("{\"kind\":\"finished\",\"records\":%lu,\"run_status\":%d,\"cleanup_"
         "status\":%d,\"key_deleted\":%s}\n",
         records, result, cleaned, created && !cleaned ? "true" : "false");
  return result ? result : cleaned;
}
