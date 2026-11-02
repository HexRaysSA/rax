/* Complete fixed CMD trees and descendant NT opens. Read/query/close only. */
#define main command_header_fixture_main
#include "../native-command-processor/absolute-v1.c"
#undef main
#include <limits.h>
#include <stdlib.h>
#include <wchar.h>

__declspec(dllimport) LONG NTAPI NtEnumerateKey(HANDLE, ULONG, ULONG, void *,
                                                ULONG, ULONG *);
__declspec(dllimport) LONG NTAPI RtlOpenCurrentUser(ULONG, HANDLE *);

enum {
  MAX_NODES = 1024,
  MAX_DEPTH = 32,
  MAX_STATES = 32768,
  SCRATCH_BYTES = 1114112
};
typedef struct {
  ULONG tags, grant, bytes;
  BYTE *name;
} State;
typedef struct {
  unsigned int hive, view;
  ULONG status;
  int node;
} Root;
static State states[MAX_STATES];
static unsigned int state_count, node_count, reserved;
static size_t value_count, value_bytes, path_bytes;
static BYTE *scratch;
static const ULONG views[] = {0, 0x100, 0x200, 0x300};
static const ULONG requests[] = {0x20019, 0x02000000};

static ULONG number(size_t offset) {
  ULONG value;
  memcpy(&value, scratch + offset, sizeof value);
  return value;
}

static int state(HANDLE key) {
  ULONG returned = 0, tags, grant, bytes;
  if (NtQueryKey(key, 7, scratch, SCRATCH_BYTES, &returned) != 0 ||
      returned != 4)
    return -1;
  tags = number(0);
  if (NtQueryObject(key, 0, scratch, 56, &returned) != 0 || returned != 56)
    return -1;
  grant = number(4);
  if (NtQueryKey(key, 3, scratch, SCRATCH_BYTES, &returned) != 0 ||
      returned < 4 || returned > SCRATCH_BYTES)
    return -1;
  bytes = number(0);
  if (bytes > returned - 4 || bytes > 32766 || bytes % 2)
    return -1;
  for (unsigned int i = 0; i < state_count; ++i)
    if (states[i].tags == tags && states[i].grant == grant &&
        states[i].bytes == bytes &&
        memcmp(states[i].name, scratch + 4, bytes) == 0)
      return (int)i;
  if (state_count == MAX_STATES)
    return -1;
  BYTE *name = malloc(bytes ? bytes : 1);
  if (!name)
    return -1;
  memcpy(name, scratch + 4, bytes);
  states[state_count] = (State){tags, grant, bytes, name};
  return (int)state_count++;
}

static LONG open_nt(HANDLE parent, WCHAR *text, ULONG access,
                    unsigned int extended, HANDLE *key) {
  size_t bytes = wcslen(text) * sizeof(WCHAR);
  if (bytes > 32766)
    return (LONG)0xc000000d;
  Unicode name = {(USHORT)bytes, (USHORT)bytes, text};
  Attributes attrs = {sizeof attrs, parent, &name, 0x40, NULL, NULL};
  *key = NULL;
  return extended ? NtOpenKeyEx(key, access, &attrs, 0)
                  : NtOpenKey(key, access, &attrs);
}

static int rows(HANDLE parent, int source, WCHAR **names, ULONG count) {
  WCHAR empty[] = L"";
  WCHAR missing[] = L"__RAX_ABSENT_CHILD_20261029";
  unsigned int row = 0;
  for (ULONG target = 0; target < count + 2; ++target) {
    WCHAR *name = target == 0           ? empty
                  : target == count + 1 ? missing
                                        : names[target - 1];
    for (unsigned int extended = 0; extended < 2; ++extended)
      for (size_t requested = 0;
           requested < sizeof requests / sizeof requests[0]; ++requested)
        for (unsigned int view = 0; view < 4; ++view) {
          HANDLE key = NULL;
          LONG status = open_nt(parent, name, requests[requested] | views[view],
                                extended, &key);
          int captured = -1;
          if (status == 0) {
            if (!key)
              return 20;
            captured = state(key);
            if (captured < 0 || NtClose(key) != 0)
              return 21;
          } else if (key) {
            NtClose(key);
            return 22;
          }
          printf("%s{\"source\":%d,\"name\":%lu,\"extended\":%u,\"request\":%"
                 "lu,\"view\":%lu,\"status\":%lu,\"target\":%d}",
                 row++ ? "," : "", source, target, extended,
                 requests[requested], views[view], (ULONG)status, captured);
        }
  }
  return 0;
}

static int controls(HANDLE seed, int captured, WCHAR **names, ULONG count) {
  printf(",\"opens\":[{\"seed\":0,\"status\":0,\"source\":%d,\"rows\":[",
         captured);
  int result = rows(seed, captured, names, count);
  if (result)
    return result;
  printf("]}");
  State *base = &states[captured];
  WCHAR *canonical = calloc(base->bytes / 2 + 1, sizeof(WCHAR));
  if (!canonical)
    return 23;
  memcpy(canonical, base->name, base->bytes);
  for (unsigned int view = 0; view < 4; ++view) {
    HANDLE key = NULL;
    LONG status = open_nt(NULL, canonical, 0x02000000 | views[view], 1, &key);
    int source = -1;
    if (status == 0) {
      if (!key || (source = state(key)) < 0) {
        free(canonical);
        return 24;
      }
    } else if (key) {
      NtClose(key);
      free(canonical);
      return 25;
    }
    printf(",{\"seed\":1,\"view\":%lu,\"status\":%lu,\"source\":%d,\"rows\":[",
           views[view], (ULONG)status, source);
    if (key) {
      result = rows(key, source, names, count);
      if (NtClose(key) != 0)
        result = 26;
    }
    printf("]}");
    if (result) {
      free(canonical);
      return result;
    }
  }
  free(canonical);
  for (unsigned int request = 0; request < 2; ++request) {
    WCHAR empty[] = L"";
    HANDLE key = NULL;
    ULONG desired = request == 0 ? 0x02000100 : 0x20019;
    LONG status = open_nt(seed, empty, desired, 1, &key);
    int source = -1;
    if (status == 0) {
      if (!key || (source = state(key)) < 0)
        return 24;
    } else if (key) {
      NtClose(key);
      return 25;
    }
    printf(
        ",{\"seed\":%u,\"request\":%lu,\"status\":%lu,\"source\":%d,\"rows\":[",
        request + 2, desired, (ULONG)status, source);
    if (key) {
      result = rows(key, source, names, count);
      if (NtClose(key) != 0)
        result = 26;
    }
    printf("]}");
    if (result)
      return result;
  }
  printf("]");
  return 0;
}

static int security(State *identity, ULONG *status, ULONG *grant) {
  WCHAR *canonical = calloc(identity->bytes / 2 + 1, sizeof(WCHAR));
  if (!canonical)
    return 27;
  memcpy(canonical, identity->name, identity->bytes);
  HANDLE key = NULL;
  *status = (ULONG)open_nt(NULL, canonical, 0x01000000, 1, &key);
  free(canonical);
  *grant = 0;
  if (*status != 0)
    return key ? (NtClose(key), 28) : 0;
  ULONG returned = 0;
  if (!key || NtQueryObject(key, 0, scratch, 56, &returned) != 0 ||
      returned != 56)
    return 29;
  *grant = number(4);
  return NtClose(key) == 0 && (*grant & 0x01000000) != 0 ? 0 : 29;
}

static int walk(HKEY key, unsigned int hive, ULONG view, int parent,
                WCHAR *component, unsigned int depth) {
  if (depth > MAX_DEPTH || node_count == MAX_NODES)
    return 30;
  int captured = state(key);
  if (captured < 0)
    return 31;
  unsigned int id = node_count++;
  State *identity = &states[captured];
  ULONG security_status = 0, security_grant = 0;
  int checked = security(identity, &security_status, &security_grant);
  if (checked)
    return checked;
  path_bytes += identity->bytes;
  if (path_bytes > 1048576)
    return 32;
  ULONG returned = 0;
  if (NtQueryKey(key, 2, scratch, SCRATCH_BYTES, &returned) != 0 ||
      returned < 44 || returned > SCRATCH_BYTES)
    return 33;
  BYTE metadata[44];
  memcpy(metadata, scratch, sizeof metadata);
  ULONG children = number(20), values = number(32);
  if (children > MAX_NODES - reserved || values > 4096 - value_count)
    return 34;
  reserved += children;
  WCHAR **names = calloc(children ? children : 1, sizeof(*names));
  if (!names)
    return 35;
  int result = 0;
  for (ULONG i = 0; i < children; ++i) {
    WCHAR name[256];
    DWORD length = 256;
    if (RegEnumKeyExW(key, i, name, &length, NULL, NULL, NULL, NULL) != 0 ||
        !length || length > 255) {
      result = 36;
      goto done;
    }
    for (DWORD j = 0; j < length; ++j)
      if (name[j] == 0 || name[j] == L'\\') {
        result = 37;
        goto done;
      }
    if (_wcsicmp(name, L"__RAX_ABSENT_CHILD_20261029") == 0) {
      result = 38;
      goto done;
    }
    names[i] = calloc(length + 1, sizeof(WCHAR));
    if (!names[i]) {
      result = 39;
      goto done;
    }
    memcpy(names[i], name, length * sizeof(WCHAR));
  }
  printf("%s{\"id\":%u,\"hive\":%u,\"view\":%lu,\"parent\":%d,\"component_"
         "hex\":\"",
         id ? "," : "", id, hive, view, parent);
  hex((BYTE *)component, (ULONG)(wcslen(component) * 2));
  printf("\",\"state\":%d,\"security_status\":%lu,\"security_grant\":%lu,"
         "\"children\":[",
         captured, security_status, security_grant);
  for (ULONG i = 0; i < children; ++i) {
    printf("%s\"", i ? "," : "");
    hex((BYTE *)names[i], (ULONG)(wcslen(names[i]) * 2));
    printf("\"");
  }
  printf("],\"values\":[");
  for (ULONG i = 0; i < values; ++i) {
    if (NtEnumerateValueKey(key, i, 1, scratch, SCRATCH_BYTES, &returned) !=
            0 ||
        returned < 20 || returned > SCRATCH_BYTES) {
      result = 40;
      goto done;
    }
    ULONG offset = number(8), bytes = number(12), length = number(16);
    if (length > 32766 || length % 2 || length > returned - 20 ||
        bytes > 1048576 || offset > returned || bytes > returned - offset) {
      result = 41;
      goto done;
    }
    value_bytes += length + bytes;
    if (++value_count > 4096 || value_bytes > 16777216) {
      result = 42;
      goto done;
    }
    printf("%s{\"name_hex\":\"", i ? "," : "");
    hex(scratch + 20, length);
    printf("\",\"kind\":%lu,\"data_hex\":\"", number(4));
    hex(scratch + offset, bytes);
    printf("\"}");
  }
  if ((ULONG)NtEnumerateValueKey(key, values, 1, scratch, SCRATCH_BYTES,
                                 &returned) != 0x8000001a) {
    result = 43;
    goto done;
  }
  printf("]");
  result = controls(key, captured, names, children);
  if (result)
    goto done;
  if (NtQueryKey(key, 2, scratch, SCRATCH_BYTES, &returned) != 0 ||
      returned < 44 || memcmp(metadata, scratch, 44) != 0) {
    result = 44;
    goto done;
  }
  printf("}");
  for (ULONG i = 0; i < children; ++i) {
    HKEY child = NULL;
    if (RegOpenKeyExW(key, names[i], 0, 0x02000000 | view, &child) != 0 ||
        !child) {
      result = 45;
      goto done;
    }
    result = walk(child, hive, view, (int)id, names[i], depth + 1);
    if (RegCloseKey(child) != 0)
      result = 46;
    if (result)
      goto done;
  }
done:
  for (ULONG i = 0; i < children; ++i)
    free(names[i]);
  free(names);
  return result;
}

int main(void) {
  WCHAR path[] = L"Software\\Microsoft\\Command Processor";
  Root roots[4];
  unsigned int used = 0;
  DWORD before = 0, after = 0;
  OSVERSIONINFOW version = {0};
  version.dwOSVersionInfoSize = sizeof version;
  if (RtlGetVersion(&version) != 0)
    return 50;
  /* Warm predefined-hive bookkeeping, then measure owned native handles. */
  HKEY warm = NULL;
  LONG warmed = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, 0x02000100, &warm);
  if (warmed == 0) {
    if (!warm || RegCloseKey(warm) != 0)
      return 51;
  } else if (warm ||
             (warmed != ERROR_FILE_NOT_FOUND && warmed != ERROR_PATH_NOT_FOUND))
    return 52;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 53;
  scratch = malloc(SCRATCH_BYTES);
  if (!scratch)
    return 54;
  printf("{\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],\"handles_before\":%"
         "lu,\"nodes\":[",
         sizeof(void *), version.dwMajorVersion, version.dwMinorVersion,
         version.dwBuildNumber, before);
  for (unsigned int hive = 0; hive < 2; ++hive) {
    HKEY base = HKEY_LOCAL_MACHINE;
    if (hive) {
      HANDLE user = NULL;
      if (RtlOpenCurrentUser(0x02000000, &user) != 0 || !user)
        return 55;
      base = (HKEY)user;
    }
    for (unsigned int view = 1; view < 3; ++view) {
      HKEY key = NULL;
      LONG status =
          RegOpenKeyExW(base, path, 0, 0x02000000 | views[view], &key);
      int first = -1;
      if (status == 0) {
        if (!key || reserved == MAX_NODES)
          return 56;
        ++reserved;
        first = (int)node_count;
        int result = walk(key, hive, views[view], -1, L"", 0);
        if (RegCloseKey(key) != 0)
          result = 57;
        if (result)
          return result;
      } else if (key || (status != ERROR_FILE_NOT_FOUND &&
                         status != ERROR_PATH_NOT_FOUND))
        return 58;
      roots[used++] = (Root){hive, view, (ULONG)status, first};
    }
    if (hive && NtClose(base) != 0)
      return 59;
  }
  printf("],\"roots\":[");
  for (unsigned int i = 0; i < used; ++i)
    printf("%s{\"hive\":%u,\"view\":%u,\"status\":%lu,\"node\":%d}",
           i ? "," : "", roots[i].hive, roots[i].view, roots[i].status,
           roots[i].node);
  printf("],\"states\":[");
  for (unsigned int i = 0; i < state_count; ++i) {
    printf("%s{\"tags\":%lu,\"granted_access\":%lu,\"name_hex\":\"",
           i ? "," : "", states[i].tags, states[i].grant);
    hex(states[i].name, states[i].bytes);
    printf("\"}");
    free(states[i].name);
  }
  free(scratch);
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 60;
  printf("],\"handles_after\":%lu}\n", after);
  return before == after ? 0 : 61;
}
