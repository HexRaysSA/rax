/* Bounded closure of native reopens of the fixed System Software parent.
 * Derived from the retained CMD graph producer; its original stays immutable. */
#define main command_absolute_control_main
#include "../native-command-processor/absolute-v1.c"
#undef main

enum { CAPACITY = 16, EDGES = CAPACITY * 8 };
typedef struct {
  HANDLE key;
  ULONG tags, grant, bytes;
  BYTE name[4080];
} State;
typedef struct {
  unsigned int source, extended;
  ULONG view, status;
  int target;
} Edge;
typedef struct {
  ULONG view, status;
  unsigned int native;
  int target;
} Seed;
static const ULONG views[] = {0, 0x100, 0x200, 0x300};
static const WCHAR path[] = L"System\\Software";

static int add(State *states, unsigned int *count, HANDLE key) {
  State candidate;
  Buffer b;
  ULONG returned = 0;
  memset(&candidate, 0, sizeof candidate);
  candidate.key = key;
  if (NtQueryKey(key, 7, &b, sizeof b, &returned) != 0 || returned != 4)
    return -2;
  candidate.tags = word(&b, 0);
  if (NtQueryObject(key, 0, &b, 56, &returned) != 0 || returned != 56)
    return -3;
  candidate.grant = word(&b, 4);
  if (NtQueryKey(key, 3, &b, sizeof b, &returned) != 0 || returned < 4 ||
      returned > sizeof b)
    return -4;
  candidate.bytes = word(&b, 0);
  if (candidate.bytes > sizeof candidate.name ||
      candidate.bytes > returned - 4 || candidate.bytes % 2)
    return -5;
  memcpy(candidate.name, b.bytes + 4, candidate.bytes);
  for (unsigned int i = 0; i < *count; ++i) {
    if (states[i].tags == candidate.tags &&
        states[i].bytes == candidate.bytes &&
        memcmp(states[i].name, candidate.name, candidate.bytes) == 0) {
      if (states[i].grant != candidate.grant || NtClose(key) != 0)
        return -6;
      return (int)i;
    }
  }
  if (*count == CAPACITY)
    return -7;
  states[*count] = candidate;
  return (int)(*count)++;
}

static int graph(HKEY hive, unsigned int index) {
  State states[CAPACITY];
  Edge edges[EDGES];
  Seed seeds[7];
  unsigned int count = 0, used = 0;
  memset(states, 0, sizeof states);
  int physical = -1;
  for (unsigned int view = 0; view < 3; ++view) {
    HKEY key = NULL;
    LONG status = RegOpenKeyExW(hive, path, 0, 0x02000000 | views[view], &key);
    int target = -1;
    if (status == 0) {
      if (key == NULL)
        return 30;
      target = add(states, &count, key);
      if (target < 0)
        return 31;
      if (view == 2)
        physical = target;
    } else if (key != NULL || (status != ERROR_FILE_NOT_FOUND &&
                               status != ERROR_PATH_NOT_FOUND))
      return 32;
    seeds[used++] = (Seed){views[view], (ULONG)status, 0, target};
  }
  if (physical >= 0) {
    WCHAR canonical[2040];
    memcpy(canonical, states[physical].name, states[physical].bytes);
    Unicode name = {(USHORT)states[physical].bytes,
                    (USHORT)states[physical].bytes, canonical};
    Attributes attrs = {sizeof attrs, NULL, &name, 0x40, NULL, NULL};
    for (unsigned int view = 0; view < 4; ++view) {
      HANDLE key = NULL;
      LONG status = NtOpenKeyEx(&key, 0x02000000 | views[view], &attrs, 0);
      int target = -1;
      if (status == 0) {
        if (key == NULL)
          return 33;
        target = add(states, &count, key);
        if (target < 0)
          return 34;
      } else if (key != NULL) {
        NtClose(key);
        return 35;
      }
      seeds[used++] = (Seed){views[view], (ULONG)status, 1, target};
    }
  }
  unsigned int edge_count = 0;
  for (unsigned int source = 0; source < count; ++source) {
    WCHAR empty[] = L"";
    Unicode name = {0, 2, empty};
    Attributes attrs = {sizeof attrs, states[source].key, &name, 0x40, NULL,
                        NULL};
    for (unsigned int extended = 0; extended < 2; ++extended) {
      for (unsigned int view = 0; view < 4; ++view) {
        HANDLE key = NULL;
        LONG status =
            extended ? NtOpenKeyEx(&key, 0x02000000 | views[view], &attrs, 0)
                     : NtOpenKey(&key, 0x02000000 | views[view], &attrs);
        int target = -1;
        if (status == 0) {
          if (key == NULL)
            return 36;
          target = add(states, &count, key);
          if (target < 0)
            return 37;
        } else if (key != NULL) {
          NtClose(key);
          return 38;
        }
        if (edge_count == EDGES)
          return 39;
        edges[edge_count++] =
            (Edge){source, extended, views[view], (ULONG)status, target};
      }
    }
  }
  printf("%s{\"hive\":%u,\"states\":[", index ? "," : "", index);
  for (unsigned int i = 0; i < count; ++i) {
    printf("%s{\"tags\":%lu,\"granted_access\":%lu,\"name_hex\":\"",
           i ? "," : "", states[i].tags, states[i].grant);
    hex(states[i].name, states[i].bytes);
    printf("\"}");
  }
  printf("],\"seeds\":[");
  for (unsigned int i = 0; i < used; ++i) {
    printf("%s{\"native\":%u,\"view\":%lu,\"status\":%lu,\"target\":%d}",
           i ? "," : "", seeds[i].native, seeds[i].view, seeds[i].status,
           seeds[i].target);
  }
  printf("],\"edges\":[");
  for (unsigned int i = 0; i < edge_count; ++i) {
    Edge *e = &edges[i];
    printf("%s{\"source\":%u,\"extended\":%u,\"view\":%lu,\"status\":%lu,"
           "\"target\":%d}",
           i ? "," : "", e->source, e->extended, e->view, e->status, e->target);
  }
  printf("]}");
  for (unsigned int i = 0; i < count; ++i)
    if (NtClose(states[i].key) != 0)
      return 40;
  return 0;
}

int main(void) {
  HKEY hives[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  DWORD initial = 0, before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &initial))
    return 41;
  for (unsigned int hive = 0; hive < 2; ++hive) {
    for (unsigned int view = 0; view < 3; ++view) {
      HKEY key = NULL;
      LONG status =
          RegOpenKeyExW(hives[hive], path, 0, 0x02000000 | views[view], &key);
      if (status == 0) {
        if (key == NULL || RegCloseKey(key) != 0)
          return 42;
      } else if (key != NULL || (status != ERROR_FILE_NOT_FOUND &&
                                 status != ERROR_PATH_NOT_FOUND))
        return 43;
    }
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 44;
  printf("{\"pointer_bytes\":%zu,\"handles_initial\":%lu,\"handles_before\":%"
         "lu,\"hives\":[",
         sizeof(void *), initial, before);
  for (unsigned int hive = 0; hive < 2; ++hive) {
    int result = graph(hives[hive], hive);
    if (result)
      return result;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 45;
  printf("],\"handles_after\":%lu}\n", after);
  return before == after ? 0 : 46;
}
