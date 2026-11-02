/* Independent complete fixed-subject acquisition. Wire contract: wire-v1.md. */
#include <stdlib.h>
#include <wchar.h>
#include <wincrypt.h>

enum { LS_MAX_KEYS = 16384, LS_MAX_DEPTH = 32, LS_SCRATCH = 1114112 };
typedef struct {
  WCHAR *name;
  ULONG units, type, bytes;
  BYTE *data;
} LsValue;
typedef struct {
  WCHAR *name;
  ULONG units;
  ULONGLONG time;
} LsChild;
static BYTE *ls_wire, *ls_scratch;
static size_t ls_used, ls_capacity, ls_paths, ls_value_bytes, ls_child_bytes;
static ULONG ls_keys, ls_values, ls_children, ls_reserved;

static int ls_append(const void *data, size_t count) {
  if (count > 67108864 - ls_used)
    return 0;
  size_t needed = ls_used + count;
  if (needed > ls_capacity) {
    size_t capacity = ls_capacity ? ls_capacity : 4096;
    while (capacity < needed)
      capacity *= 2;
    BYTE *next = realloc(ls_wire, capacity);
    if (!next)
      return 0;
    ls_wire = next;
    ls_capacity = capacity;
  }
  if (count)
    memcpy(ls_wire + ls_used, data, count);
  ls_used = needed;
  return 1;
}
static int ls_u32(ULONG value) {
  BYTE bytes[4];
  for (unsigned int i = 0; i < 4; ++i)
    bytes[i] = (BYTE)(value >> (i * 8));
  return ls_append(bytes, sizeof bytes);
}
static int ls_u64(ULONGLONG value) {
  BYTE bytes[8];
  for (unsigned int i = 0; i < 8; ++i)
    bytes[i] = (BYTE)(value >> (i * 8));
  return ls_append(bytes, sizeof bytes);
}
static int ls_blob(const void *data, ULONG bytes) {
  return ls_u32(bytes) && ls_append(data, bytes);
}
static ULONG ls_number(size_t offset) {
  ULONG value;
  memcpy(&value, ls_scratch + offset, sizeof value);
  return value;
}
static LONG ls_open(HANDLE parent, const WCHAR *text, ULONG access,
                    HANDLE *key) {
  size_t bytes = wcslen(text) * sizeof(WCHAR);
  if (bytes > 32766)
    return (LONG)0xc000000d;
  Unicode name = {(USHORT)bytes, (USHORT)bytes, (WCHAR *)text};
  Attributes attrs = {sizeof attrs, parent, &name, 0x40, NULL, NULL};
  *key = NULL;
  return NtOpenKeyEx(key, access, &attrs, 0);
}
static int ls_units_compare(const WCHAR *a, ULONG an, const WCHAR *b,
                            ULONG bn) {
  ULONG count = an < bn ? an : bn;
  for (ULONG i = 0; i < count; ++i) {
    if ((USHORT)a[i] < (USHORT)b[i])
      return -1;
    if ((USHORT)a[i] > (USHORT)b[i])
      return 1;
  }
  return an < bn ? -1 : an > bn ? 1 : 0;
}
static int ls_value_compare(const void *a, const void *b) {
  const LsValue *left = a, *right = b;
  return ls_units_compare(left->name, left->units, right->name, right->units);
}
static int ls_child_compare(const void *a, const void *b) {
  const LsChild *left = a, *right = b;
  return ls_units_compare(left->name, left->units, right->name, right->units);
}
static int ls_identity(HANDLE key, WCHAR **name, ULONG *bytes, ULONG *access) {
  ULONG returned = 0;
  if (NtQueryObject(key, 0, ls_scratch, 56, &returned) != 0 || returned != 56)
    return 0;
  *access = ls_number(4);
  if (NtQueryKey(key, 3, ls_scratch, LS_SCRATCH, &returned) != 0 ||
      returned < 4)
    return 0;
  *bytes = ls_number(0);
  if (*bytes > 32766 || *bytes % 2 || *bytes > returned - 4)
    return 0;
  *name = calloc(*bytes / 2 + 1, sizeof(WCHAR));
  if (!*name)
    return 0;
  memcpy(*name, ls_scratch + 4, *bytes);
  return 1;
}

static int ls_node(HANDLE key, ULONG view, unsigned int depth,
                   const WCHAR *expected) {
  WCHAR *canonical = NULL;
  LsValue *values = NULL;
  LsChild *children = NULL;
  ULONG count = 0, subkeys = 0, returned = 0, name_bytes = 0, access = 0;
  BYTE before[44];
  int result = 0;
  if (depth > LS_MAX_DEPTH || ls_keys == LS_MAX_KEYS ||
      !ls_identity(key, &canonical, &name_bytes, &access))
    return 70;
  if (expected && wcscmp(expected, canonical) != 0) {
    result = 71;
    goto done;
  }
  ++ls_keys;
  ls_paths += name_bytes;
  if (ls_paths > 8388608) {
    result = 72;
    goto done;
  }
  HANDLE security = NULL;
  ULONG security_status =
      (ULONG)ls_open(NULL, canonical, 0x01000000, &security);
  if (security_status == 0) {
    if (!security ||
        NtQueryObject(security, 0, ls_scratch, 56, &returned) != 0 ||
        returned != 56 || (ls_number(4) & 0x01000000) == 0) {
      if (security)
        NtClose(security);
      result = 73;
      goto done;
    }
  } else if (security) {
    NtClose(security);
    result = 74;
    goto done;
  }
  if (security && NtClose(security) != 0) {
    result = 75;
    goto done;
  }
  if (!ls_append("KEY1", 4) || !ls_blob(canonical, name_bytes) ||
      !ls_u32(access) || !ls_u32(security_status)) {
    result = 76;
    goto done;
  }
  if (NtQueryKey(key, 2, ls_scratch, LS_SCRATCH, &returned) != 0 ||
      returned < 44 || returned > LS_SCRATCH) {
    result = 77;
    goto done;
  }
  memcpy(before, ls_scratch, sizeof before);
  subkeys = ls_number(20);
  count = ls_number(32);
  if (count > 65536 - ls_values || subkeys > LS_MAX_KEYS - ls_reserved) {
    result = 78;
    goto done;
  }
  ls_reserved += subkeys;
  values = calloc(count ? count : 1, sizeof *values);
  children = calloc(subkeys ? subkeys : 1, sizeof *children);
  if (!values || !children) {
    result = 79;
    goto done;
  }
  for (ULONG i = 0; i < count; ++i) {
    if (NtEnumerateValueKey(key, i, 1, ls_scratch, LS_SCRATCH, &returned) !=
            0 ||
        returned < 20 || returned > LS_SCRATCH) {
      result = 80;
      goto done;
    }
    ULONG offset = ls_number(8), bytes = ls_number(12), length = ls_number(16);
    if (length % 2 || length > 32766 || length > returned - 20 ||
        bytes > 1048576 ||
        (bytes && (offset > returned || bytes > returned - offset))) {
      result = 81;
      goto done;
    }
    ls_value_bytes += length + bytes;
    if (ls_value_bytes > 33554432) {
      result = 82;
      goto done;
    }
    values[i].name = calloc(length / 2 + 1, sizeof(WCHAR));
    values[i].data = malloc(bytes ? bytes : 1);
    if (!values[i].name || !values[i].data) {
      result = 83;
      goto done;
    }
    values[i].units = length / 2;
    values[i].bytes = bytes;
    values[i].type = ls_number(4);
    memcpy(values[i].name, ls_scratch + 20, length);
    /* Native empty REG_SZ values can use DataOffset=UINT32_MAX. */
    if (bytes)
      memcpy(values[i].data, ls_scratch + offset, bytes);
  }
  ls_values += count;
  qsort(values, count, sizeof *values, ls_value_compare);
  if (!ls_u32(count)) {
    result = 84;
    goto done;
  }
  for (ULONG i = 0; i < count; ++i) {
    if (!ls_blob(values[i].name, values[i].units * 2) ||
        !ls_u32(values[i].type) || !ls_blob(values[i].data, values[i].bytes)) {
      result = 85;
      goto done;
    }
  }
  if (!ls_u32(subkeys)) {
    result = 86;
    goto done;
  }
  for (ULONG i = 0; i < subkeys; ++i) {
    WCHAR name[256];
    DWORD units = 256;
    FILETIME time;
    if (RegEnumKeyExW((HKEY)key, i, name, &units, NULL, NULL, NULL, &time) !=
            0 ||
        units == 0 || units > 255) {
      result = 87;
      goto done;
    }
    for (DWORD j = 0; j < units; ++j) {
      if (name[j] == 0 || name[j] == L'\\') {
        result = 88;
        goto done;
      }
    }
    children[i].name = calloc(units + 1, sizeof(WCHAR));
    if (!children[i].name) {
      result = 89;
      goto done;
    }
    children[i].units = units;
    children[i].time =
        (ULONGLONG)time.dwLowDateTime | ((ULONGLONG)time.dwHighDateTime << 32);
    memcpy(children[i].name, name, units * 2);
    ls_child_bytes += units * 2 + 8;
    if (++ls_children > 32768 || ls_child_bytes > 2097152 ||
        !ls_blob(name, units * 2) || !ls_u64(children[i].time)) {
      result = 90;
      goto done;
    }
  }
  if (NtQueryKey(key, 2, ls_scratch, LS_SCRATCH, &returned) != 0 ||
      returned < 44 || memcmp(before, ls_scratch, 44) != 0) {
    result = 91;
    goto done;
  }
  qsort(children, subkeys, sizeof *children, ls_child_compare);
  for (ULONG i = 0; i < subkeys; ++i) {
    size_t units = name_bytes / 2 + 1 + children[i].units;
    if (units > 16383) {
      result = 92;
      goto done;
    }
    WCHAR *path = calloc(units + 1, sizeof(WCHAR));
    if (!path) {
      result = 93;
      goto done;
    }
    memcpy(path, canonical, name_bytes);
    path[name_bytes / 2] = L'\\';
    memcpy(path + name_bytes / 2 + 1, children[i].name, children[i].units * 2);
    HANDLE child = NULL;
    LONG opened = ls_open(key, children[i].name, 0x02000000 | view, &child);
    if (opened != 0 || !child) {
      if (child)
        NtClose(child);
      free(path);
      result = 94;
      goto done;
    }
    result = ls_node(child, view, depth + 1, path);
    free(path);
    if (NtClose(child) != 0)
      result = 95;
    if (result)
      goto done;
  }
done:
  if (values)
    for (ULONG i = 0; i < count; ++i) {
      free(values[i].name);
      free(values[i].data);
    }
  if (children)
    for (ULONG i = 0; i < subkeys; ++i)
      free(children[i].name);
  free(values);
  free(children);
  free(canonical);
  return result;
}
