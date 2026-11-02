/* Finite read/query/close controls for the fixed machine/user CMD leaves. */
#define main command_absolute_control_main
#include "absolute-v1.c"
#undef main

__declspec(dllimport) LONG NTAPI NtEnumerateKey(HANDLE, ULONG, ULONG, void *,
                                                ULONG, ULONG *);
__declspec(dllimport) LONG NTAPI RtlOpenCurrentUser(ULONG, HANDLE *);
static WCHAR path[] = L"Software\\Microsoft\\Command Processor";
static const ULONG views[] = {0, 0x100, 0x200, 0x300};

static LONG open_root(size_t hive, HANDLE *out) {
  if (hive == 1)
    return RtlOpenCurrentUser(0x02000000, out);
  WCHAR machine[] = L"\\REGISTRY\\MACHINE";
  Unicode name = {34, 36, machine};
  Attributes attrs = {sizeof attrs, NULL, &name, 0x40, NULL, NULL};
  return NtOpenKeyEx(out, 0x02000000, &attrs, 0);
}

static int describe(HANDLE key) {
  Buffer b;
  ULONG returned = 0;
  LONG status = NtQueryObject(key, 0, &b, 56, &returned);
  if (status != 0 || returned != 56)
    return 40;
  printf("\"granted_access\":%lu", word(&b, 4));
  status = NtQueryKey(key, 7, &b, sizeof b, &returned);
  if (status != 0 || returned != 4)
    return 41;
  printf(",\"tags\":%lu", word(&b, 0));
  status = NtQueryKey(key, 3, &b, sizeof b, &returned);
  if (status != 0 || returned < 4 || returned > sizeof b ||
      word(&b, 0) > returned - 4 || word(&b, 0) % 2)
    return 42;
  printf(",\"name_hex\":\"");
  hex(b.bytes + 4, word(&b, 0));
  printf("\"");
  return 0;
}

static int content(HANDLE key) {
  Buffer b;
  ULONG returned = 0;
  LONG status = NtQueryKey(key, 2, &b, sizeof b, &returned);
  if (status != 0 || returned < 44 || returned > sizeof b)
    return 43;
  ULONG children = word(&b, 20), count = word(&b, 32);
  if (children > 32 || count > 64)
    return 44;
  printf(",\"children\":%lu,\"values\":[", children);
  for (ULONG index = 0; index <= count; ++index) {
    status = NtEnumerateValueKey(key, index, 1, &b, sizeof b, &returned);
    if (index == count) {
      if ((ULONG)status != 0x8000001a)
        return 45;
      break;
    }
    if (status != 0 || returned < 20 || returned > sizeof b)
      return 46;
    ULONG offset = word(&b, 8), bytes = word(&b, 12), name_bytes = word(&b, 16);
    if (name_bytes > returned - 20 || name_bytes % 2 || offset > returned ||
        bytes > returned - offset)
      return 47;
    printf("%s{\"kind\":%lu,\"name_hex\":\"", index ? "," : "", word(&b, 4));
    hex(b.bytes + 20, name_bytes);
    printf("\",\"data_hex\":\"");
    hex(b.bytes + offset, bytes);
    printf("\"}");
  }
  printf("],\"child_names\":[");
  for (ULONG index = 0; index <= children; ++index) {
    status = NtEnumerateKey(key, index, 0, &b, sizeof b, &returned);
    if (index == children) {
      if ((ULONG)status != 0x8000001a)
        return 48;
      break;
    }
    if (status != 0 || returned < 16 || returned > sizeof b ||
        word(&b, 12) > returned - 16 || word(&b, 12) % 2)
      return 49;
    printf("%s\"", index ? "," : "");
    hex(b.bytes + 16, word(&b, 12));
    printf("\"");
  }
  printf("]");
  return 0;
}

static int self_opens(HANDLE parent) {
  WCHAR empty[] = L"";
  Unicode name = {0, 2, empty};
  Attributes relative = {sizeof relative, parent, &name, 0x40, NULL, NULL};
  printf(",\"self_opens\":[");
  for (unsigned int extended = 0; extended < 2; ++extended) {
    for (size_t view = 0; view < 4; ++view) {
      HANDLE key = NULL;
      LONG status =
          extended ? NtOpenKeyEx(&key, 0x02000000 | views[view], &relative, 0)
                   : NtOpenKey(&key, 0x02000000 | views[view], &relative);
      printf("%s{\"extended\":%u,\"view\":%lu,\"status\":%lu",
             extended || view ? "," : "", extended, views[view], (ULONG)status);
      if (status == 0) {
        if (key == NULL)
          return 50;
        printf(",");
        int result = describe(key);
        if (result)
          return result;
        if (NtClose(key) != 0)
          return 51;
      } else if (key != NULL) {
        NtClose(key);
        return 52;
      }
      printf("}");
    }
  }
  printf("]");
  return 0;
}

int main(void) {
  HKEY hives[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  DWORD initial = 0, before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &initial))
    return 53;
  /* Separate first-use Win32 predefined-root initialization from the measured
     campaign. The identity of any startup-only retained handle is not assumed.
   */
  for (size_t hive = 0; hive < 2; ++hive) {
    for (size_t view = 0; view < 3; ++view) {
      HKEY key = NULL;
      LONG status =
          RegOpenKeyExW(hives[hive], path, 0, 0x02000000 | views[view], &key);
      if (status == 0) {
        if (key == NULL || RegCloseKey(key) != 0)
          return 54;
      } else if (key != NULL || (status != ERROR_FILE_NOT_FOUND &&
                                 status != ERROR_PATH_NOT_FOUND))
        return 55;
    }
    HANDLE root = NULL;
    if (open_root(hive, &root) != 0 || root == NULL || NtClose(root) != 0)
      return 56;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 57;
  printf("{\"pointer_bytes\":%zu,\"handles_initial\":%lu,\"handles_before\":%"
         "lu,\"hives\":[",
         sizeof(void *), initial, before);
  for (size_t hive = 0; hive < 2; ++hive) {
    HANDLE root = NULL;
    if (open_root(hive, &root) != 0 || root == NULL)
      return 58;
    printf("%s{\"hive\":%zu,\"root\":{", hive ? "," : "", hive);
    int result = describe(root);
    if (result)
      return result;
    printf("},\"native_relative\":[");
    Unicode name = {(USHORT)(sizeof path - sizeof path[0]), sizeof path, path};
    Attributes attrs = {sizeof attrs, root, &name, 0x40, NULL, NULL};
    for (unsigned int extended = 0; extended < 2; ++extended) {
      for (size_t view = 0; view < 4; ++view) {
        HANDLE key = NULL;
        LONG status =
            extended ? NtOpenKeyEx(&key, 0x02000000 | views[view], &attrs, 0)
                     : NtOpenKey(&key, 0x02000000 | views[view], &attrs);
        printf("%s{\"extended\":%u,\"view\":%lu,\"status\":%lu",
               extended || view ? "," : "", extended, views[view],
               (ULONG)status);
        if (status == 0) {
          if (key == NULL)
            return 59;
          printf(",");
          result = describe(key);
          if (result)
            return result;
          if (NtClose(key) != 0)
            return 60;
        } else if (key != NULL) {
          NtClose(key);
          return 61;
        }
        printf("}");
      }
    }
    if (NtClose(root) != 0)
      return 62;
    printf("],\"captures\":[");
    for (size_t acquisition = 0; acquisition < 4; ++acquisition) {
      ULONG view = views[acquisition == 3 ? 2 : acquisition];
      HKEY key = NULL;
      LONG status =
          RegOpenKeyExW(hives[hive], path, 0, 0x02000000 | view, &key);
      printf("%s{\"acquisition\":%zu,\"view\":%lu,\"open_status\":%lu,\"handle_"
             "nonzero\":%u",
             acquisition ? "," : "", acquisition, view, (ULONG)status,
             key != NULL);
      if (status != 0) {
        if (key != NULL ||
            (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND))
          return 63;
        printf("}");
        continue;
      }
      if (key == NULL)
        return 64;
      if (acquisition == 3) {
        WCHAR empty[] = L"";
        Unicode same = {0, 2, empty};
        Attributes relative = {sizeof relative, key, &same, 0x40, NULL, NULL};
        HANDLE reopened = NULL;
        if (NtOpenKeyEx(&reopened, 0x02000100, &relative, 0) != 0 ||
            reopened == NULL)
          return 65;
        if (RegCloseKey(key) != 0)
          return 66;
        key = reopened;
      }
      printf(",");
      result = describe(key);
      if (result)
        return result;
      result = content(key);
      if (result)
        return result;
      result = self_opens(key);
      if (result)
        return result;
      if (NtClose(key) != 0)
        return 67;
      printf("}");
    }
    printf("]}");
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 68;
  printf("],\"handles_after\":%lu}\n", after);
  return before == after ? 0 : 69;
}
