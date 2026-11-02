/* Fixed read-only opens; the full snapshot digest remains independent. */
static int ls_controls(const WCHAR *logical) {
  const WCHAR suffix[] = L"\\Software\\Classes\\Local Settings";
  const WCHAR absent[] = L"__RAX_ABSENT_LOCAL_SETTINGS_20261029";
  const ULONG views[] = {0, 0x100, 0x200};
  const ULONG requests[] = {0x20019, 0x02000000};
  WCHAR hive_name[512];
  size_t units = wcslen(logical), suffix_units = wcslen(suffix);
  if (units < suffix_units || units >= 512 ||
      wcscmp(logical + units - suffix_units, suffix) != 0)
    return 110;
  wmemcpy(hive_name, logical, units - suffix_units);
  hive_name[units - suffix_units] = 0;
  HANDLE hive = NULL, subject = NULL, extra_parent = NULL;
  WCHAR *canonical = NULL;
  ULONG bytes = 0, access = 0;
  int result = 0;
  if (ls_open(NULL, hive_name, 0x20019, &hive) != 0 || !hive ||
      ls_open(NULL, logical, 0x20019, &subject) != 0 || !subject ||
      !ls_identity(subject, &canonical, &bytes, &access)) {
    result = 111;
    goto done;
  }
  printf(",\"canonical_hex\":\"");
  hex((BYTE *)canonical, bytes);
  printf("\"");
  HANDLE seeds[] = {hive, subject};
  const char *seed_names[] = {"hive_tags", "subject_tags"};
  for (unsigned int i = 0; i < 2; ++i) {
    ULONG returned = 0;
    if (NtQueryKey(seeds[i], 7, ls_scratch, LS_SCRATCH, &returned) != 0 ||
        returned != 4) {
      result = 119;
      goto done;
    }
    printf(",\"%s\":%lu", seed_names[i], ls_number(0));
  }
  printf(",\"opens\":[");
  unsigned int row = 0;
  for (unsigned int route = 0; route < 4; ++route) {
    const WCHAR *base = route == 0   ? logical
                        : route == 1 ? canonical
                        : route == 2 ? suffix + 1
                                     : L"";
    for (unsigned int seed = 0; seed < (route >= 2 ? 3u : 1u); ++seed) {
      HANDLE parent = route == 2 ? hive : route == 3 ? subject : NULL;
      ULONG parent_tags = 0, parent_returned = 0;
      if (seed != 0) {
        if (ls_open(NULL, route == 2 ? hive_name : logical,
                    0x20019 | views[seed], &extra_parent) != 0 ||
            !extra_parent) {
          result = 120;
          goto done;
        }
        parent = extra_parent;
      }
      if (parent && (NtQueryKey(parent, 7, ls_scratch, LS_SCRATCH,
                                &parent_returned) != 0 ||
                     parent_returned != 4)) {
        result = 121;
        goto done;
      }
      if (parent)
        parent_tags = ls_number(0);
      for (unsigned int name = 0; name < 3; ++name) {
        WCHAR path[1024];
        int count = name == 0
                        ? _snwprintf_s(path, 1024, _TRUNCATE, L"%ls", base)
                        : _snwprintf_s(path, 1024, _TRUNCATE, L"%ls%ls%ls%ls",
                                       base, *base ? L"\\" : L"", absent,
                                       name == 2 ? L"\\Child" : L"");
        if (count < 0 || (size_t)count > 32766 / sizeof(WCHAR)) {
          result = 112;
          goto done;
        }
        Unicode text = {(USHORT)(count * sizeof(WCHAR)),
                        (USHORT)(count * sizeof(WCHAR)), path};
        Attributes attrs = {sizeof attrs, parent, &text, 0x40, NULL, NULL};
        for (unsigned int extended = 0; extended < 2; ++extended) {
          for (unsigned int view = 0; view < 3; ++view) {
            for (unsigned int request = 0; request < 2; ++request) {
              HANDLE key = NULL;
              ULONG desired = requests[request] | views[view];
              ULONG status =
                  (ULONG)(extended ? NtOpenKeyEx(&key, desired, &attrs, 0)
                                   : NtOpenKey(&key, desired, &attrs));
              printf("%s{\"route\":%u,\"parent_view\":%lu,\"parent_tags\":%lu,"
                     "\"name\":%u,\"extended\":%u,"
                     "\"view\":%lu,\"request\":%lu,\"status\":%lu,"
                     "\"handle_nonzero\":%u",
                     row++ ? "," : "", route, views[seed], parent_tags, name,
                     extended, views[view], requests[request], status,
                     key != NULL);
              if (status == 0) {
                WCHAR *actual = NULL;
                ULONG actual_bytes = 0, granted = 0, returned = 0;
                if (!key ||
                    !ls_identity(key, &actual, &actual_bytes, &granted)) {
                  if (key)
                    NtClose(key);
                  result = 113;
                  goto done;
                }
                ULONG tag_status = (ULONG)NtQueryKey(key, 7, ls_scratch,
                                                     LS_SCRATCH, &returned);
                if (tag_status != 0 || returned != 4 || actual_bytes != bytes ||
                    memcmp(actual, canonical, bytes)) {
                  free(actual);
                  NtClose(key);
                  result = 114;
                  goto done;
                }
                printf(",\"granted_access\":%lu,\"tags\":%lu", granted,
                       ls_number(0));
                free(actual);
                if (NtClose(key) != 0) {
                  result = 115;
                  goto done;
                }
              } else if (key) {
                NtClose(key);
                result = 116;
                goto done;
              }
              printf("}");
            }
          }
        }
      }
      if (extra_parent) {
        if (NtClose(extra_parent) != 0) {
          extra_parent = NULL;
          result = 122;
          goto done;
        }
        extra_parent = NULL;
      }
    }
  }
  printf("]");
done:
  free(canonical);
  if (extra_parent && NtClose(extra_parent) != 0)
    result = 123;
  if (subject && NtClose(subject) != 0)
    result = 117;
  if (hive && NtClose(hive) != 0)
    result = 118;
  return result;
}
