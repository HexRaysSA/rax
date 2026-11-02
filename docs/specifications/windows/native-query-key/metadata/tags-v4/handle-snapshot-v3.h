/* Own-process handle snapshots. Layout: retained PHNT ntpsapi.h,
 * ProcessHandleInformation=51 and PROCESS_HANDLE_TABLE_ENTRY_INFO. */
typedef struct {
  HANDLE value;
  SIZE_T handle_count, pointer_count;
  ULONG access, type_index, attributes, reserved;
} HandleEntry;
typedef struct {
  ULONG_PTR count, reserved;
  HandleEntry entries[1];
} HandleSnapshot;
_Static_assert(sizeof(HandleEntry) == (sizeof(void *) == 8 ? 40 : 28),
               "handle entry layout");
_Static_assert(offsetof(HandleSnapshot, entries) == 2 * sizeof(void *),
               "handle snapshot header");

static int handle_snapshot(const char *phase) {
  __declspec(align(16)) static unsigned char storage[32768];
  __declspec(align(16)) static unsigned char type_storage[4096];
  QueryFn process_query = (QueryFn)GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
  QueryFn object_query =
      (QueryFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
  ULONG returned = 0;
  DWORD public_count = 0;
  if (!process_query || !object_query ||
      !GetProcessHandleCount(GetCurrentProcess(), &public_count))
    return 30;
  memset(storage, 0, sizeof(storage));
  LONG status = process_query(GetCurrentProcess(), 51, storage, sizeof(storage),
                              &returned);
  printf("{\"kind\":\"handle_snapshot\",\"phase\":\"%s\","
         "\"status\":%lu,\"public_count\":%lu,\"returned\":%lu",
         phase, (ULONG)status, public_count, returned);
  if (status < 0) {
    printf("}\n");
    return 31;
  }
  HandleSnapshot *snapshot = (HandleSnapshot *)storage;
  if (snapshot->count > 512) {
    printf(",\"bounds_error\":true}\n");
    fflush(stdout);
    return 32;
  }
  SIZE_T required =
      offsetof(HandleSnapshot, entries) + snapshot->count * sizeof(HandleEntry);
  if (returned > sizeof(storage) || returned < required ||
      returned - required > 8) {
    printf(",\"bounds_error\":true}\n");
    fflush(stdout);
    return 32;
  }
  printf(",\"count\":%zu,\"entries\":[", (SIZE_T)snapshot->count);
  for (SIZE_T i = 0; i < snapshot->count; ++i) {
    HandleEntry *entry = &snapshot->entries[i];
    ULONG type_returned = 0;
    memset(type_storage, 0, sizeof(type_storage));
    LONG type_status = object_query(entry->value, 2, type_storage,
                                    sizeof(type_storage), &type_returned);
    printf("%s{\"handle\":\"%llx\",\"access\":%lu,\"type_index\":%lu,"
           "\"attributes\":%lu,\"type_status\":%lu,\"type_utf16\":\"",
           i ? "," : "", (unsigned long long)(uintptr_t)entry->value,
           entry->access, entry->type_index, entry->attributes,
           (ULONG)type_status);
    if (type_status == 0) {
      UNICODE_STRING *name = (UNICODE_STRING *)type_storage;
      uintptr_t first = (uintptr_t)type_storage;
      uintptr_t end = first + sizeof(type_storage);
      uintptr_t start = (uintptr_t)name->Buffer;
      if (name->Length % 2 || name->Length > name->MaximumLength ||
          type_returned > sizeof(type_storage) ||
          (name->Length &&
           (start < first || start > end || name->Length > end - start))) {
        printf("\",\"bounds_error\":true}]}\n");
        fflush(stdout);
        return 33;
      }
      for (unsigned j = 0; j < name->Length / 2; ++j)
        printf("%02x%02x", name->Buffer[j] & 255, name->Buffer[j] >> 8);
    }
    printf("\"}");
  }
  printf("]}\n");
  return fflush(stdout) ? 34 : 0;
}
