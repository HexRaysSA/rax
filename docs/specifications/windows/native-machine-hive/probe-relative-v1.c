/* Keep the absolute producer intact; reuse its native types and query helpers.
 */
#define main absolute_root_capture
#include "probe-v1.c"
#undef main
#include <wchar.h>

int main(void) {
  WCHAR root_name[] = L"\\REGISTRY\\MACHINE";
  WCHAR *children[] = {L"",
                       L"System\\CurrentControlSet\\Control\\Nls\\CodePage",
                       L"SOFTWARE\\Microsoft\\AppModel\\Lookaside\\machine"};
  const ULONG views[] = {0, 0x100, 0x200, 0x300};
  Unicode root = {34, 34, root_name};
  Attributes absolute = {sizeof absolute, NULL, &root, 0x40, NULL, NULL};
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 20;
  printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[",
         sizeof(void *), before);
  unsigned int row = 0;
  for (size_t parent_view = 0; parent_view < 3; ++parent_view) {
    HANDLE parent = NULL;
    if (NtOpenKeyEx(&parent, 0x20019 | views[parent_view], &absolute, 0) != 0)
      return 21;
    for (size_t child = 0; child < sizeof children / sizeof children[0];
         ++child) {
      USHORT bytes = (USHORT)(wcslen(children[child]) * 2);
      Unicode name = {bytes, bytes, children[child]};
      Attributes relative = {sizeof relative, parent, &name, 0x40, NULL, NULL};
      for (size_t view = 0; view < 4; ++view) {
        HANDLE handle = NULL;
        LONG status = NtOpenKeyEx(&handle, 0x20019 | views[view], &relative, 0);
        printf(
            "%s{\"parent_view\":%lu,\"child\":%zu,\"view\":%lu,\"status\":%lu",
            row++ ? "," : "", views[parent_view], child, views[view],
            (ULONG)status);
        if (status == 0) {
          Buffer buffer;
          ULONG returned = 0;
          LONG tags = NtQueryKey(handle, 7, &buffer, sizeof buffer, &returned);
          printf(",\"tags_status\":%lu", (ULONG)tags);
          if (tags == 0) {
            if (returned != 4)
              return 22;
            printf(",\"tags\":%lu", word(&buffer, 0));
          }
          returned = 0;
          LONG named = NtQueryKey(handle, 3, &buffer, sizeof buffer, &returned);
          printf(",\"name_status\":%lu", (ULONG)named);
          if (named == 0) {
            ULONG length = word(&buffer, 0);
            if (returned < 4 || returned > sizeof buffer ||
                length > returned - 4)
              return 23;
            printf(",\"name_hex\":\"");
            hex(buffer.bytes + 4, length);
            printf("\"");
          }
          if (NtClose(handle) != 0)
            return 24;
        } else if (handle != NULL) {
          NtClose(handle);
          return 25;
        }
        printf("}");
      }
    }
    if (NtClose(parent) != 0)
      return 26;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 27;
  printf("],\"handles_after\":%lu}\n", after);
  return before == after ? 0 : 28;
}
