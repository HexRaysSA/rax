/* Fixed Command Processor absolute NT opens; read/query/close only. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef struct {
  USHORT length, maximum;
  WCHAR *buffer;
} Unicode;
typedef struct {
  ULONG length;
  HANDLE root;
  Unicode *name;
  ULONG flags;
  void *security, *qos;
} Attributes;
__declspec(dllimport) LONG NTAPI NtOpenKey(HANDLE *, ULONG, Attributes *);
__declspec(dllimport) LONG NTAPI NtOpenKeyEx(HANDLE *, ULONG, Attributes *,
                                             ULONG);
__declspec(dllimport) LONG NTAPI NtQueryKey(HANDLE, ULONG, void *, ULONG,
                                            ULONG *);
__declspec(dllimport) LONG NTAPI NtQueryObject(HANDLE, ULONG, void *, ULONG,
                                               ULONG *);
__declspec(dllimport) LONG NTAPI NtEnumerateValueKey(HANDLE, ULONG, ULONG,
                                                     void *, ULONG, ULONG *);
__declspec(dllimport) LONG NTAPI NtClose(HANDLE);
__declspec(dllimport) LONG NTAPI RtlGetVersion(OSVERSIONINFOW *);
_Static_assert(sizeof(Attributes) == (sizeof(void *) == 8 ? 48 : 24),
               "OBJECT_ATTRIBUTES");
typedef union {
  ULONGLONG alignment;
  BYTE bytes[4096];
} Buffer;

static ULONG word(const Buffer *buffer, size_t offset) {
  ULONG value;
  memcpy(&value, buffer->bytes + offset, sizeof value);
  return value;
}
static void hex(const BYTE *bytes, ULONG count) {
  for (ULONG i = 0; i < count; ++i)
    printf("%02x", (unsigned int)bytes[i]);
}

#ifndef RAX_CMD_KEY
#define RAX_CMD_KEY                                                            \
  L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\Command Processor"
#endif

int main(void) {
  WCHAR path[] = RAX_CMD_KEY;
  Unicode name = {(USHORT)(sizeof path - sizeof path[0]),
                  (USHORT)(sizeof path - sizeof path[0]), path};
  Attributes attributes = {sizeof attributes, NULL, &name, 0x40, NULL, NULL};
  const ULONG requests[] = {
      0,          1,          2,          8,          0x20,       0x20019,
      0xf003f,    0x02000000, 0x80000000, 0x40000000, 0x20000000, 0x10000000,
      0x00100000, 0x01000000, 0x03000000, 0x04000000, 0x82000000};
  const ULONG views[] = {0, 0x100, 0x200, 0x300};
  DWORD before = 0, after = 0;
  SYSTEM_INFO system;
  OSVERSIONINFOW version = {0};
  version.dwOSVersionInfoSize = sizeof version;
  if (RtlGetVersion(&version) != 0)
    return 2;
  GetNativeSystemInfo(&system);
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 3;
  printf("{\"pointer_bytes\":%zu,\"native_architecture\":%u,\"kernel\":[%lu,%"
         "lu,%lu],"
         "\"handles_before\":%lu,\"rows\":[",
         sizeof(void *), (unsigned int)system.wProcessorArchitecture,
         version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber,
         before);
  unsigned int row = 0;
  for (unsigned int extended = 0; extended < 2; ++extended) {
    for (size_t index = 0; index < sizeof requests / sizeof requests[0];
         ++index) {
      for (size_t view = 0; view < sizeof views / sizeof views[0]; ++view) {
        HANDLE handle = NULL;
        ULONG requested = requests[index] | views[view];
        LONG opened = extended ? NtOpenKeyEx(&handle, requested, &attributes, 0)
                               : NtOpenKey(&handle, requested, &attributes);
        printf("%s{\"extended\":%u,\"request\":%lu,\"view\":%lu,\"status\":%lu,"
               "\"handle_nonzero\":%u",
               row++ ? "," : "", extended, requests[index], views[view],
               (ULONG)opened, handle != NULL);
        if (opened == 0) {
          Buffer buffer;
          ULONG returned = 0;
          memset(&buffer, 0xa5, sizeof buffer);
          LONG status = NtQueryObject(handle, 0, &buffer, 56, &returned);
          printf(",\"basic_status\":%lu,\"basic_length\":%lu", (ULONG)status,
                 returned);
          if (status == 0) {
            if (returned != 56)
              return 4;
            printf(",\"granted_access\":%lu", word(&buffer, 4));
          }
          returned = 0;
          status = NtQueryKey(handle, 7, &buffer, sizeof buffer, &returned);
          printf(",\"tags_status\":%lu", (ULONG)status);
          if (status == 0) {
            if (returned != 4)
              return 5;
            printf(",\"tags\":%lu", word(&buffer, 0));
          }
          returned = 0;
          status = NtQueryKey(handle, 2, &buffer, sizeof buffer, &returned);
          printf(",\"full_status\":%lu", (ULONG)status);
          if (status == 0) {
            if (returned < 44 || returned > sizeof buffer)
              return 6;
            printf(",\"children\":%lu,\"values\":%lu", word(&buffer, 20),
                   word(&buffer, 32));
          }
          returned = 0;
          status = NtQueryKey(handle, 3, &buffer, sizeof buffer, &returned);
          printf(",\"name_status\":%lu", (ULONG)status);
          if (status == 0) {
            ULONG bytes = word(&buffer, 0);
            if (returned < 4 || returned > sizeof buffer ||
                bytes > returned - 4 || bytes % 2)
              return 7;
            printf(",\"name_hex\":\"");
            hex(buffer.bytes + 4, bytes);
            printf("\"");
          }
          returned = 0;
          status = NtEnumerateValueKey(handle, 0, 1, &buffer, sizeof buffer,
                                       &returned);
          printf(",\"value_status\":%lu", (ULONG)status);
          if (status == 0) {
            ULONG offset = word(&buffer, 8), bytes = word(&buffer, 12),
                  name_bytes = word(&buffer, 16);
            if (returned < 20 || returned > sizeof buffer ||
                name_bytes > returned - 20 || offset > returned ||
                bytes > returned - offset)
              return 8;
            printf(",\"value_type\":%lu,\"value_name_hex\":\"",
                   word(&buffer, 4));
            hex(buffer.bytes + 20, name_bytes);
            printf("\",\"value_data_hex\":\"");
            hex(buffer.bytes + offset, bytes);
            printf("\"");
          }
          LONG closed = NtClose(handle);
          printf(",\"close_status\":%lu", (ULONG)closed);
          if (closed != 0)
            return 9;
        } else if (handle != NULL) {
          NtClose(handle);
          return 10;
        }
        printf("}");
      }
    }
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 11;
  printf("],\"handles_after\":%lu}\n", after);
  return before == after ? 0 : 12;
}
