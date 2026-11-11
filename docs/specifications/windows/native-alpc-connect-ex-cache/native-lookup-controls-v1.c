#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  ULONG Flags;
  SECURITY_QUALITY_OF_SERVICE SecurityQos;
  SIZE_T MaxMessageLength, MemoryBandwidth, MaxPoolUsage, MaxSectionSize,
      MaxViewSize, MaxTotalSectionSize;
  ULONG DupObjectTypes;
#if defined(_WIN64)
  ULONG Reserved;
#endif
} PortAttributes;
typedef LONG(NTAPI *ConnectEx)(PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
                             PortAttributes *, ULONG, PSECURITY_DESCRIPTOR,
                             void *, SIZE_T *, void *, void *, LARGE_INTEGER *);
typedef LONG(NTAPI *InitializeAttributes)(ULONG, void *, SIZE_T, SIZE_T *);
typedef void *(NTAPI *GetAttribute)(void *, ULONG);
typedef LONG(NTAPI *QueryObject)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef LONG(NTAPI *Send)(HANDLE, ULONG, void *, void *, void *, SIZE_T *, void *, LARGE_INTEGER *);
typedef LONG(NTAPI *QuerySection)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);
typedef LONG(NTAPI *CompareObjects)(HANDLE, HANDLE);
typedef LONG(NTAPI *MapSection)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T, LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
typedef LONG(NTAPI *UnmapSection)(HANDLE, void *);
/* Caller ABI selected by the measured NTDLL helper, independently checked by
 * required size, object type, granted access and the returned mapped view. */
typedef struct {
  ULONG Flags;
  HANDLE Handle;
  ULONG ObjectType;
  ACCESS_MASK DesiredAccess;
} CallerHandleAttribute;

/* Filled only from the complete, independently retained stopped-guest capture.
 * This is one fixed normal connection, with no arbitrary guest data forwarding. */
static BYTE server_security[] = {1, 0, 20, 128, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 52, 0, 0, 0, 2, 0, 32, 0, 1, 0, 0, 0, 20, 0, 24, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 19, 0, 2, 0, 0, 0, 16, 0, 0, 2, 0, 48, 0, 1, 0, 0, 0, 0, 0, 40, 0, 1, 0, 0, 0, 1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 226, 171, 119, 216, 188, 124, 30, 146, 72, 114, 14, 244, 131, 25, 194, 1, 84, 253, 208, 30};

int main(void) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  ConnectEx connect_ex = (ConnectEx)GetProcAddress(ntdll, "NtAlpcConnectPortEx");
  InitializeAttributes initialize = (InitializeAttributes)GetProcAddress(
      ntdll, "AlpcInitializeMessageAttribute");
  GetAttribute get_attribute = (GetAttribute)GetProcAddress(ntdll, "AlpcGetMessageAttribute");
  QueryObject query_object = (QueryObject)GetProcAddress(ntdll, "NtQueryObject");
  Send send = (Send)GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
  if (!connect_ex || !initialize || !get_attribute || !query_object || !send ||
      setvbuf(stdout, NULL, _IONBF, 0)) return 10;
  BYTE sid[SECURITY_MAX_SID_SIZE] = {0};
  WCHAR domain[256];
  DWORD sid_bytes = sizeof(sid), domain_characters = 256;
  SID_NAME_USE use = SidTypeUnknown;
  SetLastError(0);
  BOOL lookup = LookupAccountNameW(NULL, L"NT SERVICE\\XtaCache", sid,
                                  &sid_bytes, domain, &domain_characters, &use);
  DWORD lookup_error = lookup ? 0 : GetLastError();
  if (lookup) {
    if (!IsValidSid(sid)) return 15;
    sid_bytes = GetLengthSid(sid);
    if (sid_bytes > sizeof(sid)) return 16;
  }
  BOOL sid_matches = lookup && sid_bytes == sizeof(server_security) - 68 &&
                     memcmp(sid, server_security + 68, sid_bytes) == 0;
  printf("ACCOUNT lookup=%u error=%lu sid_bytes=%lu sid_matches=%u use=%u sid=",
         (unsigned)lookup, lookup_error, sid_bytes, (unsigned)sid_matches,
         (unsigned)use);
  if (lookup) for (DWORD i = 0; i < sid_bytes; ++i) printf("%02X", (unsigned)sid[i]);
  putchar('\n');
  static WCHAR path[] = L"\\{BEC19D6F-D7B2-41A8-860C-8787BB964F2D}";
  UNICODE_STRING name = {sizeof(path) - sizeof(WCHAR), sizeof(path), path};
  OBJECT_ATTRIBUTES connection = {0};
  connection.Length = sizeof(connection);
  connection.ObjectName = &name;
  PortAttributes port = {0};
  port.Flags = 0x80000;
  port.SecurityQos.Length = sizeof(port.SecurityQos);
  port.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
  port.SecurityQos.EffectiveOnly = TRUE;
  port.MaxMessageLength = 80;
  port.MaxPoolUsage = port.MaxSectionSize = port.MaxViewSize =
      port.MaxTotalSectionSize = UINT32_MAX;
  port.DupObjectTypes = 0x80;
  __declspec(align(16)) BYTE message[128] = {0}, attributes[256] = {0};
  SIZE_T required = 0;
  LONG initialized = initialize(0x10000000, attributes, sizeof(attributes), &required);
  if (initialized < 0) return 11;
  if (required > sizeof(attributes) || required < 8) return 30;
  memset(attributes + 8, 0xA5, required - 8);
#if defined(_WIN64)
  SIZE_T length = 80;
  *(ULONG *)(void *)(message + 48) = 7;
#else
  SIZE_T length = 64;
  *(ULONG *)(void *)(message + 32) = 7;
#endif
  *(USHORT *)(void *)message = 40;
  *(USHORT *)(void *)(message + 2) = (USHORT)length;

  if (!sid_matches) return 31;
  HANDLE peer = NULL;
  LONG status = connect_ex(&peer, &connection, NULL, &port, 0x20000, server_security,
                           message, &length, NULL, attributes, NULL);
  printf("CONNECT status=%08lX length=%zu attributes=%zu\n", (DWORD)status, length, required);
  if (status < 0 || !peer || length != 80 || required != 32) return 32;
  CallerHandleAttribute *initial = get_attribute(attributes, 0x10000000);
  if (!initial || !initial->Handle) return 33;
  const HANDLE initial_section = initial->Handle;
  status = send(peer, 0x10000, message, NULL, NULL, NULL, NULL, NULL);
  printf("CONNECT release=%08lX\n", (DWORD)status);
  if (status < 0 || !CloseHandle(initial_section)) return 34;

  typedef LONG(NTAPI *Compare)(HANDLE, HANDLE);
  const Compare compare = (Compare)GetProcAddress(ntdll, "NtCompareObjects");
  if (!compare) return 51;
  HANDLE first_section = NULL;
  __declspec(align(16)) BYTE second_msg[80] = {40,0,80,0}, second_attrs[64] = {0};
  SIZE_T second_size = 80, second_required = 0;
  if (initialize(0x10000000, second_attrs, sizeof(second_attrs), &second_required) != 0) return 52;
  second_msg[48] = 7;
  HANDLE second_peer = NULL;
  if (connect_ex(&second_peer, &connection, NULL, &port, 0x20000, server_security,
                 second_msg, &second_size, NULL, second_attrs, NULL) != 0 || !second_peer) return 53;
  const CallerHandleAttribute *second_initial = get_attribute(second_attrs, 0x10000000);
  if (!second_initial || !second_initial->Handle ||
      send(second_peer, 0x10000, second_msg, NULL, NULL, NULL, NULL, NULL) != 0 ||
      !CloseHandle(second_initial->Handle)) return 54;
  const WCHAR *names[] = {L"kernel32.dll", L"kernel32.dll", L"apphelp.dll", L".\\x64.exe"};
  for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    WCHAR path[MAX_PATH];
    if (i == 3) {
      memcpy(path, names[i], 10 * sizeof(WCHAR));
    } else {
      const UINT size = GetSystemDirectoryW(path, MAX_PATH);
      const SIZE_T name_length = wcslen(names[i]);
      if (!size || size + 1 + name_length >= MAX_PATH) return 35;
      path[size] = L'\\';
      memcpy(path + size + 1, names[i], (name_length + 1) * sizeof(WCHAR));
    }
    HANDLE file = CreateFileW(path, 0xA1, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
      printf("open index=%u error=%lu\n", i, GetLastError());
      return 36;
    }
    __declspec(align(16)) BYTE send_attrs[64] = {0}, receive_attrs[64] = {0};
    __declspec(align(16)) BYTE request[80] = {40, 0, 80, 0}, reply[80] = {0};
    request[40] = 2;
    SIZE_T send_size = 0, receive_size = 0, reply_length = sizeof(reply);
    if (initialize(0x30000000, send_attrs, sizeof(send_attrs), &send_size) != 0 ||
        initialize(0x30000000, receive_attrs, sizeof(receive_attrs), &receive_size) != 0 ||
        send_size != sizeof(send_attrs) || receive_size != sizeof(receive_attrs))
      return 37;
    CallerHandleAttribute *handle_attr = get_attribute(send_attrs, 0x10000000);
    if (!handle_attr || (BYTE *)handle_attr - send_attrs != 40) return 38;
    handle_attr->Handle = file;
    handle_attr->DesiredAccess = 0xa1;
    ((ULONG *)(void *)send_attrs)[1] = 0x10000000;
    HANDLE active = i == 1 ? second_peer : peer;
    status = send(active, 0x20000, request, send_attrs, reply, &reply_length, receive_attrs, NULL);
    const BOOL file_closed = CloseHandle(file);
    const ULONG valid = ((ULONG *)(void *)receive_attrs)[1];
    printf("LOOKUP index=%u name=%ls status=%08lX size=%zu type=%04X opcode=%u slot=%u attrs=%08lX file_closed=%u\n",
           i, names[i], (DWORD)status, reply_length, (unsigned)*(USHORT *)(void *)(reply + 4),
           (unsigned)reply[40], (unsigned)reply[48], valid, (unsigned)file_closed);
    if (status != 0 || reply_length != sizeof(reply) || reply[40] != 3 || !file_closed) return 39;
    if (valid & 0x10000000) {
      CallerHandleAttribute *received = get_attribute(receive_attrs, 0x10000000);
      if (!received || (BYTE *)received - receive_attrs != 40 || !received->Handle) return 40;
      __declspec(align(8)) BYTE basic[56] = {0};
      ULONG returned = 0, grant = 0;
      const LONG queried = query_object(received->Handle, 0, basic, sizeof(basic), &returned);
      memcpy(&grant, basic + 4, sizeof grant);
      const void *view = MapViewOfFile(received->Handle, FILE_MAP_READ, 0, 0, 0);
      if (!view) return 41;
      MEMORY_BASIC_INFORMATION info = {0};
      WCHAR mapped[1024] = {0};
      const DWORD mapped_length = K32GetMappedFileNameW(GetCurrentProcess(), (void *)view, mapped, 1024);
      const SIZE_T info_bytes = VirtualQuery(view, &info, sizeof(info));
      if (!mapped_length || mapped_length >= 1024 || !wcsstr(mapped, L"\\Windows\\XtaCache\\") ||
          !info_bytes || info.RegionSize > 16 * 1024 * 1024 || info.RegionSize < 4096 ||
          info.Type != MEM_MAPPED || info.Protect != PAGE_READONLY || memcmp(view, "XTAC", 4))
        return 42;
      BCRYPT_ALG_HANDLE algorithm = NULL;
      BYTE hash[32] = {0};
      if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 43;
      const NTSTATUS hashed = BCryptHash(algorithm, NULL, 0, (PUCHAR)view, (ULONG)info.RegionSize,
                                        hash, sizeof(hash));
      BCryptCloseAlgorithmProvider(algorithm, 0);
      if (hashed < 0) return 44;
      printf("SECTION index=%u granted=%08lX basic-status=%08lX extent=%zu path=%ls sha256=",
             i, grant, (DWORD)queried, info.RegionSize, mapped);
      for (unsigned j = 0; j < sizeof(hash); ++j) printf("%02X", (unsigned)hash[j]);
      putchar('\n');
      if (!UnmapViewOfFile(view)) return 45;
      void *outside = MapViewOfFile(received->Handle, FILE_MAP_READ, 0, 0, info.RegionSize + 1);
      if (outside) { UnmapViewOfFile(outside); return 55; }
      printf("BOUNDARY index=%u outside-error=%lu\n", i, GetLastError());
      SIZE_T low = info.RegionSize - 4096 + 1, high = info.RegionSize + 1;
      while (low < high) {
        const SIZE_T middle = low + (high - low + 1) / 2;
        const void *limited = MapViewOfFile(received->Handle, FILE_MAP_READ, 0, 0, middle);
        if (limited) {
          if (!UnmapViewOfFile(limited)) return 48;
          low = middle;
        } else {
          high = middle - 1;
        }
      }
      printf("BOUNDS index=%u exact-request=%zu rounded=%zu\n", i, low, info.RegionSize);
      if (i == 0) {
        first_section = received->Handle;
      } else {
        if (i == 1) printf("IDENTITY repeat=%08lX\n", (DWORD)compare(first_section, received->Handle));
        if (!CloseHandle(received->Handle)) return 49;
      }
    }
    if (*(USHORT *)(void *)(reply + 4) & 0x2000) {
      status = send(active, 0x10000, reply, NULL, NULL, NULL, NULL, NULL);
      printf("RELEASE index=%u status=%08lX\n", i, (DWORD)status);
      if (status != 0) return 46;
    }
  }
  if (!CloseHandle(first_section) || !CloseHandle(peer) || !CloseHandle(second_peer)) return 47;
  puts("DONE");
  return 0;
}
