#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
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
typedef LONG(NTAPI *QuerySection)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);
typedef LONG(NTAPI *CompareObjects)(HANDLE, HANDLE);
typedef LONG(NTAPI *MapSection)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T, LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
typedef LONG(NTAPI *UnmapSection)(HANDLE, void *);
typedef LONG(NTAPI *SendReceive)(HANDLE, ULONG, void *, void *, void *, SIZE_T *, void *, LARGE_INTEGER *);
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

static void print_hex(const BYTE *bytes, SIZE_T count) {
  static const char digits[] = "0123456789ABCDEF";
  char output[8192];
  while (count) {
    SIZE_T take = count < sizeof(output) / 2 ? count : sizeof(output) / 2;
    for (SIZE_T i = 0; i < take; ++i) {
      output[2 * i] = digits[bytes[i] >> 4];
      output[2 * i + 1] = digits[bytes[i] & 15];
    }
    if (fwrite(output, 2, (size_t)take, stdout) != (size_t)take) ExitProcess(24);
    bytes += take;
    count -= take;
  }
}

int main(void) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  ConnectEx connect_ex = (ConnectEx)GetProcAddress(ntdll, "NtAlpcConnectPortEx");
  InitializeAttributes initialize = (InitializeAttributes)GetProcAddress(
      ntdll, "AlpcInitializeMessageAttribute");
  GetAttribute get_attribute = (GetAttribute)GetProcAddress(ntdll, "AlpcGetMessageAttribute");
  QueryObject query_object = (QueryObject)GetProcAddress(ntdll, "NtQueryObject");
  QuerySection query_section = (QuerySection)GetProcAddress(ntdll, "NtQuerySection");
  CompareObjects compare_objects = (CompareObjects)GetProcAddress(ntdll, "NtCompareObjects");
  MapSection map_section = (MapSection)GetProcAddress(ntdll, "NtMapViewOfSection");
  UnmapSection unmap_section = (UnmapSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
  SendReceive send_receive = (SendReceive)GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
  if (!connect_ex || !initialize || !get_attribute || !query_object || !query_section || !compare_objects || !map_section || !unmap_section || !send_receive ||
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
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 12;
  printf("PROFILE pointer_bytes=%zu descriptor_bytes=%zu attribute_bytes=%zu "
         "message_bytes=%zu entry=", sizeof(void *), sizeof(server_security),
         (size_t)required, (size_t)length);
  for (unsigned i = 0; i < 32; ++i)
    printf("%02X", ((const BYTE *)(uintptr_t)connect_ex)[i]);
  putchar('\n');
  HANDLE connected = NULL;
  DWORD status = 0xDEADBEEF, exception = 0;
  __try {
    status = (DWORD)connect_ex(&connected, &connection, NULL, &port, 0x20000,
                              server_security, message, &length, NULL,
                              attributes, NULL);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  printf("CONNECT status=%08lX exception=%08lX port=%llu length=%zu message=",
         status, exception, (unsigned long long)(uintptr_t)connected, (size_t)length);
  for (unsigned i = 0; i < 128; ++i) printf("%02X", (unsigned)message[i]);
  printf(" attributes=");
  for (unsigned i = 0; i < 256; ++i) printf("%02X", (unsigned)attributes[i]);
  putchar('\n');
  BOOL closed = TRUE;
  BOOL section_closed = TRUE;
  if (status == 0 && exception == 0) {
    if (required != 8 + sizeof(CallerHandleAttribute)) return 17;
    void *attribute = get_attribute(attributes, 0x10000000);
    uintptr_t offset = (uintptr_t)attribute - (uintptr_t)attributes;
    if (!attribute || offset > sizeof(attributes) - sizeof(CallerHandleAttribute)) return 18;
    CallerHandleAttribute received;
    CopyMemory(&received, attribute, sizeof(received));
    __declspec(align(8)) BYTE basic[56] = {0}, type[1024] = {0};
    ULONG returned_basic = 0, returned_type = 0, granted = 0;
    LONG basic_status = query_object(received.Handle, 0, basic, sizeof(basic), &returned_basic);
    LONG type_status = query_object(received.Handle, 2, type, sizeof(type), &returned_type);
    CopyMemory(&granted, basic + 4, sizeof(granted));
    UNICODE_STRING type_name;
    CopyMemory(&type_name, type, sizeof(type_name));
    uintptr_t type_at = (uintptr_t)type_name.Buffer, type_begin = (uintptr_t)type;
    BOOL section_type = type_status == 0 && type_name.Length == 14 &&
        type_at >= type_begin && type_at - type_begin <= sizeof(type) - 14 &&
        memcmp(type_name.Buffer, L"Section", 14) == 0;
    printf("HANDLE attribute_offset=%zu caller_bytes=%zu flags=%08lX "
           "object_type=%08lX desired=%08lX basic_status=%08lX basic_bytes=%lu "
           "granted=%08lX type_status=%08lX type_bytes=%lu section_type=%u\n",
           (size_t)offset, sizeof(received), received.Flags, received.ObjectType,
           received.DesiredAccess, (DWORD)basic_status, returned_basic, granted,
           (DWORD)type_status, returned_type, (unsigned)section_type);
    if (basic_status != 0 || !section_type) return 19;
    BYTE before_message[128], before_attributes[256];
    CopyMemory(before_message, message, sizeof(message));
    CopyMemory(before_attributes, attributes, sizeof(attributes));
    DWORD release_status = 0xDEADBEEF, release_exception = 0;
    __try {
      release_status = (DWORD)send_receive(connected, 0x10000, message, NULL, NULL, NULL, NULL, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      release_exception = GetExceptionCode();
    }
    printf("RELEASE status=%08lX exception=%08lX message_unchanged=%u attributes_unchanged=%u entry=",
           release_status, release_exception,
           (unsigned)(memcmp(before_message, message, sizeof(message)) == 0),
           (unsigned)(memcmp(before_attributes, attributes, sizeof(attributes)) == 0));
    print_hex((const BYTE *)(uintptr_t)send_receive, 32);
    putchar('\n');

    __declspec(align(8)) BYTE port_basic[56] = {0};
    ULONG port_returned = 0, port_granted = 0;
    LONG port_status = query_object(connected, 0, port_basic, sizeof(port_basic), &port_returned);
    CopyMemory(&port_granted, port_basic + 4, sizeof(port_granted));
    printf("PORT basic_status=%08lX basic_bytes=%lu granted=%08lX\n",
           (DWORD)port_status, port_returned, port_granted);
    /* A second normal request checks object identity while both port handles
     * are still open. All arguments and buffers are local, fixed and bounded. */
    __declspec(align(16)) BYTE second_message[128] = {0}, second_attributes[256] = {0};
    SIZE_T second_required = 0;
    LONG second_initialized = initialize(0x10000000, second_attributes,
                                         sizeof(second_attributes), &second_required);
    if (second_initialized < 0 || second_required != required) return 31;
#if defined(_WIN64)
    SIZE_T second_length = 80;
    *(ULONG *)(void *)(second_message + 48) = 7;
#else
    SIZE_T second_length = 64;
    *(ULONG *)(void *)(second_message + 32) = 7;
#endif
    *(USHORT *)(void *)second_message = 40;
    *(USHORT *)(void *)(second_message + 2) = (USHORT)second_length;
    HANDLE second_port = NULL;
    DWORD second_status = 0xDEADBEEF, second_exception = 0;
    __try {
      second_status = (DWORD)connect_ex(&second_port, &connection, NULL, &port, 0x20000,
                                       server_security, second_message, &second_length,
                                       NULL, second_attributes, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      second_exception = GetExceptionCode();
    }
    DWORD compared = 0xDEADBEEF;
    BOOL second_port_closed = TRUE, second_section_closed = TRUE;
    if (second_status == 0 && second_exception == 0) {
      void *second_attribute = get_attribute(second_attributes, 0x10000000);
      uintptr_t second_offset = (uintptr_t)second_attribute - (uintptr_t)second_attributes;
      if (!second_attribute || second_offset > sizeof(second_attributes) - sizeof(CallerHandleAttribute)) return 32;
      CallerHandleAttribute second_received;
      CopyMemory(&second_received, second_attribute, sizeof(second_received));
      compared = (DWORD)compare_objects(received.Handle, second_received.Handle);
      second_section_closed = CloseHandle(second_received.Handle);
      second_port_closed = CloseHandle(second_port);
    }
    printf("IDENTITY second_status=%08lX exception=%08lX compare_status=%08lX "
           "second_port_closed=%u second_section_closed=%u\n", second_status,
           second_exception, compared, (unsigned)second_port_closed,
           (unsigned)second_section_closed);
    if (!second_port_closed || !second_section_closed) return 33;
    /* All following operations use only our returned Section handle. The port
     * is closed first; writable mappings are never written. */
    closed = CloseHandle(connected);
    if (!closed) return 25;
    connected = NULL;
    __declspec(align(8)) BYTE section_information[24] = {0};
    SIZE_T section_returned = 0;
    LONG section_status = query_section(received.Handle, 0, section_information,
                                         sizeof(section_information), &section_returned);
    printf("SECTION status=%08lX returned=%zu bytes=", (DWORD)section_status,
           (size_t)section_returned);
    print_hex(section_information, sizeof(section_information));
    putchar('\n');
    const SIZE_T bounds[] = {65535, 65536, 65537, 131072};
    for (unsigned i = 0; i < sizeof(bounds) / sizeof(bounds[0]); ++i) {
      SetLastError(0);
      void *bounded = MapViewOfFile(received.Handle, FILE_MAP_READ, 0, 0, bounds[i]);
      DWORD error = bounded ? 0 : GetLastError();
      MEMORY_BASIC_INFORMATION info = {0};
      SIZE_T queried = bounded ? VirtualQuery(bounded, &info, sizeof(info)) : 0;
      printf("BOUNDARY requested=%zu mapped=%u error=%lu queried=%zu region_bytes=%zu "
             "state=%08lX type=%08lX protect=%08lX\n", (size_t)bounds[i],
             (unsigned)(bounded != NULL), error, (size_t)queried,
             (size_t)info.RegionSize, info.State, info.Type, info.Protect);
      if (bounded && !UnmapViewOfFile(bounded)) return 26;
    }
    SetLastError(0);
    void *write_view = MapViewOfFile(received.Handle, FILE_MAP_WRITE, 0, 0, 0);
    DWORD write_error = write_view ? 0 : GetLastError();
    MEMORY_BASIC_INFORMATION write_info = {0};
    SIZE_T write_queried = write_view ? VirtualQuery(write_view, &write_info, sizeof(write_info)) : 0;
    printf("WRITABLE mapped=%u error=%lu queried=%zu region_bytes=%zu protect=%08lX "
           "allocation_protect=%08lX wrote_bytes=0\n", (unsigned)(write_view != NULL),
           write_error, (size_t)write_queried, (size_t)write_info.RegionSize,
           write_info.Protect, write_info.AllocationProtect);
    if (write_view && !UnmapViewOfFile(write_view)) return 27;
    const SIZE_T native_sizes[] = {0, 1, 65535, 65536, 65537, 131072};
    const ULONG native_protections[] = {PAGE_READONLY, PAGE_READWRITE};
    for (unsigned pi = 0; pi < sizeof(native_protections) / sizeof(native_protections[0]); ++pi) {
      for (unsigned si = 0; si < sizeof(native_sizes) / sizeof(native_sizes[0]); ++si) {
        void *native_base = NULL;
        SIZE_T native_size = native_sizes[si];
        LONG mapped = map_section(received.Handle, GetCurrentProcess(), &native_base,
                                  0, 0, NULL, &native_size, 2, 0, native_protections[pi]);
        MEMORY_BASIC_INFORMATION info = {0};
        SIZE_T query = mapped >= 0 && native_base ? VirtualQuery(native_base, &info, sizeof(info)) : 0;
        LONG unmapped = mapped >= 0 && native_base ? unmap_section(GetCurrentProcess(), native_base) : (LONG)0xDEADBEEF;
        printf("NTMAP requested=%zu protection=%08lX status=%08lX base_nonzero=%u "
               "returned_size=%zu query_bytes=%zu region_bytes=%zu view_protect=%08lX "
               "allocation_protect=%08lX unmap_status=%08lX wrote_bytes=0\n",
               (size_t)native_sizes[si], native_protections[pi], (DWORD)mapped,
               (unsigned)(native_base != NULL), (size_t)native_size, (size_t)query,
               (size_t)info.RegionSize, info.Protect, info.AllocationProtect, (DWORD)unmapped);
        if (mapped >= 0 && native_base && unmapped < 0) return 34;
      }
    }

    SetLastError(0);
    void *view = MapViewOfFile(received.Handle, FILE_MAP_READ, 0, 0, 0);
    DWORD map_error = view ? 0 : GetLastError();
    MEMORY_BASIC_INFORMATION information = {0};
    SIZE_T queried = view ? VirtualQuery(view, &information, sizeof(information)) : 0;
    printf("VIEW mapped=%u error=%lu queried=%zu region_bytes=%zu state=%08lX "
           "type=%08lX protect=%08lX allocation_protect=%08lX bytes=",
           (unsigned)(view != NULL), map_error, (size_t)queried,
           (size_t)information.RegionSize, information.State, information.Type,
           information.Protect, information.AllocationProtect);
    if (view && queried && information.RegionSize <= 1048576 &&
        information.State == MEM_COMMIT && information.Protect == PAGE_READONLY) {
      const BYTE *bytes = view;
      print_hex(bytes, information.RegionSize);
    }
    putchar('\n');
    section_closed = CloseHandle(received.Handle);
    if (!section_closed) return 28;
    if (view) {
      BYTE endpoints[2] = {0xA5, 0xA5};
      SIZE_T first = 0, last = 0;
      BOOL first_ok = ReadProcessMemory(GetCurrentProcess(), view, endpoints, 1, &first);
      BOOL last_ok = FALSE;
      if (information.RegionSize && information.RegionSize <= 1048576) {
        const BYTE *last_address = (const BYTE *)view + information.RegionSize - 1;
        last_ok = ReadProcessMemory(GetCurrentProcess(), last_address, endpoints + 1, 1, &last);
      }
      printf("LIFETIME port_closed=%u section_closed=%u first_read=%u first_bytes=%zu "
             "last_read=%u last_bytes=%zu first=%02X last=%02X\n", (unsigned)closed,
             (unsigned)section_closed, (unsigned)first_ok, (size_t)first,
             (unsigned)last_ok, (size_t)last, (unsigned)endpoints[0], (unsigned)endpoints[1]);
      if (!UnmapViewOfFile(view)) return 20;
    }
  }
  if (status < 0x80000000 && exception == 0 && connected) closed = CloseHandle(connected);
  if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 13;
  printf("SUMMARY port_closed=%u section_closed=%u handles_before=%lu handles_after=%lu\n",
         (unsigned)closed, (unsigned)section_closed, before, after);
  return closed && section_closed ? 0 : 14;
}
