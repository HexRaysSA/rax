#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *QueryFn)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

static DWORD protection(void *address) {
  MEMORY_BASIC_INFORMATION info;
  return VirtualQuery(address, &info, sizeof(info)) ? info.Protect : 0;
}

int main(int argc, char **argv) {
  int which = argc > 1 ? atoi(argv[1]) : 0;
  QueryFn query = (QueryFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                          "NtQueryVirtualMemory");
  unsigned char *pages =
      VirtualAlloc(NULL, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  void *subject = GetModuleHandleW(NULL);
  HANDLE process = GetCurrentProcess();
  unsigned char control[16384];
  SIZE_T needed = 0;
  NTSTATUS baseline =
      query(process, subject, 2, control, sizeof(control), &needed);
  if (baseline != 0 || needed > 8192 || needed < sizeof(UNICODE_STRING))
    return 90;
  memset(pages, 0xCC, 16384);
  void *output = pages + 128;
  PSIZE_T returned = (PSIZE_T)(pages + 64);
  SIZE_T length = 4096;
  DWORD old;
  void *allocation = NULL;
  HANDLE file = INVALID_HANDLE_VALUE, section = NULL;
  void *mapping = NULL;
  const wchar_t *filename = L"mapped filename \x03bb.bin";
  switch (which) {
  case 1:
    length = 0;
    break;
  case 2:
    length = 1;
    break;
  case 3:
    length = sizeof(UNICODE_STRING) - 1;
    break;
  case 4:
    length = sizeof(UNICODE_STRING);
    break;
  case 5:
    length = needed - 1;
    break;
  case 6:
    length = needed;
    break;
  case 7:
    length = needed + 1;
    break;
  case 8:
    output = NULL;
    break;
  case 9:
    output = NULL;
    length = 0;
    break;
  case 10:
    output = pages + 129;
    length = needed;
    break;
  case 11:
    output = (void *)1;
    length = needed;
    break;
  case 12:
    VirtualProtect(pages, 4096, PAGE_READONLY, &old);
    break;
  case 13:
    VirtualProtect(pages, 4096, PAGE_NOACCESS, &old);
    break;
  case 14:
    VirtualProtect(pages, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 15:
    output = pages + 4096 - sizeof(UNICODE_STRING);
    VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old);
    break;
  case 16:
    returned = NULL;
    break;
  case 17:
    returned = (PSIZE_T)1;
    break;
  case 18:
    returned = (PSIZE_T)(pages + 65);
    break;
  case 19:
    returned = (PSIZE_T)(pages + 8192);
    VirtualProtect(pages + 8192, 4096, PAGE_READONLY, &old);
    break;
  case 20:
    returned = (PSIZE_T)(pages + 8192);
    VirtualProtect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 21:
    returned = (PSIZE_T)output;
    break;
  case 22:
    returned = (PSIZE_T)((char *)output + offsetof(UNICODE_STRING, Buffer));
    break;
  case 23:
    process = (HANDLE)0x1234;
    break;
  case 24:
    process = (HANDLE)0x1234;
    output = NULL;
    break;
  case 25:
    process = GetCurrentThread();
    break;
  case 26:
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                          GetCurrentProcessId());
    break;
  case 27:
    process = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    break;
  case 28:
    subject = NULL;
    break;
  case 29:
    subject = allocation =
        VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    break;
  case 30:
    subject = allocation = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
    break;
  case 31:
    subject = (void *)(ULONG_PTR)-1;
    break;
  case 32:
    subject = allocation =
        VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    VirtualFree(allocation, 0, MEM_RELEASE);
    allocation = NULL;
    break;
  case 33:
    length = 8192;
    VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old);
    break;
  case 34:
    output = pages + 4096 - sizeof(UNICODE_STRING);
    VirtualProtect(pages + 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &old);
    break;
  case 35:
    subject = (char *)subject + 1;
    break;
  case 36:
    subject = GetModuleHandleW(L"kernel32.dll");
    break;
  case 37:
  case 38:
  case 41:
  case 42:
  case 43:
  case 44:
    file = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE | DELETE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
      return 91;
    section = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 131072, NULL);
    mapping = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!mapping)
      return 92;
    subject = which == 38 ? (char *)mapping + 65536 : mapping;
    if (which == 41)
      UnmapViewOfFile(mapping);
    if (which == 42) {
      if (!MoveFileExW(filename, L"renamed filename \x03bb.bin",
                       MOVEFILE_REPLACE_EXISTING))
        return 93;
    }
    if (which == 43) {
      CloseHandle(file);
      file = INVALID_HANDLE_VALUE;
      CloseHandle(section);
      section = NULL;
    }
    if (which == 44 && !DeleteFileW(filename))
      return 94;
    break;
  case 39:
    section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
                                 65536, NULL);
    subject = mapping = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!mapping)
      return 95;
    break;
  case 40: {
    wchar_t path[32768];
    if (!GetModuleFileNameW(GetModuleHandleW(L"kernel32.dll"), path, 32768))
      return 96;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    section =
        CreateFileMappingW(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    subject = mapping = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!mapping)
      return 97;
    break;
  }
  case 45:
    process = (HANDLE)0x1234;
    length = 0;
    break;
  case 46:
    subject = NULL;
    length = 0;
    break;
  case 47:
    length = sizeof(UNICODE_STRING) + 1;
    break;
  }
  switch (which) {
  case 77:
    length = needed - 2;
    break;
  case 78:
    length = needed - 3;
    break;
  case 79:
    length = needed - 8;
    break;
  case 80:
    length = needed - 32;
    break;
  case 81:
    length = needed - 64;
    break;
  case 82:
    length = 48;
    break;
  case 83:
    length = 64;
    break;
  case 84:
    length = 80;
    break;
  case 85:
    length = 96;
    break;
  case 86:
    length = 128;
    break;
  case 87:
    length = 192;
    break;
  case 88:
    length = 256;
    break;
  case 89:
    length = needed - 4;
    break;
  case 90:
    length = needed - 6;
    break;
  }
  if (which >= 91) {
    subject = GetModuleHandleW(L"kernel32.dll");
    if (query(process, subject, 2, control, sizeof(control), &needed) != 0)
      return 98;
    switch (which) {
    case 91:
      length = needed - 1;
      break;
    case 92:
      length = needed - 2;
      break;
    case 93:
      length = 64;
      break;
    case 94:
      length = 80;
      break;
    case 95:
      length = 96;
      break;
    }
  }
  NTSTATUS status = 0;
  DWORD raised = 0;
  __try {
    status = query(process, subject, 2, output, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    raised = GetExceptionCode();
  }
  DWORD protections[3] = {protection(pages), protection(pages + 4096),
                          protection(pages + 8192)};
  VirtualProtect(pages, 16384, PAGE_READWRITE, &old);
  SIZE_T return_value = 0;
  if ((char *)returned >= (char *)pages &&
      (char *)returned + sizeof(SIZE_T) <= (char *)pages + 16384)
    memcpy(&return_value, returned, sizeof(SIZE_T));
  printf("{\"case\":%d,\"status\":%lu,\"raised\":%lu,\"required\":%llu,"
         "\"length\":%llu,\"returned\":%llu,\"header_size\":%zu,\"protect\":[%"
         "lu,%lu,%lu],\"output_hex\":\"",
         which, (unsigned long)status, raised, (unsigned long long)needed,
         (unsigned long long)length, (unsigned long long)return_value,
         sizeof(UNICODE_STRING), protections[0], protections[1],
         protections[2]);
  if ((char *)output >= (char *)pages &&
      (char *)output + 128 <= (char *)pages + 16384) {
    for (int i = 0; i < 128; ++i)
      printf("%02x", ((unsigned char *)output)[i]);
    UNICODE_STRING value;
    memcpy(&value, output, sizeof(value));
    printf("\",\"name_length\":%u,\"maximum_length\":%u,\"buffer_offset\":%lld,"
           "\"name_hex\":\"",
           value.Length, value.MaximumLength,
           (long long)((ULONG_PTR)value.Buffer - (ULONG_PTR)output));
    if ((char *)value.Buffer >= (char *)pages &&
        (char *)value.Buffer + value.Length <= (char *)pages + 16384)
      for (unsigned i = 0; i < value.Length; ++i)
        printf("%02x", ((unsigned char *)value.Buffer)[i]);
  }
  printf("\"}\n");
  return 0;
}
