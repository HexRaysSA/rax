#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *WriteFn)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                                 PVOID, ULONG, PLARGE_INTEGER, PULONG);

int main(int argc, char **argv) {
  int which = argc > 1 ? atoi(argv[1]) : 0;
  WriteFn write =
      (WriteFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteFile");
  IO_STATUS_BLOCK io;
  memset(&io, 0xCC, sizeof(io));
  PIO_STATUS_BLOCK output = &io;
  HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE event = NULL;
  char bytes[] = "XY";
  PVOID buffer = bytes;
  ULONG length = 2;
  PLARGE_INTEGER offset = NULL;
  PULONG key = NULL;
  switch (which) {
  case 1:
    output = NULL;
    break;
  case 2:
    handle = (HANDLE)(ULONG_PTR)0x1234;
    break;
  case 3:
    buffer = NULL;
    break;
  case 4:
    buffer = NULL;
    length = 0;
    break;
  case 5:
    handle = (HANDLE)(ULONG_PTR)0x1234;
    buffer = NULL;
    break;
  case 6:
    output = NULL;
    handle = (HANDLE)(ULONG_PTR)0x1234;
    break;
  case 7:
    event = (HANDLE)(ULONG_PTR)0x1234;
    break;
  case 8:
    event = (HANDLE)(ULONG_PTR)0x1234;
    buffer = NULL;
    break;
  case 9:
    offset = (PLARGE_INTEGER)(ULONG_PTR)1;
    break;
  case 10:
    key = (PULONG)(ULONG_PTR)1;
    break;
  case 11:
    output = (PIO_STATUS_BLOCK)(ULONG_PTR)1;
    break;
  }
  NTSTATUS status =
      write(handle, event, NULL, NULL, output, buffer, length, offset, key);
  fprintf(stderr, "status=%08lx;iosb=", (unsigned long)status);
  for (size_t i = 0; i < sizeof(io); ++i)
    fprintf(stderr, "%02x", ((unsigned char *)&io)[i]);
  fprintf(stderr, "\n");
  return 0;
}
