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
  unsigned char *pages =
      VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  memset(pages, 0xCC, 8192);
  DWORD previous;
  VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &previous);
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
  if (which == 12)
    output = (PIO_STATUS_BLOCK)(pages + 4096 - sizeof(void *));
  if (which == 13)
    output = (PIO_STATUS_BLOCK)(pages + 32 + 1);
  if (which == 14) {
    handle = (HANDLE)(ULONG_PTR)0x1234;
    offset = (PLARGE_INTEGER)(ULONG_PTR)1;
  }
  if (which == 15) {
    handle = (HANDLE)(ULONG_PTR)0x1234;
    key = (PULONG)(ULONG_PTR)1;
  }
  if (which == 16) {
    handle = (HANDLE)(ULONG_PTR)0x1234;
    event = (HANDLE)(ULONG_PTR)0x1234;
    offset = (PLARGE_INTEGER)(ULONG_PTR)1;
  }
  if (which == 17) {
    event = (HANDLE)(ULONG_PTR)0x1234;
    output = NULL;
  }
  NTSTATUS status =
      write(handle, event, NULL, NULL, output, buffer, length, offset, key);
  fprintf(stderr, "status=%08lx;iosb=", (unsigned long)status);
  for (size_t i = 0; i < sizeof(io); ++i)
    fprintf(stderr, "%02x", ((unsigned char *)&io)[i]);
  fprintf(stderr, ";prefix=");
  if (which == 12)
    for (size_t i = 4096 - sizeof(void *); i < 4096; ++i)
      fprintf(stderr, "%02x", pages[i]);
  if (which == 13)
    for (size_t i = 32; i < 32 + 2 * sizeof(void *) + 2; ++i)
      fprintf(stderr, "%02x", pages[i]);
  fprintf(stderr, "\n");
  return 0;
}
