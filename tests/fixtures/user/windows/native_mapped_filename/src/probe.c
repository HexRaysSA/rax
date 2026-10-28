typedef unsigned long U32;
typedef unsigned short U16;
typedef unsigned char U8;
typedef __UINTPTR_TYPE__ UPTR;
typedef void *HANDLE;
#if defined(_M_IX86) || defined(__i386__)
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI
#endif
#define DLL __declspec(dllimport)
DLL HANDLE WINAPI GetStdHandle(U32);
DLL HANDLE WINAPI GetModuleHandleW(const U16 *);
DLL int WINAPI WriteFile(HANDLE, const void *, U32, U32 *, void *);
DLL __declspec(noreturn) void WINAPI ExitProcess(U32);
DLL U32 WINAPI NtQueryVirtualMemory(HANDLE, void *, U32, void *, UPTR, UPTR *);

typedef struct {
  U16 length;
  U16 maximum;
  U16 *buffer;
} STRING;

void entry(void) {
  static union {
    UPTR alignment;
    U8 bytes[4096];
  } output;
  static const char marker[] = "RAX-MAPPED-NAME\n";
  UPTR returned = 0;
  U32 count = 0;
  HANDLE image = GetModuleHandleW((const U16 *)0);
  if (!image)
    ExitProcess(61);
  U32 status = NtQueryVirtualMemory((HANDLE)(UPTR)-1, image, 2, output.bytes,
                                    sizeof(output.bytes), &returned);
  if (status != 0)
    ExitProcess(62);
  STRING *name = (STRING *)output.bytes;
  if (!name->length || name->maximum != name->length + 2 ||
      name->buffer != (U16 *)(output.bytes + sizeof(STRING)) ||
      returned != sizeof(STRING) + name->maximum)
    ExitProcess(63);
  HANDLE stream = GetStdHandle((U32)-11);
  if (!WriteFile(stream, marker, sizeof(marker) - 1, &count, (void *)0) ||
      count != sizeof(marker) - 1)
    ExitProcess(64);
  if (!WriteFile(stream, name->buffer, name->length, &count, (void *)0) ||
      count != name->length)
    ExitProcess(65);
  ExitProcess(0);
}
