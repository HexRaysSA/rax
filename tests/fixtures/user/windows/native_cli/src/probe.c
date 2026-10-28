typedef unsigned long U32;
typedef unsigned short U16;
typedef unsigned char U8;
typedef void *HANDLE;
#if defined(_M_IX86) || defined(__i386__)
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI
#endif
#define DLL __declspec(dllimport)
DLL HANDLE WINAPI GetStdHandle(U32);
DLL int WINAPI WriteFile(HANDLE, const void *, U32, U32 *, void *);
DLL HANDLE WINAPI GetModuleHandleW(const U16 *);
DLL __declspec(noreturn) void WINAPI ExitProcess(U32);

static U32 read32(const U8 *p) {
  return p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24);
}

void entry(void) {
  static const U16 name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3',
                             '2', '.', 'd', 'l', 'l', 0};
  static const char marker[] = "RAXCLI\n";
  const U8 *module = (const U8 *)GetModuleHandleW(name);
  U32 count = 0;
  HANDLE out = GetStdHandle((U32)-11);
  if (!module || module[0] != 'M' || module[1] != 'Z')
    ExitProcess(71);
  const U8 *pe = module + read32(module + 0x3c);
  if (read32(pe) != 0x4550)
    ExitProcess(72);
  U8 signature[8];
  for (U32 i = 0; i < 4; ++i) {
    signature[i] = pe[8 + i];
    signature[4 + i] = pe[24 + 56 + i];
  }
  if (!WriteFile(out, marker, sizeof(marker) - 1, &count, 0) ||
      count != sizeof(marker) - 1)
    ExitProcess(73);
  if (!WriteFile(out, signature, sizeof(signature), &count, 0) ||
      count != sizeof(signature))
    ExitProcess(74);
  ExitProcess(0x87654321UL);
}
