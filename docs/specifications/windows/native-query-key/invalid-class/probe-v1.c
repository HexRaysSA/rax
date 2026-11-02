/* Invalid NtQueryKey calls and actual mapped-service identity; no CRT. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef LONG(NTAPI *QueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
union Function {
  FARPROC generic;
  QueryKey query;
};
typedef DWORD(WINAPI *MappedName)(HANDLE, LPVOID, LPWSTR, DWORD);
typedef BOOL(WINAPI *MachinePair)(HANDLE, USHORT *, USHORT *);
union MappedFunction {
  FARPROC generic;
  MappedName mapped;
};
union MachineFunction {
  FARPROC generic;
  MachinePair pair;
};
union Address {
  FARPROC function;
  LPVOID address;
};
static void identity(FARPROC service) {
  HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
  union MappedFunction mapped;
  union MachineFunction machine;
  union Address address;
  mapped.generic = GetProcAddress(kernel, "K32GetMappedFileNameW");
  machine.generic = GetProcAddress(kernel, "IsWow64Process2");
  address.function = service;
  if (!mapped.generic || !machine.generic)
    ExitProcess(75);
    static WCHAR name[32768];
  USHORT process = 0, native = 0;
  HANDLE current = (HANDLE)(LONG_PTR)-1;
  DWORD count = mapped.mapped(current, address.address, name, 32768);
  if (!count || count == 32768 || !machine.pair(current, &process, &native))
    ExitProcess(76);
  DWORD header[4] = {0x31494b51, process, native, count};
  DWORD written = 0;
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!WriteFile(output, header, sizeof(header), &written, NULL) ||
      written != sizeof(header))
    ExitProcess(77);
  if (!WriteFile(output, name, count * 2, &written, NULL) ||
      written != count * 2)
    ExitProcess(78);
  ExitProcess(0);
}
void __cdecl entry(void) {
  __declspec(align(16)) volatile unsigned char arena[64];
  for (unsigned i = 0; i < 64; ++i)
    arena[i] = 165;
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  union Function f;
  f.generic = GetProcAddress(module, "NtQueryKey");
  if (!module || !f.generic)
    ExitProcess(71);
  const WCHAR *tail = GetCommandLineW();
  while (*tail)
    ++tail;
  if (tail[-1] == L'i')
    identity(f.generic);
  unsigned mode = 0;
  const WCHAR *command = GetCommandLineW();
  for (; *command; ++command)
    if (*command >= L'0' && *command <= L'9')
      mode = (unsigned)(*command - L'0');
  void *buffer = (void *)(arena + 4);
  ULONG length = 32;
  ULONG *returned = (ULONG *)(arena + 4);
  switch (mode) {
  case 1:
    returned = NULL;
    break;
  case 2:
    buffer = NULL;
    returned = (ULONG *)(arena + 32);
    break;
  case 3:
    buffer = NULL;
    length = 0;
    returned = NULL;
    break;
  case 4:
    buffer = (void *)(arena + 1);
    returned = (ULONG *)(arena + 32);
    break;
  case 5:
    buffer = (void *)(arena + 1);
    length = 0;
    returned = (ULONG *)(arena + 32);
    break;
  case 6:
    buffer = (void *)arena;
    returned = NULL;
    break;
  case 7:
    buffer = (void *)arena;
    length = 0;
    returned = NULL;
    break;
  case 8:
    buffer = (void *)(ULONG_PTR)1;
    returned = (ULONG *)(arena + 32);
    break;
  case 9:
    buffer = (void *)(ULONG_PTR)4096;
    returned = (ULONG *)(ULONG_PTR)4096;
    break;
  }
  LONG status = f.query(NULL, 9, buffer, length, returned);
  DWORD written = 0;
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!WriteFile(output, &mode, 4, &written, NULL) || written != 4)
    ExitProcess(74);
  if (!WriteFile(output, &status, 4, &written, NULL) || written != 4)
    ExitProcess(72);
  if (!WriteFile(output, (const void *)arena, 64, &written, NULL) ||
      written != 64)
    ExitProcess(73);
  ExitProcess(0);
}
