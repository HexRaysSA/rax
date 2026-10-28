#include <stdio.h>
#include <windows.h>

int main(void) {
  HMODULE module = GetModuleHandleW(L"kernel32.dll");
  WCHAR path[32768];
  DWORD count = GetModuleFileNameW(module, path, 32768);
  if (!count || count >= 32768)
    return 2;
  char utf8[131072];
  int bytes = WideCharToMultiByte(CP_UTF8, 0, path, count, utf8, sizeof(utf8),
                                  NULL, NULL);
  if (!bytes)
    return 3;
  printf("module=%.*s\n", bytes, utf8);
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)module + dos->e_lfanew);
  printf("timestamp=%08lx;image_size=%08lx\n", nt->FileHeader.TimeDateStamp,
         nt->OptionalHeader.SizeOfImage);
  return 0;
}
