#define WIN32_LEAN_AND_MEAN
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *Query)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

enum {
  page_bytes = 4096,
  poison = 0xa5,
};
static const SIZE_T returned_poison = 0xa5a5a5a5;

static void emit(Query query, void *view, unsigned char *pages, const char *tag,
                 const char *kind, size_t declared, size_t clip,
                 DWORD protection, size_t required) {
  memset(pages, poison, page_bytes * 2);
  unsigned char *output = pages + page_bytes - clip;
  DWORD previous = 0;
  if (protection)
    assert(
        VirtualProtect(pages + page_bytes, page_bytes, protection, &previous));
  SIZE_T returned = returned_poison;
  const NTSTATUS status =
      query(GetCurrentProcess(), view, 2, output, declared, &returned);
  MEMORY_BASIC_INFORMATION after;
  assert(VirtualQuery(pages + page_bytes, &after, sizeof(after)) ==
         sizeof(after));
  if (protection)
    assert(VirtualProtect(pages + page_bytes, page_bytes, previous, &previous));
  uintptr_t pointer;
  memcpy(&pointer, output + 4, sizeof(pointer));
  const char *pointer_kind = pointer == (uintptr_t)(output + 8) ? "inline"
                             : pointer == returned_poison       ? "untouched"
                                                                : "temporary";
  if (pointer != returned_poison) {
    const uint32_t marker = pointer == (uintptr_t)(output + 8) ? 8 : 0xfefefefe;
    memcpy(output + 4, &marker, sizeof(marker));
  }
  printf("row=%s case=%s length=%zu clip=%zu required=%zu returned=%lu "
         "status=%08lx "
         "protect=%08lx pointer=%s data=",
         tag, kind, declared, clip, required, (unsigned long)returned,
         (unsigned long)status, after.Protect, pointer_kind);
  for (size_t i = 0; i < required + 2; ++i)
    printf("%02x", (unsigned)output[i]);
  putchar('\n');
}

static void observe(Query query, const wchar_t *path, const char *tag,
                    BOOL create, unsigned char *pages) {
  HANDLE file = CreateFileW(
      path, create ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      create ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  assert(file != INVALID_HANDLE_VALUE);
  if (create) {
    DWORD written = 0;
    assert(WriteFile(file, "x", 1, &written, NULL) && written == 1);
  }
  HANDLE section = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
  assert(section);
  void *view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
  assert(view);
  SIZE_T required = 0;
  __declspec(align(4)) unsigned char control[1024];
  assert(query(GetCurrentProcess(), view, 2, control, sizeof(control),
               &required) == 0);
  assert(required >= 10 && required < 500);
  const UNICODE_STRING *name = (const UNICODE_STRING *)control;
  assert(name->Buffer == (const wchar_t *)(control + 8));
  assert(name->Length + 10 == required);
  assert(!wcsncmp(name->Buffer, L"\\Device\\HarddiskVolume", 22));
  printf("subject=%s required=%lu name_bytes=%u\n", tag,
         (unsigned long)required, (unsigned)name->Length);

  for (SIZE_T size = 0; size <= required + 1; ++size)
    emit(query, view, pages, tag, "length", size, 512, 0, required);
  for (SIZE_T clip = 1; clip <= required + 1; ++clip) {
    emit(query, view, pages, tag, "noaccess", 512, clip, PAGE_NOACCESS,
         required);
    emit(query, view, pages, tag, "guard", 512, clip,
         PAGE_READWRITE | PAGE_GUARD, required);
  }
  assert(UnmapViewOfFile(view));
  assert(CloseHandle(section));
  assert(CloseHandle(file));
}

int wmain(int argc, wchar_t **argv) {
  assert(argc == 2);
  assert(sizeof(void *) == 4 && sizeof(UNICODE_STRING) == 8);
  unsigned short guest = 0, native = 0;
  assert(IsWow64Process2(GetCurrentProcess(), &guest, &native));
  assert(guest == IMAGE_FILE_MACHINE_I386 &&
         native == IMAGE_FILE_MACHINE_ARM64);
  FILE *output = NULL;
  assert(!_wfreopen_s(&output, argv[1], L"wb", stdout));
  Query query = (Query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                      "NtQueryVirtualMemory");
  assert(query);
  unsigned char *pages = VirtualAlloc(NULL, 2 * page_bytes,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  assert(pages);

  wchar_t windows[MAX_PATH], path[MAX_PATH];
  const UINT chars = GetWindowsDirectoryW(windows, MAX_PATH);
  assert(chars > 0 && chars < MAX_PATH);
  assert(swprintf_s(path, MAX_PATH, L"%ls\\win.ini", windows) > 0);
  observe(query, path, "win_ini", FALSE, pages);
  assert(swprintf_s(path, MAX_PATH, L"%ls\\SysWOW64\\kernel32.dll", windows) >
         0);
  observe(query, path, "kernel32", FALSE, pages);
  assert(swprintf_s(path, MAX_PATH,
                    L"%ls\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
                    windows) > 0);
  observe(query, path, "powershell", FALSE, pages);

  const unsigned lengths[] = {1, 19, 39, 79, 140};
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
    wchar_t filename[144];
    const unsigned length = lengths[i];
    assert(length < sizeof(filename) / sizeof(filename[0]));
    wmemset(filename, L'x', length);
    filename[length] = L'\0';
    char tag[16];
    assert(sprintf_s(tag, sizeof(tag), "file%u", length) > 0);
    observe(query, filename, tag, TRUE, pages);
    assert(DeleteFileW(filename));
  }
  assert(VirtualFree(pages, 0, MEM_RELEASE));
  puts("complete guest=014c native=aa64 subjects=8");
  assert(!fclose(output));
  return 0;
}
