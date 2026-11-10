#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define PSAPI_VERSION 2
#include <cstdint>
#include <cstdio>
#include <windows.h>
#include <psapi.h>

static void text(const char *name, const wchar_t *value, DWORD count) {
  std::printf("text name=%s units=%lu hex=", name, count);
  for (DWORD index = 0; index < count; ++index)
    std::printf("%04X", unsigned(value[index]));
  std::puts("");
}

int main() {
  const HANDLE process = GetCurrentProcess();
  const HMODULE module = GetModuleHandleW(L"ntdll.dll");
  if (!module)
    return 21;
  USHORT caller_machine = 0, native_machine = 0;
  if (!IsWow64Process2(process, &caller_machine, &native_machine))
    return 22;
  wchar_t logical[32768]{}, mapped[32768]{};
  const DWORD logical_units = GetModuleFileNameW(module, logical, 32768);
  const DWORD mapped_units = K32GetMappedFileNameW(process, module, mapped, 32768);
  if (!logical_units || logical_units >= 32768 || !mapped_units || mapped_units >= 32768)
    return 23;
  if (logical_units < 3 || logical[1] != L':')
    return 26;
  wchar_t drive[] = {logical[0], L':', L'\0'};
  wchar_t drive_target[32768]{};
  if (!QueryDosDeviceW(drive, drive_target, 32768))
    return 27;
  DWORD drive_units = 0;
  while (drive_units < 32768 && drive_target[drive_units])
    ++drive_units;
  if (!drive_units || drive_units == 32768)
    return 28;
  const auto getter = GetProcAddress(module, "CsrGetProcessId");
  if (!getter)
    return 24;
  unsigned char code[64]{};
  SIZE_T returned = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<const void *>(getter), code,
                         sizeof(code), &returned) || returned != sizeof(code))
    return 25;
  std::printf("profile width=%zu caller-machine=%04X native-machine=%04X module=%llX getter-rva=%llX\n",
              sizeof(void *), unsigned(caller_machine), unsigned(native_machine),
              static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(module)),
              static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(getter) -
                                              reinterpret_cast<uintptr_t>(module)));
  text("logical-provider", logical, logical_units);
  text("mapped-provider", mapped, mapped_units);
  text("drive-target", drive_target, drive_units);
  std::printf("getter-code bytes=64 hex=");
  for (unsigned char value : code)
    std::printf("%02X", unsigned(value));
  std::puts("");
  std::puts("complete read-only=1 getter-called=0");
  return 0;
}
