#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <vector>
using Query = LONG(NTAPI *)(ULONG, PULONG, PVOID);
static bool generation(ULONG &value) {
  SIZE_T got = 0;
  return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void *>(uintptr_t(0x7FFE03A4)), &value, sizeof(value), &got) && got == sizeof(value);
}
int main() {
  auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetMUIRegistryInfo"));
  if (!query) return 31;
  for (unsigned index = 0; index < 3; ++index) {
    ULONG before = 0, after = 0, size = 0;
    if (!generation(before) || query(0, &size, nullptr) != 0 || size < 16 || size > 1048576) return 32;
    std::vector<unsigned char> first(size), second(size);
    const ULONG expected = size;
    if (query(0, &size, first.data()) != 0 || size != expected || query(0, &size, second.data()) != 0 || size != expected || first != second || !generation(after)) return 33;
    ULONG payload = 0;
    for (unsigned byte = 0; byte < 4; ++byte) payload |= ULONG(first[12 + byte]) << (byte * 8);
    std::printf("generation ordinal=%u shared-before=%lu payload-generation=%lu shared-after=%lu bytes=%lu hex=", index, before, payload, after, size);
    for (unsigned char byte : first) std::printf("%02X", unsigned(byte));
    std::puts("");
    if (before != payload || payload != after) return 34;
  }
  std::puts("complete captures=3 read-only=1");
  return 0;
}
