#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <windows.h>

using Query = LONG(NTAPI *)(HANDLE, const void *, ULONG, void *, SIZE_T,
                            SIZE_T *);
static Query query;
static unsigned char *memory;
static HMODULE image;
static HANDLE processes[10];
static LONG invoke(HANDLE process, const void *base, void *output,
                   SIZE_T length, SIZE_T *returned, ULONG *exception) {
  __try {
    return query(process, base, 14, output, length, returned);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    *exception = GetExceptionCode();
    return LONG(*exception);
  }
}
static void protect(unsigned page, DWORD flags) {
  DWORD old = 0;
  if (!VirtualProtect(memory + page * 4096, 4096, flags, &old)) {
    printf("failure=protect page=%u flags=%lX error=%lu\n", page, flags,
           GetLastError());
    ExitProcess(20);
  }
}
static void dump(unsigned offset, unsigned length) {
  for (unsigned i = 0; i < length; ++i)
    printf("%02X", unsigned(memory[offset + i]));
}
static void one(unsigned ordinal, unsigned family, unsigned process,
                unsigned target, SIZE_T length, unsigned output_mode,
                unsigned returned_mode, unsigned selector) {
  for (unsigned page = 0; page < 4; ++page)
    protect(page, PAGE_READWRITE);
  memset(memory, 0xa5, 16384);
  ULONG type = selector == 1 ? 2 : 1, flags = selector == 2 ? 1 : 0;
  void *output = memory + 128;
  SIZE_T *returned = reinterpret_cast<SIZE_T *>(memory + 256);
  switch (output_mode) {
  case 1:
    output = nullptr;
    break;
  case 2:
    output = reinterpret_cast<void *>(uintptr_t(1));
    break;
  case 3:
    output = memory + 129;
    break;
  case 4:
    output = memory + 132;
    break;
  case 5:
    output = memory + 4096;
    break;
  case 6:
    output = memory + 4096;
    break;
  case 7:
    output = memory + 4096;
    break;
  case 8:
    output = memory + 4080;
    break;
  case 9:
    output = memory + 4080;
    break;
  case 10:
    output = memory + 4080;
    break;
  case 11:
    output = memory + 4072;
    break;
  }
  if (output_mode != 1 && output_mode != 2) {
    memcpy(output, &type, 4);
    memcpy(static_cast<unsigned char *>(output) + 4, &flags, 4);
  }
  switch (returned_mode) {
  case 1:
    returned = nullptr;
    break;
  case 2:
    returned = reinterpret_cast<SIZE_T *>(uintptr_t(1));
    break;
  case 3:
    returned = reinterpret_cast<SIZE_T *>(memory + 257);
    break;
  case 4:
    returned = reinterpret_cast<SIZE_T *>(memory + 8192);
    break;
  case 5:
    returned = reinterpret_cast<SIZE_T *>(memory + 8192);
    break;
  case 6:
    returned = reinterpret_cast<SIZE_T *>(memory + 8192);
    break;
  case 7:
    returned = reinterpret_cast<SIZE_T *>(memory + 4096);
    break;
  case 8:
    returned = static_cast<SIZE_T *>(output);
    break;
  case 9:
    returned = reinterpret_cast<SIZE_T *>(memory + 8192 - 4);
    break;
  }
  if (output_mode == 5 || output_mode == 8 || output_mode == 11)
    protect(1, PAGE_NOACCESS);
  if (output_mode == 6 || output_mode == 9)
    protect(1, PAGE_READWRITE | PAGE_GUARD);
  if (output_mode == 7 || output_mode == 10)
    protect(1, PAGE_READONLY);
  if (returned_mode == 4 || returned_mode == 9)
    protect(2, PAGE_NOACCESS);
  if (returned_mode == 5)
    protect(2, PAGE_READWRITE | PAGE_GUARD);
  if (returned_mode == 6)
    protect(2, PAGE_READONLY);
  const void *address = image;
  switch (target) {
  case 1:
    address = memory + 12288;
    break;
  case 2:
    address = reinterpret_cast<void *>(uintptr_t(1));
    break;
  case 3:
    address = nullptr;
    break;
  case 4:
    address = reinterpret_cast<void *>(~uintptr_t(0));
    break;
  }
  ULONG exception = 0;
  LONG status =
      invoke(processes[process], address, output, length, returned, &exception);
  DWORD protection[4]{};
  for (unsigned page = 0; page < 4; ++page) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(memory + page * 4096, &info, sizeof(info)))
      ExitProcess(21);
    protection[page] = info.Protect;
    protect(page, PAGE_READWRITE);
  }
  printf("case=%u family=%u process=%u target=%u length=%llX output=%u "
         "returned=%u selector=%u status=%08lX exception=%08lX protection=",
         ordinal, family, process, target,
         static_cast<unsigned long long>(length), output_mode, returned_mode,
         selector, status, exception);
  for (auto value : protection)
    printf("%08lX,", value);
  printf(" bytes0=");
  dump(120, 160);
  printf(" bytes1=");
  dump(4064, 96);
  printf(" bytes2=");
  dump(8176, 48);
  puts("");
}
int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  image = GetModuleHandleW(nullptr);
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  query =
      reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryVirtualMemory"));
  memory = static_cast<unsigned char *>(
      VirtualAlloc(nullptr, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!query || !memory)
    return 22;
  processes[0] = GetCurrentProcess();
  processes[1] = nullptr;
  processes[2] = reinterpret_cast<HANDLE>(intptr_t(-2));
  processes[3] = reinterpret_cast<HANDLE>(uintptr_t(0x1234));
  unsigned index = 4;
  for (DWORD access : {0u, 0x10u, 0x400u, 0x1000u, 0x1400u}) {
    if (access == 0) {
      if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                           GetCurrentProcess(), &processes[index], 0, FALSE,
                           0)) {
        printf("failure=duplicate-zero-process error=%lu\n", GetLastError());
        return 23;
      }
      ++index;
    } else {
      processes[index++] = OpenProcess(access, FALSE, GetCurrentProcessId());
    }
    if (!processes[index - 1])
      return 23;
  }
  processes[9] = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  if (!processes[9])
    return 24;
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 25;
  printf("host pointer=%zu image=%p memory=%p handles-before=%lu\n",
         sizeof(void *), image, memory, before);
  unsigned ordinal = 0;
  for (SIZE_T length : {0u, 23u, 24u, 25u, 4097u})
    for (unsigned output = 0; output < 12; ++output)
      for (unsigned returned = 0; returned < 10; ++returned)
        for (unsigned target = 0; target < 5; ++target)
          for (unsigned selector = 0; selector < 3; ++selector)
            one(ordinal++, 0, 0, target, length, output, returned, selector);
  for (unsigned process = 1; process < 10; ++process)
    for (SIZE_T length : {23u, 24u})
      for (unsigned output = 0; output < 12; ++output)
        for (unsigned returned = 0; returned < 10; ++returned)
          for (unsigned selector = 0; selector < 3; ++selector)
            one(ordinal++, 1, process, 0, length, output, returned, selector);
  if (!GetProcessHandleCount(GetCurrentProcess(), &after) || before != after)
    return 26;
  for (unsigned i = 4; i < 10; ++i)
    if (!CloseHandle(processes[i]))
      return 27;
  if (!VirtualFree(memory, 0, MEM_RELEASE))
    return 28;
  printf("complete cases=%u handles-before=%lu handles-after=%lu\n", ordinal,
         before, after);
  return 0;
}
