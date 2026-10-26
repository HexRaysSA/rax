#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#if defined(_M_IX86)
using Initialize = LONG(NTAPI *)(PVOID *, ULONG *, LARGE_INTEGER *);
#else
using Initialize = LONG(NTAPI *)(PVOID *, ULONG *, LARGE_INTEGER *, ULONG *);
#endif
using Unmap = LONG(NTAPI *)(HANDLE, PVOID);
static Initialize initialize;
static Unmap unmap;
static unsigned ordinal;
static unsigned successes, failures, exceptions, unmapped;

static void hex(const void *p, size_t size) {
  auto b = static_cast<const unsigned char *>(p);
  for (size_t i = 0; i < size; ++i)
    printf("%02X", b[i]);
}

struct LocaleViews {
  uintptr_t bases[256];
  unsigned count;
};
static LocaleViews locale_views() {
  LocaleViews result = {};
  uintptr_t cursor = 0;
  for (unsigned steps = 0; steps < 65536; ++steps) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<void *>(cursor), &mbi, sizeof(mbi)) !=
        sizeof(mbi))
      return result;
    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED &&
        mbi.BaseAddress == mbi.AllocationBase) {
      wchar_t filename[1024] = {};
      DWORD chars = GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress,
                                       filename, 1024);
      if (chars >= 11 && chars < 1024 &&
          _wcsicmp(filename + chars - 11, L"\\locale.nls") == 0) {
        if (result.count >= 256)
          ExitProcess(97);
        result.bases[result.count++] =
            reinterpret_cast<uintptr_t>(mbi.AllocationBase);
      }
    }
    uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    if (base > ~uintptr_t(0) - mbi.RegionSize ||
        base + mbi.RegionSize <= cursor)
      return result;
    cursor = base + mbi.RegionSize;
  }
  ExitProcess(98);
}

static void run(const char *name, int argument, int variant, int other = -1,
                int other_variant = 0) {
  auto scratch = static_cast<unsigned char *>(
      VirtualAlloc(nullptr, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!scratch)
    ExitProcess(90);
  memset(scratch, 0xA5, 16384);
  DWORD old = 0;
  if (!VirtualProtect(scratch + 4096, 4096, PAGE_READONLY, &old) ||
      !VirtualProtect(scratch + 8192, 4096, PAGE_NOACCESS, &old) ||
      !VirtualProtect(scratch + 12288, 4096, PAGE_READWRITE | PAGE_GUARD, &old))
    ExitProcess(91);
  void *args[4] = {scratch + 256, scratch + 288, scratch + 320, scratch + 352};
  for (unsigned i = 0; i < 4; ++i) {
    int kind = static_cast<int>(i) == argument ? variant : 0;
    if (static_cast<int>(i) == other)
      kind = other_variant;
    switch (kind) {
    case 1:
      args[i] = nullptr;
      break;
    case 2:
      args[i] = reinterpret_cast<void *>(1);
      break;
    case 3:
      args[i] = scratch + 4096 + 256 + i * 32;
      break;
    case 4:
      args[i] = scratch + 8192 + 256 + i * 32;
      break;
    case 5:
      args[i] = scratch + 256 + i * 32 + 1;
      break;
    case 6:
      args[i] = scratch + 4095;
      break;
    case 7:
      args[i] = reinterpret_cast<void *>(~uintptr_t(0));
      break;
    case 8:
      args[i] = scratch + 384;
      break;
    case 9:
      args[i] = scratch + 12288 + 256 + i * 32;
      break;
    default:
      break;
    }
  }
  auto before = locale_views();
  LONG status = 0;
  DWORD exception = 0;
  __try {
#if defined(_M_IX86)
    status = initialize(static_cast<PVOID *>(args[0]),
                        static_cast<ULONG *>(args[1]),
                        static_cast<LARGE_INTEGER *>(args[2]));
#else
    status = initialize(
        static_cast<PVOID *>(args[0]), static_cast<ULONG *>(args[1]),
        static_cast<LARGE_INTEGER *>(args[2]), static_cast<ULONG *>(args[3]));
#endif
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    exception = GetExceptionCode();
  }
  printf("case ordinal=%u name=%s argument=%d variant=%d other=%d "
         "other-variant=%d status=%08lX seh=%08lX pointer-bytes=%zu\n",
         ordinal++, name, argument, variant, other, other_variant,
         static_cast<unsigned long>(status), exception, sizeof(void *));
  MEMORY_BASIC_INFORMATION guard = {};
  if (VirtualQuery(scratch + 12288, &guard, sizeof(guard)) != sizeof(guard))
    ExitProcess(96);
  printf("guard protect=%08lX\n", guard.Protect);
  auto after = locale_views();
  printf("locale-views before=%u after=%u", before.count, after.count);
  for (unsigned i = 0; i < after.count; ++i) {
    bool existed = false;
    for (unsigned j = 0; j < before.count; ++j)
      existed |= after.bases[i] == before.bases[j];
    if (!existed)
      printf(" new=%p", reinterpret_cast<void *>(after.bases[i]));
  }
  printf("\n");
  printf("outputs hex=");
  hex(scratch + 256, 144);
  printf("\nchanges");
  for (size_t i = 0; i < 4096;) {
    if (scratch[i] == 0xA5) {
      ++i;
      continue;
    }
    size_t start = i;
    while (i < 4096 && scratch[i] != 0xA5)
      ++i;
    printf(" offset=%zu bytes=%zu hex=", start, i - start);
    hex(scratch + start, i - start);
  }
  printf("\n");
  if (exception)
    ++exceptions;
  else if (status < 0)
    ++failures;
  else
    ++successes;
  uintptr_t candidate = 0;
  auto out = reinterpret_cast<uintptr_t>(args[0]);
  auto first = reinterpret_cast<uintptr_t>(scratch);
  if (out >= first && out <= first + 4096 - sizeof(void *)) {
    memcpy(&candidate, args[0], sizeof(candidate));
    MEMORY_BASIC_INFORMATION mbi = {};
    if (candidate &&
        VirtualQuery(reinterpret_cast<void *>(candidate), &mbi, sizeof(mbi)) ==
            sizeof(mbi) &&
        mbi.AllocationBase == reinterpret_cast<void *>(candidate) &&
        mbi.Type == MEM_MAPPED && mbi.State == MEM_COMMIT) {
      wchar_t filename[1024] = {};
      DWORD chars = GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress,
                                       filename, 1024);
      printf("mapping base=%p allocation=%p bytes=%zu state=%08lX "
             "protect=%08lX allocation-protect=%08lX type=%08lX "
             "filename-chars=%lu filename=%ls\n",
             mbi.BaseAddress, mbi.AllocationBase, mbi.RegionSize, mbi.State,
             mbi.Protect, mbi.AllocationProtect, mbi.Type, chars, filename);
      if (mbi.Protect == PAGE_READONLY && mbi.RegionSize >= 128) {
        printf("prefix hex=");
        hex(mbi.BaseAddress, 128);
        printf("\n");
      }
      LONG cleanup = unmap(GetCurrentProcess(), mbi.AllocationBase);
      printf("unmap status=%08lX\n", static_cast<unsigned long>(cleanup));
      if (cleanup < 0)
        ExitProcess(92);
      ++unmapped;
    }
  }
  if (!VirtualFree(scratch, 0, MEM_RELEASE))
    ExitProcess(93);
  fflush(stdout);
}

int main() {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  initialize = reinterpret_cast<Initialize>(
      GetProcAddress(ntdll, "NtInitializeNlsFiles"));
  unmap =
      reinterpret_cast<Unmap>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  if (!initialize || !unmap)
    return 94;
  printf("producer name=native-nls-initialize pointer-bytes=%zu\n",
         sizeof(void *));
  run("all-writable", -1, 0);
  for (int argument = 0; argument < 4; ++argument)
    for (int variant = 1; variant <= 9; ++variant)
      run("single-output", argument, variant);
  for (int first = 0; first < 4; ++first)
    for (int second = first + 1; second < 4; ++second) {
      run("both-null", first, 1, second, 1);
      run("both-bad", first, 2, second, 2);
      run("same-output", first, 8, second, 8);
      run("first-bad-second-readonly", first, 2, second, 3);
      run("first-readonly-second-bad", first, 3, second, 2);
    }
  for (int first = 0; first < 4; ++first)
    for (int second = first + 1; second < 4; ++second) {
      run("first-guard-second-bad", first, 9, second, 2);
      run("first-bad-second-guard", first, 2, second, 9);
    }
  printf("complete cases=%u success=%u failed=%u seh=%u unmapped=%u\n", ordinal,
         successes, failures, exceptions, unmapped);
  return exceptions ? 95 : 0;
}
