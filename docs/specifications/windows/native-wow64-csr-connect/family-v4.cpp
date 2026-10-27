#define WIN32_LEAN_AND_MEAN
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <windows.h>
#include <winternl.h>

using Connect = NTSTATUS(NTAPI *)(PWSTR, ULONG, PVOID, ULONG, PBOOLEAN);
struct Result {
  ULONG status;
  ULONG exception;
};

static Result invoke(Connect fn, PWSTR directory, ULONG server, PVOID data,
                     ULONG bytes, PBOOLEAN inside) {
  __try {
    return {static_cast<ULONG>(fn(directory, server, data, bytes, inside)), 0};
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return {0xDEADBEEF, GetExceptionCode()};
  }
}

enum Kind {
  Ordinary,
  NullBuffer,
  NoAccessBuffer,
  GuardBuffer,
  ReadonlyBuffer,
  CrossBuffer,
  NullInside,
  BadInside,
  NoAccessInside,
  GuardInside,
  ReadonlyInside,
  AliasFirst,
  AliasFifth,
  AliasTail,
  NullDirectory,
  BadDirectory,
  NoAccessDirectory,
  GuardDirectory,
  MissingDirectory,
  UnalignedBuffer,
  ReadonlyGuardBuffer,
  ReadonlyGuardInside
};
struct Case {
  const char *name;
  ULONG server;
  ULONG bytes;
  Kind kind;
  BYTE fill;
  Kind second = Ordinary;
};

static ULONG protection(void *pointer) {
  MEMORY_BASIC_INFORMATION region{};
  return VirtualQuery(pointer, &region, sizeof(region)) == sizeof(region)
             ? region.Protect
             : 0xFFFFFFFF;
}

static void dump(void *pointer, SIZE_T count) {
  const ULONG flags = protection(pointer);
  if (!pointer || (flags & (PAGE_GUARD | PAGE_NOACCESS)) ||
      flags == 0xFFFFFFFF) {
    std::printf("unreadable");
    return;
  }
  std::array<BYTE, 80> data{};
  SIZE_T got = 0;
  if (!ReadProcessMemory(GetCurrentProcess(), pointer, data.data(), count,
                         &got)) {
    std::printf("rpm-error-%lu-got-%zu", GetLastError(), got);
    return;
  }
  for (SIZE_T index = 0; index < got; ++index)
    std::printf("%02X", unsigned(data[index]));
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 12;
  FILE *stream = nullptr;
  if (freopen_s(&stream, argv[1], "wb", stdout) != 0 || !stream)
    return 13;
  auto ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll)
    return 2;
  std::printf("IDENTITY profile=%s pointer-bytes=%zu\n",
              argc > 1 ? argv[1] : "unknown", sizeof(void *));
  const auto image_base = reinterpret_cast<const BYTE *>(ntdll);
  const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(image_base);
  const auto nt =
      reinterpret_cast<const IMAGE_NT_HEADERS32 *>(image_base + dos->e_lfanew);
  std::printf("IMAGE machine=%04X\n", unsigned(nt->FileHeader.Machine));
  using Version = NTSTATUS(NTAPI *)(PRTL_OSVERSIONINFOW);
  auto version =
      reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  RTL_OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  if (!version || version(&os) != 0)
    return 3;
  std::printf("KERNEL major=%lu minor=%lu build=%lu\n", os.dwMajorVersion,
              os.dwMinorVersion, os.dwBuildNumber);
  auto pages = static_cast<BYTE *>(VirtualAlloc(
      nullptr, 4 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  if (!pages)
    return 4;
  const Case cases[] = {
      {"base-zero", 1, 8, Ordinary, 0},
      {"base-a5", 1, 8, Ordinary, 0xA5},
      {"base-5a", 1, 8, Ordinary, 0x5A},
      {"base-ff", 1, 8, Ordinary, 0xFF},
      {"base-repeat", 1, 8, Ordinary, 0},
      {"length-0", 1, 0, Ordinary, 0xA5},
      {"length-1", 1, 1, Ordinary, 0xA5},
      {"length-4", 1, 4, Ordinary, 0xA5},
      {"length-7", 1, 7, Ordinary, 0xA5},
      {"length-9", 1, 9, Ordinary, 0xA5},
      {"length-16", 1, 16, Ordinary, 0xA5},
      {"length-64", 1, 64, Ordinary, 0xA5},
      {"null-buffer-0", 1, 0, NullBuffer, 0xA5},
      {"null-buffer-8", 1, 8, NullBuffer, 0xA5},
      {"noaccess-buffer", 1, 8, NoAccessBuffer, 0xA5},
      {"guard-buffer", 1, 8, GuardBuffer, 0xA5},
      {"readonly-buffer", 1, 8, ReadonlyBuffer, 0xA5},
      {"cross-buffer", 1, 8, CrossBuffer, 0xA5},
      {"null-inside", 1, 8, NullInside, 0xA5},
      {"bad-inside", 1, 8, BadInside, 0xA5},
      {"noaccess-inside", 1, 8, NoAccessInside, 0xA5},
      {"guard-inside", 1, 8, GuardInside, 0xA5},
      {"readonly-inside", 1, 8, ReadonlyInside, 0xA5},
      {"alias-first", 1, 8, AliasFirst, 0xA5},
      {"alias-fifth", 1, 8, AliasFifth, 0xA5},
      {"alias-tail", 1, 8, AliasTail, 0xA5},
      {"null-directory", 1, 8, NullDirectory, 0xA5},
      {"bad-directory", 1, 8, BadDirectory, 0xA5},
      {"noaccess-directory", 1, 8, NoAccessDirectory, 0xA5},
      {"guard-directory", 1, 8, GuardDirectory, 0xA5},
      {"missing-directory", 1, 8, MissingDirectory, 0xA5},
      {"bootstrap", 0, 0, NullBuffer, 0xA5},
      {"server-2", 2, 8, Ordinary, 0xA5},
      {"length-31", 1, 31, Ordinary, 0xA5},
      {"length-32", 1, 32, Ordinary, 0xA5},
      {"length-79", 1, 79, Ordinary, 0xA5},
      {"length-80", 1, 80, Ordinary, 0xA5},
      {"unaligned-buffer", 1, 8, UnalignedBuffer, 0xA5},
      {"readonly-guard-buffer", 1, 8, ReadonlyGuardBuffer, 0xA5},
      {"readonly-guard-inside", 1, 8, ReadonlyGuardInside, 0xA5},
      {"zero-guard-buffer", 1, 0, GuardBuffer, 0xA5},
      {"zero-readonly-buffer", 1, 0, ReadonlyBuffer, 0xA5},
      {"zero-both-guards", 1, 0, GuardBuffer, 0xA5, GuardInside},
      {"short-guard-buffer", 1, 7, GuardBuffer, 0xA5},
      {"short-readonly-buffer", 1, 7, ReadonlyBuffer, 0xA5},
      {"short-guard-inside", 1, 7, Ordinary, 0xA5, GuardInside},
      {"short-noaccess-inside", 1, 7, Ordinary, 0xA5, NoAccessInside},
      {"null-guard-inside", 1, 0, NullBuffer, 0xA5, GuardInside},
      {"null-readonly-guard-inside", 1, 8, NullBuffer, 0xA5,
       ReadonlyGuardInside},
      {"both-guards", 1, 8, GuardBuffer, 0xA5, GuardInside},
      {"noaccess-buffer-guard-inside", 1, 8, NoAccessBuffer, 0xA5, GuardInside},
      {"readonly-buffer-guard-inside", 1, 8, ReadonlyBuffer, 0xA5, GuardInside},
      {"guard-buffer-noaccess-inside", 1, 8, GuardBuffer, 0xA5, NoAccessInside},
      {"readonly-buffer-null-inside", 1, 8, ReadonlyBuffer, 0xA5, NullInside},
      {"short-alias-first", 1, 7, AliasFirst, 0xA5},
      {"zero-alias-first", 1, 0, AliasFirst, 0xA5},

  };
  unsigned calls = 0;
  for (const char *name :
       {"CsrClientConnectToServer", "NtWow64CsrClientConnectToServer"}) {
    auto address = GetProcAddress(ntdll, name);
    auto fn = reinterpret_cast<Connect>(address);
    std::printf("EXPORT name=%s available=%u rva=%llX\n", name,
                unsigned(fn != nullptr),
                fn ? static_cast<unsigned long long>(
                         reinterpret_cast<uintptr_t>(address) -
                         reinterpret_cast<uintptr_t>(ntdll))
                   : 0);
    if (!fn)
      continue;
    for (const Case &sample : cases) {
      ULONG old = 0;
      if (!VirtualProtect(pages, 4 * 4096, PAGE_READWRITE, &old))
        return 5;
      std::memset(pages, sample.fill, 4 * 4096);
      std::array<BYTE, 80> ordinary{};
      ordinary.fill(sample.fill);
      BOOLEAN inside = 0xA5;
      wchar_t directory[] = L"\\Windows";
      wchar_t missing[] = L"\\AssistMissingCsrDirectory";
      std::memcpy(pages + 3 * 4096, directory, sizeof(directory));
      PVOID data = ordinary.data();
      PBOOLEAN output = &inside;
      PWSTR root = directory;
      ULONG mode = PAGE_READWRITE;
      switch (sample.kind) {
      case NullBuffer:
        data = nullptr;
        break;
      case NoAccessBuffer:
        data = pages;
        mode = PAGE_NOACCESS;
        break;
      case GuardBuffer:
        data = pages;
        mode = PAGE_READWRITE | PAGE_GUARD;
        break;
      case ReadonlyBuffer:
        data = pages;
        mode = PAGE_READONLY;
        break;
      case CrossBuffer:
        data = pages + 4096 - 4;
        if (!VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old))
          return 6;
        break;
      case NullInside:
        output = nullptr;
        break;
      case BadInside:
        output = reinterpret_cast<PBOOLEAN>(1);
        break;
      case NoAccessInside:
        output = pages + 2 * 4096;
        mode = PAGE_NOACCESS;
        break;
      case GuardInside:
        output = pages + 2 * 4096;
        mode = PAGE_READWRITE | PAGE_GUARD;
        break;
      case ReadonlyInside:
        output = pages + 2 * 4096;
        mode = PAGE_READONLY;
        break;
      case AliasFirst:
        output = ordinary.data();
        break;
      case AliasFifth:
        output = ordinary.data() + 4;
        break;
      case AliasTail:
        output = ordinary.data() + 8;
        break;
      case NullDirectory:
        root = nullptr;
        break;
      case BadDirectory:
        root = reinterpret_cast<PWSTR>(1);
        break;
      case NoAccessDirectory:
        root = reinterpret_cast<PWSTR>(pages + 3 * 4096);
        mode = PAGE_NOACCESS;
        break;
      case GuardDirectory:
        root = reinterpret_cast<PWSTR>(pages + 3 * 4096);
        mode = PAGE_READWRITE | PAGE_GUARD;
        break;
      case MissingDirectory:
        root = missing;
        break;
      case UnalignedBuffer:
        data = ordinary.data() + 1;
        break;
      case ReadonlyGuardBuffer:
        data = pages;
        mode = PAGE_READONLY | PAGE_GUARD;
        break;
      case ReadonlyGuardInside:
        output = pages + 2 * 4096;
        mode = PAGE_READONLY | PAGE_GUARD;
        break;
      default:
        break;
      }
      BYTE *protected_page =
          ((sample.kind >= NoAccessInside && sample.kind <= ReadonlyInside) ||
           sample.kind == ReadonlyGuardInside)
              ? pages + 2 * 4096
          : sample.kind == NoAccessDirectory || sample.kind == GuardDirectory
              ? pages + 3 * 4096
              : pages;
      if (mode != PAGE_READWRITE &&
          !VirtualProtect(protected_page, 4096, mode, &old))
        return 7;
      if (sample.second != Ordinary) {
        if (sample.second == NullInside)
          output = nullptr;
        else {
          output = pages + 2 * 4096;
          ULONG second_mode = sample.second == NoAccessInside ? PAGE_NOACCESS
                              : sample.second == ReadonlyGuardInside
                                  ? PAGE_READONLY | PAGE_GUARD
                                  : PAGE_READWRITE | PAGE_GUARD;
          if (!VirtualProtect(output, 4096, second_mode, &old))
            return 10;
        }
      }
      const ULONG before_data = protection(data),
                  before_inside = protection(output),
                  before_root = protection(root);
      DWORD handles_before = 0, handles_after = 0;
      if (!GetProcessHandleCount(GetCurrentProcess(), &handles_before))
        return 14;
      const Result result =
          invoke(fn, root, sample.server, data, sample.bytes, output);
      if (!GetProcessHandleCount(GetCurrentProcess(), &handles_after))
        return 15;
      std::printf("COUNTS before=%lu after=%lu\n", handles_before,
                  handles_after);
      std::printf("CASE export=%s name=%s server=%lu bytes=%lu fill=%02X "
                  "status=%08lX exception=%08lX local-inside=%02X "
                  "protections=%08lX,%08lX,%08lX:%08lX,%08lX,%08lX ordinary=",
                  name, sample.name, sample.server, sample.bytes,
                  unsigned(sample.fill), result.status, result.exception,
                  unsigned(inside), before_data, before_inside, before_root,
                  protection(data), protection(output), protection(root));
      dump(ordinary.data(), ordinary.size());
      std::printf(" actual-buffer=");
      dump(data, sample.kind == CrossBuffer ? 4 : 16);
      std::printf(" actual-inside=");
      dump(output, 1);
      std::puts("");
      ++calls;
    }
  }
  if (!VirtualFree(pages, 0, MEM_RELEASE))
    return 8;
  std::printf("DONE calls=%u\n", calls);
  return calls >= 33 ? 0 : 9;
}
