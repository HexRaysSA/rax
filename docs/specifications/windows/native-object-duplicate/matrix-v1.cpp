#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <vector>

using Duplicate = LONG(NTAPI *)(HANDLE, HANDLE, HANDLE, HANDLE *, ACCESS_MASK, ULONG, ULONG);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Version = LONG(WINAPI *)(OSVERSIONINFOW *);

struct Source {
  const char *name;
  char kind;
  HANDLE handle;
  bool owned;
};

struct Basic {
  ULONG attributes;
  ACCESS_MASK granted;
  ULONG handle_count;
  ULONG pointer_count;
  ULONG reserved[10];
};
static_assert(sizeof(Basic) == 56);

static HANDLE pseudo(std::intptr_t value) { return reinterpret_cast<HANDLE>(value); }
static unsigned long long word(HANDLE value) {
  return static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value));
}

static bool close_owned(HANDLE value) {
  DWORD flags = 0;
  if (!GetHandleInformation(value, &flags)) return false;
  if ((flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0 &&
      !SetHandleInformation(value, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0)) return false;
  return CloseHandle(value) != FALSE;
}

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto duplicate = reinterpret_cast<Duplicate>(GetProcAddress(ntdll, "NtDuplicateObject"));
  auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryObject"));
  auto version = reinterpret_cast<Version>(GetProcAddress(ntdll, "RtlGetVersion"));
  if (!duplicate || !query || !version) return 2;
  OSVERSIONINFOW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  USHORT process_machine = 0, native_machine = 0;
  if (version(&os) < 0 || !IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)) return 3;
  std::printf("KERNEL major=%lu minor=%lu build=%lu pointer-bytes=%zu process-machine=%04X native-machine=%04X pid=%lu tid=%lu\n",
      os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber, sizeof(void *),
      process_machine, native_machine, GetCurrentProcessId(), GetCurrentThreadId());
  if (os.dwMajorVersion != 10 || os.dwMinorVersion != 0 || os.dwBuildNumber != 29704 ||
      native_machine != 0xaa64) return 4;

  // Resolve/warm every query path before acquiring the handle-count baseline.
  Basic warmed{};
  ULONG returned = 0;
  query(pseudo(-2), 0, &warmed, sizeof(warmed), &returned);
  GetThreadId(GetCurrentThread());
  GetProcessId(GetCurrentProcess());
  DWORD before = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 5;
  std::vector<Source> sources;
  sources.push_back({"pseudo-thread", 't', pseudo(-2), false});
  sources.push_back({"pseudo-process", 'p', pseudo(-1), false});
  bool setup_ok = true;
  auto add = [&](const char *name, char kind, HANDLE original, ACCESS_MASK access, DWORD flags) {
    HANDLE value = nullptr;
    LONG status = duplicate(pseudo(-1), original, pseudo(-1), &value, access, 0, 0);
    std::printf("SOURCE-CREATE name=%s status=%08lX handle=%llX access=%08lX flags=%lu\n",
        name, ULONG(status), word(value), access, flags);
    if (status < 0 || !value) { setup_ok = false; return; }
    sources.push_back({name, kind, value, true});
    if (!SetHandleInformation(value, HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE, flags))
      setup_ok = false;
  };
  add("thread-full", 't', pseudo(-2), THREAD_ALL_ACCESS, 0);
  add("thread-protected", 't', pseudo(-2), THREAD_ALL_ACCESS, HANDLE_FLAG_PROTECT_FROM_CLOSE);
  add("thread-inherited", 't', pseudo(-2), THREAD_ALL_ACCESS, HANDLE_FLAG_INHERIT);
  add("thread-both", 't', pseudo(-2), THREAD_ALL_ACCESS,
      HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE);
  add("thread-query", 't', pseudo(-2), THREAD_QUERY_INFORMATION, 0);
  add("process-full", 'p', pseudo(-1), PROCESS_ALL_ACCESS, 0);
  add("process-dup", 'p', pseudo(-1), PROCESS_DUP_HANDLE, 0);
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (event) sources.push_back({"event", 'e', event, true});
  else setup_ok = false;
  DWORD with_sources = 0;
  GetProcessHandleCount(GetCurrentProcess(), &with_sources);
  std::printf("BASE before=%lu with-sources=%lu sources=%zu setup-ok=%u\n",
      before, with_sources, sources.size(), unsigned(setup_ok));

  const ACCESS_MASK accesses[] = {
      0, 2, 8, 0x40, 0x4a, 0x1fffff, MAXIMUM_ALLOWED, GENERIC_READ,
      GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL, 0x00200000, 0x08000000, 0xffffffff};
  const ULONG attributes[] = {0, 1, 2, 3, 0x200};
  // DUPLICATE_CLOSE_SOURCE is deliberately absent: sources stay stable here.
  const ULONG options[] = {0, DUPLICATE_SAME_ACCESS, 4, 6, 0x10};
  unsigned long rows = 0, successful = 0, closed = 0, anomalies = 0;
  if (setup_ok && sources.size() == 10) {
    for (const Source &source : sources) {
      Basic source_basic{};
      ULONG source_length = 0;
      LONG source_status = query(source.handle, 0, &source_basic, sizeof(source_basic), &source_length);
      DWORD source_flags = 0;
      SetLastError(0);
      BOOL source_info = GetHandleInformation(source.handle, &source_flags);
      DWORD source_error = GetLastError();
      std::printf("SOURCE name=%s kind=%c handle=%llX basic-status=%08lX granted=%08lX basic-attrs=%08lX returned=%lu info=%u flags=%lu error=%lu\n",
          source.name, source.kind, word(source.handle), ULONG(source_status), source_basic.granted,
          source_basic.attributes, source_length, unsigned(source_info), source_flags, source_error);
      for (ACCESS_MASK access : accesses) for (ULONG attribute : attributes) for (ULONG option : options) {
        const std::uintptr_t poison = sizeof(void *) == 8 ? std::uintptr_t(0xa5a5a5a5a5a5a5a5ull)
                                                         : std::uintptr_t(0xa5a5a5a5ul);
        HANDLE output = reinterpret_cast<HANDLE>(poison);
        LONG status = duplicate(pseudo(-1), source.handle, pseudo(-1), &output, access, attribute, option);
        Basic basic{};
        ULONG length = 0;
        LONG basic_status = LONG(0xc0000008ul);
        DWORD flags = 0, info_error = 0, id = 0, id_error = 0;
        BOOL info = FALSE;
        bool released = false;
        const bool changed = reinterpret_cast<std::uintptr_t>(output) != poison;
        if (changed && output && output != pseudo(-1) && output != pseudo(-2)) {
          bool aliases_source = false;
          for (const Source &existing : sources) if (existing.owned && output == existing.handle) aliases_source = true;
          if (aliases_source) {
            ++anomalies;
          } else {
            basic_status = query(output, 0, &basic, sizeof(basic), &length);
            SetLastError(0);
            info = GetHandleInformation(output, &flags);
            info_error = GetLastError();
            if (info) {
              SetLastError(0);
              if (source.kind == 't') id = GetThreadId(output);
              else if (source.kind == 'p') id = GetProcessId(output);
              id_error = GetLastError();
              released = close_owned(output);
              if (released) ++closed;
              else ++anomalies;
            } else if (status >= 0) {
              ++anomalies;
            }
          }
        } else if (status >= 0) {
          ++anomalies;
        }
        if (status >= 0) ++successful;
        ++rows;
        std::printf("ROW source=%s access=%08lX attrs=%08lX options=%08lX status=%08lX changed=%u output=%llX basic-status=%08lX granted=%08lX basic-attrs=%08lX returned=%lu info=%u flags=%lu info-error=%lu id=%lu id-error=%lu closed=%u\n",
            source.name, access, attribute, option, ULONG(status), unsigned(changed), word(output),
            ULONG(basic_status), basic.granted, basic.attributes, length, unsigned(info), flags,
            info_error, id, id_error, unsigned(released));
      }
    }
  }
  DWORD after_rows = 0;
  GetProcessHandleCount(GetCurrentProcess(), &after_rows);
  unsigned long source_closed = 0;
  for (const Source &source : sources) if (source.owned) {
    if (close_owned(source.handle)) ++source_closed;
    else ++anomalies;
  }
  DWORD final = 0;
  GetProcessHandleCount(GetCurrentProcess(), &final);
  std::printf("DONE rows=%lu successful=%lu outputs-closed=%lu source-closed=%lu anomalies=%lu before=%lu with-sources=%lu after-rows=%lu final=%lu\n",
      rows, successful, closed, source_closed, anomalies, before, with_sources, after_rows, final);
  return setup_ok && rows == 3500 && anomalies == 0 && successful == closed &&
      source_closed == 8 && after_rows == with_sources && final == before ? 0 : 21;
}
