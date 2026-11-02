#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <initializer_list>
#include <windows.h>
#include <winternl.h>

// Fixed installed keys, query-only access, private descriptors and handles.
// No registry value, key, override or process-wide default is changed.
using Open = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using OpenEx = LONG(NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, ULONG);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Close = LONG(NTAPI *)(HANDLE);
static Open open_key;
static OpenEx open_ex;
static Query query_key;
static Close close_key;
static unsigned ordinal;
static const wchar_t *current_version =
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
static const wchar_t *appmodel =
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\AppModel\\Lookaside\\machine";

struct Key {
  HANDLE value = nullptr;
  Key() = default;
  Key(const Key &) = delete;
  Key &operator=(const Key &) = delete;
  ~Key() {
    if (value)
      close_key(value);
  }
};

static LONG invoke(bool extended, HANDLE *out, ULONG view, HANDLE root,
                   const wchar_t *text) {
  const auto length = USHORT(wcslen(text) * sizeof(wchar_t));
  UNICODE_STRING name{};
  name.Length = length;
  name.MaximumLength = length + sizeof(wchar_t);
  name.Buffer = const_cast<wchar_t *>(text);
  OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  attributes.RootDirectory = root;
  attributes.ObjectName = &name;
  attributes.Attributes = 0x40;
  return extended ? open_ex(out, 0x20019 | view, &attributes, 0)
                  : open_key(out, 0x20019 | view, &attributes);
}

static void observe(bool extended, unsigned path_kind, ULONG root_view,
                    HANDLE root, const wchar_t *name, ULONG view) {
  Key key;
  const LONG status = invoke(extended, &key.value, view, root, name);
  struct alignas(8) NameInformation {
    ULONG bytes;
    wchar_t units[32766];
  } data{};
  static_assert(sizeof(data) == 65536);
  ULONG returned = 0;
  const LONG name_status = status >= 0
                               ? query_key(key.value, 3, &data, sizeof(data), &returned)
                               : LONG(0xE0000001);
  ULONG bytes = 0;
  if (name_status >= 0) {
    bytes = data.bytes;
    if (returned > sizeof(data) || returned < 4 || bytes > returned - 4 || bytes % 2)
      ExitProcess(11);
  }
  ULONG tags = 0xA5A5A5A5;
  const LONG tag_status = status >= 0
                              ? query_key(key.value, 7, &tags, sizeof(tags), &returned)
                              : LONG(0xE0000001);
  printf("{\"kind\":\"open\",\"ordinal\":%u,\"extended\":%u,"
         "\"path_kind\":%u,\"root_view\":%lu,\"view\":%lu,\"status\":%lu,"
         "\"name_status\":%lu,\"tag_status\":%lu,\"tags\":%lu,\"name_units\":[",
         ordinal++, unsigned(extended), path_kind, root_view, view, ULONG(status),
         ULONG(name_status), ULONG(tag_status), tags);
  for (ULONG i = 0; i < bytes / sizeof(wchar_t); ++i)
    printf("%s%u", i ? "," : "", unsigned(data.units[i]));
  puts("]}");
}

int main() {
  static_assert(sizeof(wchar_t) == 2);
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  open_key = reinterpret_cast<Open>(GetProcAddress(ntdll, "NtOpenKey"));
  open_ex = reinterpret_cast<OpenEx>(GetProcAddress(ntdll, "NtOpenKeyEx"));
  query_key = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryKey"));
  close_key = reinterpret_cast<Close>(GetProcAddress(ntdll, "NtClose"));
  if (!open_key || !open_ex || !query_key || !close_key)
    return 10;
  USHORT process_machine = 0, native_machine = 0;
  if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
    return 12;
  DWORD before = 0, after = 0;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 13;
  printf("{\"kind\":\"machine\",\"pointer_bytes\":%zu,"
         "\"process_machine\":%u,\"native_machine\":%u}\n",
         sizeof(void *), process_machine, native_machine);
  for (bool extended : {false, true}) {
    for (ULONG view : {0ul, 0x100ul, 0x200ul, 0x300ul}) {
      observe(extended, 0, 0, nullptr, current_version, view);
      observe(extended, 1, 0, nullptr, appmodel, view);
    }
  }
  for (ULONG root_view : {0ul, 0x100ul, 0x200ul}) {
    Key root;
    if (invoke(false, &root.value, root_view, nullptr, current_version) < 0)
      return 14;
    for (bool extended : {false, true}) {
      for (ULONG view : {0ul, 0x100ul, 0x200ul, 0x300ul}) {
        observe(extended, 2, root_view, root.value, L"", view);
        observe(extended, 3, root_view, root.value, L"Run", view);
      }
    }
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 15;
  printf("{\"kind\":\"complete\",\"calls\":%u,\"handles_before\":%lu,"
         "\"handles_after\":%lu}\n", ordinal, before, after);
  return before == after && ordinal == 64 ? 0 : 16;
}
