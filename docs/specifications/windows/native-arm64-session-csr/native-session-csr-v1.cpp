#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using Close = LONG(NTAPI *)(HANDLE);
using OpenSection = LONG(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using CreateSection = LONG(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                  PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using Connect = LONG(NTAPI *)(PHANDLE, PUNICODE_STRING, PVOID, PVOID, PSID,
                            PVOID, PULONG, PVOID, PULONG);
using Client = LONG(NTAPI *)(PCWSTR, ULONG, PVOID, ULONG, PBOOLEAN);

static void require(bool condition, const char *operation) {
  if (!condition) {
    printf("failure operation=%s error=%lu\n", operation, GetLastError());
    ExitProcess(21);
  }
}

template <typename T> static T entry(HMODULE module, const char *name) {
  auto result = GetProcAddress(module, name);
  require(result != nullptr, name);
  return reinterpret_cast<T>(result);
}

static void read(uintptr_t address, void *out, SIZE_T size) {
  SIZE_T got = 0;
  require(ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(address),
                            out, size, &got) && got == size, "read-own-memory");
}

static uint64_t word(const unsigned char *bytes, size_t offset) {
  uint64_t result = 0;
  memcpy(&result, bytes + offset, sizeof result);
  return result;
}

static void hex(const char *name, const void *bytes, size_t length) {
  printf("bytes name=%s size=%zu hex=", name, length);
  const auto *data = static_cast<const unsigned char *>(bytes);
  for (size_t i = 0; i < length; ++i) printf("%02X", data[i]);
  puts("");
}

static void regions(const char *name, uintptr_t base, size_t size) {
  size_t cursor = 0;
  unsigned count = 0;
  while (cursor < size) {
    MEMORY_BASIC_INFORMATION info{};
    SIZE_T got = VirtualQuery(reinterpret_cast<void *>(base + cursor), &info, sizeof info);
    require(got == sizeof info && info.BaseAddress == reinterpret_cast<void *>(base + cursor) &&
            info.AllocationBase == reinterpret_cast<void *>(base) &&
            info.RegionSize != 0 && info.RegionSize <= size - cursor &&
            ++count <= 8, "bounded-view-regions");
    printf("region name=%s offset=%zu size=%zu state=%08lX protection=%08lX type=%08lX\n",
           name, cursor, info.RegionSize, info.State, info.Protect, info.Type);
    cursor += info.RegionSize;
  }
  MEMORY_BASIC_INFORMATION next{};
  require(VirtualQuery(reinterpret_cast<void *>(base + size), &next, sizeof next) == sizeof next &&
          next.AllocationBase != reinterpret_cast<void *>(base), "bounded-view-end");
  printf("extent name=%s base=%llX size=%zu regions=%u\n", name,
         static_cast<unsigned long long>(base), size, count);
}

struct ClientView {
  ULONG length;
  HANDLE section;
  ULONG offset;
  SIZE_T size;
  PVOID base;
  PVOID remote;
};
struct ServerView { ULONG length; SIZE_T size; PVOID base; };
static_assert(sizeof(ClientView) == 48 && sizeof(ServerView) == 24);

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  DWORD session = MAXDWORD, before = 0, after = 0;
  require(ProcessIdToSessionId(GetCurrentProcessId(), &session) != 0, "process-session");
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  auto close = entry<Close>(ntdll, "NtClose");
  auto open_section = entry<OpenSection>(ntdll, "NtOpenSection");
  auto create_section = entry<CreateSection>(ntdll, "NtCreateSection");
  auto connect = entry<Connect>(ntdll, "NtSecureConnectPort");
  auto client = entry<Client>(ntdll, "CsrClientConnectToServer");
  auto peb = entry<void *(NTAPI *)()>(ntdll, "RtlGetCurrentPeb")();
  auto csr_pid = entry<uintptr_t(NTAPI *)()>(ntdll, "CsrGetProcessId")();
  unsigned char metadata[0x388]{};
  read(reinterpret_cast<uintptr_t>(peb), metadata, sizeof metadata);
  ULONG peb_session = 0, major = 0, minor = 0;
  USHORT build = 0;
  memcpy(&major, metadata + 0x118, 4);
  memcpy(&minor, metadata + 0x11c, 4);
  memcpy(&build, metadata + 0x120, 2);
  memcpy(&peb_session, metadata + 0x2c0, 4);
  uintptr_t local = word(metadata, 0x88), statics = word(metadata, 0x98),
            server = word(metadata, 0x380);
  printf("profile pointer_bytes=%zu process=%lu session=%lu peb_session=%lu kernel=%lu.%lu.%u csr_pid=%llu local=%llX statics=%llX offset=%llX server=%llX\n",
         sizeof(void *), GetCurrentProcessId(), session, peb_session, major, minor, unsigned(build),
         static_cast<unsigned long long>(csr_pid), static_cast<unsigned long long>(local),
         static_cast<unsigned long long>(statics), static_cast<unsigned long long>(statics - local),
         static_cast<unsigned long long>(server));
  require(session == peb_session && local && statics >= local && csr_pid, "metadata-subject");
  unsigned char prefix[128]{}, alias_prefix[128]{};
  read(local, prefix, sizeof prefix);
  hex("peb-shared-prefix", prefix, sizeof prefix);
  regions("peb-shared", local, 1 << 20);
  std::wstring directory = session == 0 ? L"\\Windows" : L"\\Sessions\\" + std::to_wstring(session) + L"\\Windows";
  std::wstring section_path = directory + L"\\SharedSection";
  UNICODE_STRING section_name{};
  section_name.Length = static_cast<USHORT>(section_path.size() * sizeof(wchar_t));
  section_name.MaximumLength = section_name.Length;
  section_name.Buffer = section_path.data();
  OBJECT_ATTRIBUTES attributes{};
  InitializeObjectAttributes(&attributes, &section_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
  require(GetProcessHandleCount(GetCurrentProcess(), &before) != 0, "handles-before");
  HANDLE selected = nullptr;
  LONG result = open_section(&selected, 0x20004, &attributes);
  printf("selected-section open=%08lX handle=%u\n", ULONG(result), unsigned(selected != nullptr));
  require(result == 0 && selected, "selected-section-open");
  void *alias = MapViewOfFile(selected, FILE_MAP_READ, 0, 0, 0);
  require(alias != nullptr, "map-selected-readonly");
  read(reinterpret_cast<uintptr_t>(alias), alias_prefix, sizeof alias_prefix);
  regions("selected-shared", reinterpret_cast<uintptr_t>(alias), 1 << 20);
  printf("selected-section prefix_equal=%u server_words_equal=%u\n",
         unsigned(memcmp(prefix, alias_prefix, sizeof prefix) == 0),
         unsigned(word(prefix, 40) == server && word(prefix, 48) == server));
  require(UnmapViewOfFile(alias) != 0, "unmap-selected-readonly");
  require(close(selected) == 0, "close-selected-section");

  HANDLE section = nullptr, port = nullptr;
  LARGE_INTEGER maximum{}; maximum.QuadPart = 65536;
  result = create_section(&section, 0xF001F, nullptr, &maximum, PAGE_READWRITE, SEC_COMMIT, nullptr);
  printf("pagefile-section status=%08lX handle=%u maximum=%lld\n",
         ULONG(result), unsigned(section != nullptr), maximum.QuadPart);
  require(result == 0 && section, "create-owned-pagefile");
  std::wstring port_path = directory + L"\\ApiPort";
  UNICODE_STRING port_name{};
  port_name.Length = static_cast<USHORT>(port_path.size() * sizeof(wchar_t));
  port_name.MaximumLength = port_name.Length;
  port_name.Buffer = port_path.data();
  unsigned char qos[12]{0, 0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0};
  unsigned char sid[12]{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0};
  ClientView view{}; view.length = sizeof view; view.section = section; view.size = 65536;
  ServerView remote{}; remote.length = sizeof remote;
  ULONG message = 0, bytes = 48;
  unsigned char information[48]{};
  uint64_t one = 1, tail = 0x123456789ABCDEF0;
  memcpy(information + 32, &one, 8); memcpy(information + 40, &tail, 8);
  hex("qos-before", qos, sizeof qos);
  hex("sid-before", sid, sizeof sid);
  hex("client-before", &view, sizeof view);
  hex("remote-before", &remote, sizeof remote);
  hex("information-before", information, sizeof information);
  result = connect(&port, &port_name, qos, &view, sid, &remote, &message, information, &bytes);
  printf("connect status=%08lX handle=%u maximum_message=%lu information_bytes=%lu\n",
         ULONG(result), unsigned(port != nullptr), message, bytes);
  hex("client-after", &view, sizeof view);
  hex("remote-after", &remote, sizeof remote);
  hex("information-after", information, sizeof information);
  if (port) {
    require(close(section) == 0, "close-client-section");
    section = nullptr;
    require(close(port) == 0, "close-client-port");
    port = nullptr;
  }
  if (section) require(close(section) == 0, "close-unconnected-section");
  require(GetProcessHandleCount(GetCurrentProcess(), &after) != 0, "handles-after");
  printf("owned-handles before=%lu after=%lu\n", before, after);

  unsigned char user[584]{}; BOOLEAN inside = 0xA5;
  result = client(directory.c_str(), 3, user, sizeof user, &inside);
  printf("user-client status=%08lX inside=%u csr_pid=%llu\n",
         ULONG(result), unsigned(inside),
         static_cast<unsigned long long>(entry<uintptr_t(NTAPI *)()>(ntdll, "CsrGetProcessId")()));
  hex("user-information", user, sizeof user);
  if (result == 0) {
    regions("user-handles", word(user, 16), 1 << 21);
    regions("user-shared", word(user, 40), 32768);
  }
  puts("finished");
  return 0;
}
