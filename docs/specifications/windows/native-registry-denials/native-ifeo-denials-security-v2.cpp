// Read-only fixed-name NT registry and parent-enumeration control.
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using OpenKey = LONG (NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, ULONG);
using QueryObject = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using EnumerateKey = LONG (NTAPI *)(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);
using Close = LONG (NTAPI *)(HANDLE);

static unsigned opened = 0, closed = 0, open_calls = 0, enum_calls = 0;

static std::string utf8(const std::wstring &text) {
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(bytes, 0);
    if (bytes != 0)
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
            result.data(), bytes, nullptr, nullptr);
    return result;
}

static LONG open_key(OpenKey open, HANDLE root, const std::wstring &path,
                     ACCESS_MASK access, HANDLE *out) {
    if (path.size() > 32767)
        return static_cast<LONG>(0xC000000Du);
    UNICODE_STRING name{};
    name.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    name.Buffer = const_cast<wchar_t *>(path.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = root;
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40;
    ++open_calls;
    const LONG status = open(out, access, &attributes, 0);
    if (status == 0 && *out != nullptr)
        ++opened;
    return status;
}

static bool release(Close close, HANDLE handle) {
    if (close(handle) != 0)
        return false;
    ++closed;
    return true;
}

int main() {
    static_assert(sizeof(OBJECT_ATTRIBUTES) == 48);
    const HMODULE library = GetModuleHandleW(L"ntdll.dll");
    const auto open = reinterpret_cast<OpenKey>(GetProcAddress(library, "NtOpenKeyEx"));
    const auto query = reinterpret_cast<QueryObject>(GetProcAddress(library, "NtQueryObject"));
    const auto enumerate = reinterpret_cast<EnumerateKey>(GetProcAddress(library, "NtEnumerateKey"));
    const auto close = reinterpret_cast<Close>(GetProcAddress(library, "NtClose"));
    if (!open || !query || !enumerate || !close)
        return 2;
    const std::wstring parent_path =
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    const wchar_t *children[] = {
        L"DefenderAgentScan.exe",
        L"cmd.exe",
        L"DefenderAgentScan.exe\\rax-missing-child-20261103",
        L"cmd.exe\\rax-missing-child-20261103",
        L"defenderagentscan.EXE\\",
        L"DefenderAgentScan.exe\\\\rax-missing-child-20261103",
    };
    const DWORD masks[] = {0x01000000, 0x01000001, 0x01000008, 0x01000009, 0x01020000, 0x01020019, 0x03000000, 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0xFFFFFFFF, 0x04000000};
    HANDLE parent = nullptr;
    const LONG parent_status = open_key(open, nullptr, parent_path, 9, &parent);
    printf("parent status=%08lX opened=%u\n", static_cast<unsigned long>(parent_status),
           parent != nullptr);
    if (parent_status != 0 || !parent)
        return 3;
    for (unsigned route = 0; route < 2; ++route) {
        for (unsigned row = 0; row < sizeof(children) / sizeof(children[0]); ++row) {
            const std::wstring path = route == 0 ? parent_path + L"\\" + children[row]
                                                 : std::wstring(children[row]);
            for (const DWORD access : masks) {
                HANDLE handle = nullptr;
                const LONG status = open_key(open, route == 0 ? nullptr : parent,
                                             path, access, &handle);
                DWORD words[14]{};
                ULONG returned = 0;
                const LONG query_status = status == 0 && handle
                    ? query(handle, 0, words, sizeof(words), &returned) : -1;
                printf("open route=%u row=%u access=%08lX status=%08lX handle=%u "
                       "query=%08lX returned=%lu granted=%08lX path=%s\n",
                       route, row, access, static_cast<unsigned long>(status), handle != nullptr,
                       static_cast<unsigned long>(query_status), returned, words[1],
                       utf8(path).c_str());
                if (handle && !release(close, handle))
                    return 4;
            }
        }
    }
    DWORD protected_index = MAXDWORD;
    for (DWORD index = 0; index < 1024; ++index) {
        wchar_t name[256]{};
        DWORD units = 256;
        FILETIME time{};
        const LSTATUS status = RegEnumKeyExW(reinterpret_cast<HKEY>(parent), index,
            name, &units, nullptr, nullptr, nullptr, &time);
        if (status == ERROR_NO_MORE_ITEMS)
            break;
        if (status != 0 || units >= 256)
            return 5;
        if (_wcsicmp(name, L"DefenderAgentScan.exe") == 0) {
            protected_index = index;
            printf("child index=%lu name=%s last_write=%08lX%08lX\n", index,
                   utf8(std::wstring(name, units)).c_str(), time.dwHighDateTime,
                   time.dwLowDateTime);
        }
    }
    if (protected_index == MAXDWORD)
        return 6;
    const ULONG lengths[] = {0, 15, 16, 55, 56, 57, 63, 64, 65, 128, 4096};
    for (ULONG information = 0; information < 3; ++information) {
        for (const ULONG length : lengths) {
            for (const unsigned poison : {0xA5u, 0x5Au}) {
                std::vector<std::uint64_t> storage((length + 7) / 8 + 1);
                memset(storage.data(), poison, storage.size() * sizeof(std::uint64_t));
                ULONG returned = poison * 0x01010101u;
                ++enum_calls;
                const LONG status = enumerate(parent, protected_index, information,
                    length == 0 ? nullptr : storage.data(), length, &returned);
                printf("enum class=%lu length=%lu poison=%02X status=%08lX "
                       "returned=%lu bytes=", information, length, poison,
                       static_cast<unsigned long>(status), returned);
                const auto *bytes = reinterpret_cast<const unsigned char *>(storage.data());
                for (ULONG index = 0; index < length; ++index)
                    printf("%02X", bytes[index]);
                puts("");
                if (bytes[length] != poison)
                    return 7;
            }
        }
    }
    if (!release(close, parent))
        return 8;
    printf("finished open_calls=%u enum_calls=%u opened=%u closed=%u\n",
           open_calls, enum_calls, opened, closed);
    return opened == closed ? 0 : 9;
}
