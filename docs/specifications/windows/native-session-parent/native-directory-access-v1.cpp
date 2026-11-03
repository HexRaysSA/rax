// Fixed, read-only installed NT directory authorization control.
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using OpenDirectory = LONG (NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using QueryObject = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using QueryDirectory = LONG (NTAPI *)(HANDLE, void *, ULONG, BOOLEAN, BOOLEAN, ULONG *, ULONG *);
using Close = LONG (NTAPI *)(HANDLE);

struct DirectoryEntry { UNICODE_STRING name; UNICODE_STRING kind; };

static std::string utf8(const std::wstring &text) {
    int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                 nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    if (size)
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            result.data(), size, nullptr, nullptr);
    return result;
}

int main() {
    static_assert(sizeof(OBJECT_ATTRIBUTES) == 48);
    static_assert(sizeof(DirectoryEntry) == 32);
    HMODULE dll = GetModuleHandleW(L"ntdll.dll");
    auto open = reinterpret_cast<OpenDirectory>(GetProcAddress(dll, "NtOpenDirectoryObject"));
    auto basic = reinterpret_cast<QueryObject>(GetProcAddress(dll, "NtQueryObject"));
    auto enumerate = reinterpret_cast<QueryDirectory>(GetProcAddress(dll, "NtQueryDirectoryObject"));
    auto close = reinterpret_cast<Close>(GetProcAddress(dll, "NtClose"));
    if (!open || !basic || !enumerate || !close)
        return 2;
    DWORD session = MAXDWORD;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session))
        return 3;
    std::vector<std::wstring> paths = {L"\\", L"\\KnownDlls", L"\\KnownDlls32",
        L"\\KnownDllsChpe32", L"\\Windows", L"\\BaseNamedObjects", L"\\Sessions",
        L"\\Sessions\\" + std::to_wstring(session)};
    if (session != 0)
        paths.push_back(L"\\Sessions\\" + std::to_wstring(session) + L"\\BaseNamedObjects");
    paths.push_back(L"\\Sessions\\" + std::to_wstring(session) + L"\\Windows");
    const DWORD masks[] = {0, 1, 2, 3, 0x00020000, 0x02000000, 0x01000000, 0x03000000};
    unsigned opened = 0, closed = 0, queries = 0;
    printf("session=%lu paths=%zu masks=%zu\n", session, paths.size(), sizeof(masks) / sizeof(masks[0]));
    for (unsigned index = 0; index < paths.size(); ++index) {
        std::wstring path = paths[index];
        UNICODE_STRING name{};
        name.Length = name.MaximumLength = static_cast<USHORT>(path.size() * 2);
        name.Buffer = path.data();
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.ObjectName = &name;
        attributes.Attributes = 0x40;
        for (DWORD mask : masks) {
            HANDLE handle = nullptr;
            LONG status = open(&handle, mask, &attributes);
            printf("open path=%u access=%08lX status=%08lX handle=%u name=%s\n",
                index, mask, static_cast<unsigned long>(status), handle != nullptr,
                utf8(path).c_str());
            if (status != 0 || !handle)
                continue;
            ++opened;
            DWORD words[14]{};
            ULONG returned = 0;
            LONG information = basic(handle, 0, words, sizeof(words), &returned);
            printf("basic path=%u access=%08lX status=%08lX returned=%lu granted=%08lX\n",
                index, mask, static_cast<unsigned long>(information), returned, words[1]);
            if (information != 0 || returned != sizeof(words))
                return 4;
            for (unsigned poison : {0xA5u, 0x5Au}) {
                std::vector<std::uint64_t> buffer(16385);
                memset(buffer.data(), poison, buffer.size() * sizeof(std::uint64_t));
                ULONG context = 0, count = 0xFEE1DEAD;
                LONG result = enumerate(handle, buffer.data(), 131072, TRUE, TRUE, &context, &count);
                ++queries;
                auto bytes = reinterpret_cast<const unsigned char *>(buffer.data());
                bool guard = true;
                for (unsigned offset = 131072; offset < buffer.size() * 8; ++offset)
                    guard = guard && bytes[offset] == poison;
                unsigned name_units = 0, kind_units = 0;
                if (result == 0) {
                    DirectoryEntry entry{};
                    memcpy(&entry, buffer.data(), sizeof(entry));
                    const auto inside = [&](const UNICODE_STRING &value) {
                        auto start = reinterpret_cast<std::uintptr_t>(buffer.data());
                        auto pointer = reinterpret_cast<std::uintptr_t>(value.Buffer);
                        return value.Length % 2 == 0 && pointer >= start && pointer - start <= 131072
                            && value.Length <= 131072 - (pointer - start);
                    };
                    if (count < sizeof(entry) || count > 131072 || !inside(entry.name) || !inside(entry.kind))
                        return 5;
                    name_units = entry.name.Length / 2;
                    kind_units = entry.kind.Length / 2;
                }
                printf("enum path=%u access=%08lX poison=%02X status=%08lX returned=%lu "
                       "context=%lu name_units=%u kind_units=%u guard=%u\n", index, mask,
                    poison, static_cast<unsigned long>(result), count, context, name_units, kind_units, guard);
                if (!guard)
                    return 6;
            }
            if (close(handle) != 0)
                return 7;
            ++closed;
        }
    }
    printf("finished opened=%u closed=%u enum_calls=%u\n", opened, closed, queries);
    return opened == closed ? 0 : 8;
}
