// Read-only fixed child identity/type/case controls beneath the current session.
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using Open = LONG (NTAPI *)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
using Query = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
using Compare = LONG (NTAPI *)(HANDLE, HANDLE);
using Close = LONG (NTAPI *)(HANDLE);
static unsigned opens = 0, closes = 0;

static std::string utf8(const std::wstring &text) {
    int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                  nullptr, 0, nullptr, nullptr);
    std::string value(size, 0);
    if (size)
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            value.data(), size, nullptr, nullptr);
    return value;
}

static LONG acquire(Open open, HANDLE root, std::wstring &path, ULONG flags,
                    ULONG access, HANDLE *result) {
    UNICODE_STRING name{};
    name.Length = name.MaximumLength = static_cast<USHORT>(path.size() * 2);
    name.Buffer = path.data();
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = root;
    attributes.ObjectName = &name;
    attributes.Attributes = flags;
    LONG status = open(result, access, &attributes);
    if (status == 0 && *result)
        ++opens;
    return status;
}

static std::string text(Query query, HANDLE handle, ULONG information) {
    std::vector<std::uint64_t> storage(512);
    ULONG returned = 0;
    LONG status = query(handle, information, storage.data(), 4096, &returned);
    if (status != 0 || returned > 4096 || returned < sizeof(UNICODE_STRING))
        return "!query-failed";
    UNICODE_STRING name{};
    memcpy(&name, storage.data(), sizeof(name));
    auto start = reinterpret_cast<std::uintptr_t>(storage.data());
    auto pointer = reinterpret_cast<std::uintptr_t>(name.Buffer);
    if (name.Length % 2 || pointer < start || pointer - start > returned
        || name.Length > returned - (pointer - start))
        return "!invalid-buffer";
    return utf8(std::wstring(name.Buffer, name.Length / 2));
}

int main() {
    HMODULE dll = GetModuleHandleW(L"ntdll.dll");
    auto directory = reinterpret_cast<Open>(GetProcAddress(dll, "NtOpenDirectoryObject"));
    auto link = reinterpret_cast<Open>(GetProcAddress(dll, "NtOpenSymbolicLinkObject"));
    auto query = reinterpret_cast<Query>(GetProcAddress(dll, "NtQueryObject"));
    auto compare = reinterpret_cast<Compare>(GetProcAddress(dll, "NtCompareObjects"));
    auto close = reinterpret_cast<Close>(GetProcAddress(dll, "NtClose"));
    if (!directory || !link || !query || !compare || !close)
        return 2;
    DWORD session = MAXDWORD;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session))
        return 3;
    std::wstring parent_name = L"\\Sessions\\" + std::to_wstring(session);
    HANDLE parent = nullptr;
    LONG status = acquire(directory, nullptr, parent_name, 0x40, 0x02000000, &parent);
    if (status != 0 || !parent)
        return 4;
    printf("parent session=%lu name=%s\n", session, utf8(parent_name).c_str());
    const wchar_t *names[] = {L"BaseNamedObjects", L"basenamedobjects", L"Windows", L"windows",
        L"AssistRaxNamespaceMissing20261103"};
    const ULONG flags[] = {0, 0x40, 0x100, 0x140};
    const ULONG access[] = {0, 1, 0x02000000};
    unsigned cases = 0, comparisons = 0;
    for (unsigned kind = 0; kind < 2; ++kind) {
        for (unsigned row = 0; row < sizeof(names) / sizeof(names[0]); ++row) {
            for (ULONG flag : flags) {
                for (ULONG mask : access) {
                    HANDLE handle = nullptr;
                    std::wstring relative = names[row];
                    Open open = kind == 0 ? directory : link;
                    LONG result = acquire(open, parent, relative, flag, mask, &handle);
                    ++cases;
                    printf("open kind=%u row=%u flags=%08lX access=%08lX status=%08lX handle=%u\n",
                        kind, row, flag, mask, static_cast<unsigned long>(result), handle != nullptr);
                    if (result != 0 || !handle)
                        continue;
                    DWORD words[14]{};
                    ULONG returned = 0;
                    LONG basic = query(handle, 0, words, sizeof(words), &returned);
                    std::string canonical = text(query, handle, 1);
                    std::string type = text(query, handle, 2);
                    printf("metadata kind=%u row=%u flags=%08lX access=%08lX basic=%08lX "
                           "returned=%lu granted=%08lX type=%s name=%s\n", kind, row, flag, mask,
                        static_cast<unsigned long>(basic), returned, words[1], type.c_str(), canonical.c_str());
                    if (basic != 0 || returned != sizeof(words) || canonical.empty() || type.empty()
                        || canonical.front() == '!' || type.front() == '!')
                        return 5;
                    std::wstring absolute = parent_name + L"\\" + relative;
                    HANDLE other = nullptr;
                    LONG second = acquire(open, nullptr, absolute, flag, mask, &other);
                    LONG equal = second == 0 && other ? compare(handle, other) : -1;
                    ++comparisons;
                    printf("identity kind=%u row=%u flags=%08lX access=%08lX open=%08lX compare=%08lX\n",
                        kind, row, flag, mask, static_cast<unsigned long>(second), static_cast<unsigned long>(equal));
                    if (second != 0 || !other || equal != 0)
                        return 6;
                    if (close(other) != 0 || close(handle) != 0)
                        return 7;
                    closes += 2;
                }
            }
        }
    }
    if (close(parent) != 0)
        return 8;
    ++closes;
    printf("finished cases=%u comparisons=%u opened=%u closed=%u\n", cases, comparisons, opens, closes);
    return opens == closes ? 0 : 9;
}
