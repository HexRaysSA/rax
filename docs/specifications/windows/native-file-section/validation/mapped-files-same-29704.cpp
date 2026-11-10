#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>

using Compare = LONG (NTAPI *)(PVOID, PVOID);
struct View {
    PVOID address = nullptr;
    bool virtual_memory = false;
    bool close() const {
        return virtual_memory ? VirtualFree(address, 0, MEM_RELEASE) != 0 : UnmapViewOfFile(address) != 0;
    }
};

View map_file(const wchar_t *path, DWORD protection) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    HANDLE section = CreateFileMappingW(file, nullptr, protection, 0, 0, nullptr);
    CloseHandle(file);
    if (!section) return {};
    PVOID address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(section);
    return {address};
}

View pagefile() {
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 8192, nullptr);
    if (!section) return {};
    PVOID address = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(section);
    return {address};
}

int main() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto same = reinterpret_cast<Compare>(GetProcAddress(ntdll, "NtAreMappedFilesTheSame"));
    if (!same) return 2;
    wchar_t native[MAX_PATH];
    DWORD length = GetModuleFileNameW(ntdll, native, MAX_PATH);
    if (!length || length == MAX_PATH) return 3;
    if (!CopyFileW(L"pe-x64.bin", L"distinct.bin", TRUE) || !CreateHardLinkW(L"alias.bin", L"pe-x64.bin", nullptr)) return 4;
    View owned[] = {
        map_file(L"pe-x64.bin", PAGE_READONLY | SEC_IMAGE),
        map_file(L"pe-x64.bin", PAGE_READONLY | SEC_IMAGE_NO_EXECUTE),
        map_file(L"pe-x64.bin", PAGE_READONLY),
        map_file(L"pe-x64.bin", PAGE_READONLY),
        map_file(L"alias.bin", PAGE_READONLY),
        map_file(L"distinct.bin", PAGE_READONLY),
        map_file(L"distinct.bin", PAGE_READONLY | SEC_IMAGE_NO_EXECUTE),
        pagefile(), pagefile(),
        {VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), true},
        {VirtualAlloc(nullptr, 8192, MEM_RESERVE, PAGE_NOACCESS), true},
        map_file(native, PAGE_READONLY),
    };
    constexpr const char *names[] = {"image", "inspection", "data", "data-peer", "hard-link", "copy-data", "copy-image",
                                      "pagefile", "pagefile-peer", "private", "reserved", "ntdll-file", "loaded-ntdll", "null", "one"};
    PVOID addresses[15]{};
    for (unsigned i=0; i<12; ++i) {
        if (!owned[i].address) {std::printf("SETUP failed=%u win32=%lu\n",i,GetLastError());return 5;}
        addresses[i]=owned[i].address;
    }
    addresses[12]=ntdll;
    addresses[14]=reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(1));
    for (unsigned a=0; a<15; ++a) for (unsigned b=0; b<15; ++b) {
        LONG status = same(addresses[a], addresses[b]);
        std::printf("PAIR first=%s second=%s status=%08lx\n", names[a],names[b],ULONG(status));
        if (a<13 && b<13) {
            status = same(static_cast<BYTE*>(addresses[a])+37,static_cast<BYTE*>(addresses[b])+97);
            std::printf("INTERIOR first=%s second=%s status=%08lx\n",names[a],names[b],ULONG(status));
        }
    }
    for (const auto &view:owned) if (!view.close()) return 6;
    if (!DeleteFileW(L"alias.bin") || !DeleteFileW(L"distinct.bin")) return 7;
    std::puts("DONE matrix=394 owned-views-released=12");
    return 0;
}
