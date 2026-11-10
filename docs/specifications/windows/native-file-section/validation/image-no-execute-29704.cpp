#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <initializer_list>

using Create = LONG (NTAPI *)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using Query = LONG (NTAPI *)(HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T);
using Map = LONG (NTAPI *)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
using Unmap = LONG (NTAPI *)(HANDLE, PVOID);
using Protect = LONG (NTAPI *)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
using QueryMemory = LONG (NTAPI *)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
struct alignas(8) Extended { unsigned long long type, value; };
using MapEx = LONG (NTAPI *)(HANDLE, HANDLE, PVOID *, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, Extended *, ULONG);
struct ImageInfo { PVOID base; SIZE_T size; ULONG flags; };
struct Extension { ULONG type; ULONG flags; SIZE_T rva; SIZE_T size; };
struct Basic { PVOID base; ULONG flags; LARGE_INTEGER size; };
static_assert(sizeof(Basic) == (sizeof(void*) == 8 ? 24 : 16));

template <typename T> T nt(HMODULE ntdll, const char *name) {
    return reinterpret_cast<T>(GetProcAddress(ntdll, name));
}

int main() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = nt<Create>(ntdll, "NtCreateSection");
    auto query = nt<Query>(ntdll, "NtQuerySection");
    auto map = nt<Map>(ntdll, "NtMapViewOfSection");
    auto unmap = nt<Unmap>(ntdll, "NtUnmapViewOfSection");
    auto protect = nt<Protect>(ntdll, "NtProtectVirtualMemory");
    auto memory = nt<QueryMemory>(ntdll, "NtQueryVirtualMemory");
    auto map_ex = nt<MapEx>(ntdll, "NtMapViewOfSectionEx");
    if (!create || !query || !map || !unmap || !protect || !memory || !map_ex) return 2;
    HANDLE process = GetCurrentProcess();
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    constexpr const wchar_t *paths[] = {L"pe-arm64.bin", L"pe-x64.bin", L"pe-x86.bin", L"native-version.bin"};
    for (unsigned i = 0; i < 4; ++i) {
        HANDLE file = CreateFileW(paths[i], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return 3;
        for (ULONG mode : {0x11000000UL, 0x01000000UL}) {
            HANDLE section = nullptr;
            LONG status = create(&section, 0xf, nullptr, nullptr, PAGE_READONLY, mode, file);
            Basic basic{};
            SIZE_T got = 0;
            LONG basic_status = section ? query(section, 0, &basic, sizeof(basic), &got) : -1;
            std::printf("CREATE file=%u mode=%08lx status=%08lx basic=%08lx attrs=%08lx size=%lld length=%llu\n",
                i, mode, ULONG(status), ULONG(basic_status), basic.flags, basic.size.QuadPart, static_cast<unsigned long long>(got));
            if (status < 0 || !section || basic_status < 0) return 4;
            unsigned long long preferred = 0;
            for (ULONG request : {2UL, 4UL, 0x20UL}) {
                SIZE_T bytes = 0;
                PVOID address = nullptr;
                LONG mapped = map(section, process, &address, 0, 0, nullptr, &bytes, 2, 0, request);
                std::printf("MAP file=%u mode=%08lx request=%02lx status=%08lx size=%llu\n", i, mode, request, ULONG(mapped), static_cast<unsigned long long>(bytes));
                if (mapped < 0) continue;
                if (!address || !bytes) return 5;
                if (request == PAGE_READONLY) {
                    auto base = reinterpret_cast<std::uintptr_t>(address);
                    ImageInfo image{};
                    SIZE_T image_length = 0;
                    auto queried = memory(process, address, 6, &image, sizeof(image), &image_length);
                    IMAGE_DOS_HEADER dos{};
                    IMAGE_FILE_HEADER file_header{};
                    SIZE_T copied = 0;
                    if (!ReadProcessMemory(process, address, &dos, sizeof(dos), &copied) || copied != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 64 ||
                        !ReadProcessMemory(process, reinterpret_cast<PVOID>(base + static_cast<ULONG>(dos.e_lfanew) + 4), &file_header, sizeof(file_header), &copied) || copied != sizeof(file_header)) return 11;
                    auto optional = base + static_cast<ULONG>(dos.e_lfanew) + 4 + sizeof(file_header);
                    WORD magic = 0;
                    if (!ReadProcessMemory(process, reinterpret_cast<PVOID>(optional), &magic, sizeof(magic), &copied)) return 13;
                    SIZE_T width = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 8 : 4;
                    preferred = 0;
                    if (!ReadProcessMemory(process, reinterpret_cast<PVOID>(optional + (width == 8 ? 24 : 28)), &preferred, width, &copied) || copied != width) return 14;
                    std::printf("IMAGE status=%08lx flags=%08lx machine=%04x size=%llu\n", ULONG(queried), image.flags, unsigned(file_header.Machine), static_cast<unsigned long long>(image.size));
                    for (ULONG type : {0UL, 1UL}) {
                        Extension extension{type, 0, 0, 0};
                        SIZE_T returned = 0;
                        auto status_ext = memory(process,address,14,&extension,sizeof(extension),&returned);
                        std::printf("EXTENSION type=%lu status=%08lx flags=%08lx rva=%llu size=%llu\n", type, ULONG(status_ext), extension.flags, static_cast<unsigned long long>(extension.rva), static_cast<unsigned long long>(extension.size));
                    }
                    for (SIZE_T offset = 0; offset < bytes;) {
                        MEMORY_BASIC_INFORMATION info{};
                        if (VirtualQuery(reinterpret_cast<PVOID>(base + offset), &info, sizeof(info)) != sizeof(info) ||
                            info.AllocationBase != address || !info.RegionSize) return 6;
                        std::printf("RUN offset=%llu bytes=%llu state=%08lx protection=%08lx allocation=%08lx type=%08lx\n",
                            static_cast<unsigned long long>(offset), static_cast<unsigned long long>(info.RegionSize),
                            info.State, info.Protect, info.AllocationProtect, info.Type);
                        offset += info.RegionSize;
                    }
                    if (mode == 0x11000000 && bytes > system.dwPageSize) {
                        for (ULONG requested : {0x20UL, 4UL, 8UL, 1UL, 2UL}) {
                            PVOID page = reinterpret_cast<PVOID>(base + system.dwPageSize);
                            SIZE_T span = system.dwPageSize;
                            ULONG old = 0;
                            LONG result = protect(process, &page, &span, requested, &old);
                            std::printf("PROTECT request=%02lx status=%08lx old=%08lx\n", requested, ULONG(result), old);
                            if (result >= 0) {
                                ULONG ignored = 0;
                                if (protect(process, &page, &span, old, &ignored) < 0) return 7;
                            }
                        }
                    }
                }
                if (unmap(process, address) < 0) return 8;
            }
            if (mode == 0x11000000) {
                for (ULONG flag : {0UL, 0x00800000UL, 0x20000000UL, 0x00100000UL}) {
                    for (bool fixed : {false, true}) {
                        if (fixed && (preferred == 0 || preferred > UINTPTR_MAX)) continue;
                        PVOID view = fixed ? reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(preferred)) : nullptr;
                        SIZE_T span = 0;
                        auto mapped = map(section, process, &view, 0, 0, nullptr, &span, 2, flag, PAGE_READONLY);
                        unsigned long long checksum = 14695981039346656037ULL;
                        if (mapped >= 0) {
                            if (!view || span > 16U*1024*1024) return 15;
                            BYTE chunk[4096];
                            for (SIZE_T offset = 0; offset < span; offset += sizeof(chunk)) {
                                SIZE_T read = 0;
                                SIZE_T amount = span - offset < sizeof(chunk) ? span - offset : sizeof(chunk);
                                if (!ReadProcessMemory(process, static_cast<BYTE*>(view)+offset, chunk, amount, &read) || read != amount) return 16;
                                for (SIZE_T n=0; n<read; ++n) checksum = (checksum ^ chunk[n]) * 1099511628211ULL;
                            }
                        }
                        std::printf("PLACEMENT file=%u flag=%08lx fixed=%u preferred=%llx returned=%llx status=%08lx size=%llu fnv=%016llx\n",
                            i, flag, unsigned(fixed), preferred, static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(view)), ULONG(mapped), static_cast<unsigned long long>(span), checksum);
                        if (mapped >= 0 && unmap(process, view) < 0) return 17;
                    }
                }
            }
            if (i == 3) {
                Extended machine{6, 0x8664};
                PVOID view = nullptr;
                SIZE_T length = 0;
                auto status_ex = map_ex(section, process, &view, nullptr, &length, 0, PAGE_READONLY, &machine, 1);
                std::printf("MAPEX mode=%08lx status=%08lx size=%llu\n", mode, ULONG(status_ex), static_cast<unsigned long long>(length));
                if (status_ex >= 0 && unmap(process, view) < 0) return 12;
            }
            if (!CloseHandle(section)) return 9;
        }
        if (!CloseHandle(file)) return 10;
    }
    std::puts("DONE files=4 views-released=1");
    return 0;
}
