#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <initializer_list>

using Query = LONG (NTAPI *)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
static Query query;
static ULONG page;
static unsigned ordinal;

struct Region {
    unsigned char *p;
    Region() : p(static_cast<unsigned char *>(VirtualAlloc(nullptr, 8 * page,
                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
        if (!p) { std::printf("allocation-failed error=%lu\n", GetLastError()); ExitProcess(2); }
        std::memset(p, 0xA5, 8 * page);
    }
    ~Region() { if (!VirtualFree(p, 0, MEM_RELEASE)) ExitProcess(3); }
    void protect(unsigned offset, unsigned bytes, DWORD protection) {
        DWORD previous;
        if (!VirtualProtect(p + offset, bytes, protection, &previous)) ExitProcess(4);
    }
};

static LONG invoke(ULONG cls, void *input, ULONG in_bytes, void *output,
                   ULONG out_bytes, ULONG *returned, ULONG *exception) {
    LONG status = static_cast<LONG>(0xDEADBEEF);
    *exception = 0;
    __try { status = query(cls, input, in_bytes, output, out_bytes, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) { *exception = GetExceptionCode(); }
    return status;
}

static BOOL safe_read(const void *p, void *data, SIZE_T bytes, SIZE_T *read) {
    MEMORY_BASIC_INFORMATION info;
    *read = 0;
    if (!VirtualQuery(p, &info, sizeof info) || info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return FALSE;
    SIZE_T available = static_cast<const unsigned char *>(info.BaseAddress) +
                       info.RegionSize - static_cast<const unsigned char *>(p);
    return ReadProcessMemory(GetCurrentProcess(), p, data, std::min(bytes, available), read);
}

static void hex(const char *name, const void *p, unsigned bytes) {
    unsigned char data[32768];
    SIZE_T read = 0;
    BOOL ok = safe_read(p, data, std::min<unsigned>(bytes, sizeof data), &read);
    std::printf(" %s-read=%u %s-captured-bytes=%zu %s=", name, ok, name, read, name);
    for (SIZE_T i = 0; i < read; ++i) std::printf("%02X", data[i]);
}

static void run(const char *label, ULONG relationship, ULONG in_bytes,
                ULONG out_bytes, unsigned mode = 0, unsigned offset = 0,
                ULONG cls = 107) {
    Region input, output, result;
    unsigned char *ip = input.p + 128, *op = output.p + 128;
    ULONG *rp = reinterpret_cast<ULONG *>(result.p + 128);
    std::memcpy(ip, &relationship, 4);
    switch (mode) {
    case 1: ip = nullptr; break;
    case 2: ip = reinterpret_cast<unsigned char *>(1); break;
    case 3: op = nullptr; break;
    case 4: op = reinterpret_cast<unsigned char *>(1); break;
    case 5: rp = nullptr; break;
    case 6: rp = reinterpret_cast<ULONG *>(1); break;
    case 7: ip += offset; std::memcpy(ip, &relationship, 4); break;
    case 8: op += offset; break;
    case 9: rp = reinterpret_cast<ULONG *>(result.p + 128 + offset); break;
    case 10: input.protect(0, page, PAGE_NOACCESS); break;
    case 11: output.protect(0, page, PAGE_READONLY); break;
    case 12: result.protect(0, page, PAGE_READONLY); break;
    case 13: input.protect(0, page, PAGE_READWRITE | PAGE_GUARD); break;
    case 14: output.protect(0, page, PAGE_READWRITE | PAGE_GUARD); break;
    case 15: result.protect(0, page, PAGE_READWRITE | PAGE_GUARD); break;
    case 16: input.protect(page, page, PAGE_NOACCESS); ip = input.p + page - offset;
             std::memcpy(ip, &relationship, std::min<unsigned>(4, offset)); break;
    case 17: output.protect(page, page, PAGE_NOACCESS); op = output.p + page - offset; break;
    case 18: rp = reinterpret_cast<ULONG *>(op); break;
    case 19: op = ip; break;
    case 20: rp = reinterpret_cast<ULONG *>(ip); break;
    case 21: op = nullptr; rp = reinterpret_cast<ULONG *>(1); break;
    case 22: ip = nullptr; op = nullptr; rp = reinterpret_cast<ULONG *>(1); break;
    case 23: ip += 1; std::memcpy(ip, &relationship, 4); op = nullptr; break;
    case 24: input.protect(0, page, PAGE_NOACCESS); op = nullptr; break;
    case 25: input.protect(0, page, PAGE_NOACCESS); rp = reinterpret_cast<ULONG *>(1); break;
    case 26: rp = reinterpret_cast<ULONG *>(op + offset); break;
    case 28: output.protect(page, page, PAGE_READONLY); op = output.p + page - offset; break;
    case 29: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(offset)); break;
    case 30: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(-4)); break;
    case 31: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0x7FFFFFFC)); break;
    case 32: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0xFFFFFFFC)); break;
    case 33: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0x7FFFFFFEFFFCull)); break;
    case 34: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0x7FFFFFFFFFFCull)); break;
    case 35: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0x7FFFFFFF0000ull)); break;
    case 36: ip = reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(0x800000000000ull)); break;
    case 27: result.protect(page, page, PAGE_NOACCESS);
             rp = reinterpret_cast<ULONG *>(result.p + page - offset); break;
    }
    unsigned repeats = mode >= 13 && mode <= 15 ? 2 : 1;
    for (unsigned repeat = 0; repeat < repeats; ++repeat) {
        ULONG exception = 0;
        LONG status = invoke(cls, ip, in_bytes, op, out_bytes, rp, &exception);
        ULONG length = 0;
        SIZE_T got = 0;
        BOOL length_ok = rp && safe_read(rp, &length, 4, &got);
        std::printf("case=%u label=%s width=%zu class=%lu relationship=%lu input-bytes=%lu output-bytes=%lu mode=%u offset=%u repeat=%u status=%08lX exception=%08lX returned-read=%u returned-captured-bytes=%zu returned=%08lX",
                    ordinal++, label, sizeof(void *), cls, relationship, in_bytes, out_bytes,
                    mode, offset, repeat, static_cast<ULONG>(status), exception, length_ok, got, length);
        unsigned capture = status >= 0 && length_ok && length <= 32768
                           ? std::max<unsigned>(length, 96) : 96;
        hex("output", op, capture);
        hex("result-backing", result.p + 128, 16);
        std::puts("");
    }
}

static void range_guards() {
    if constexpr (sizeof(void *) == 8) {
        constexpr uintptr_t limit = 0x7FFFFFFF0000ull;
        auto *span = static_cast<unsigned char *>(VirtualAlloc(
            reinterpret_cast<void *>(limit - 65536), 65536,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!span) { std::printf("range-guard-allocation-failed error=%lu\n", GetLastError()); ExitProcess(6); }
        for (unsigned role = 0; role < 3; ++role) {
            Region input, output, result;
            ULONG relation = 6;
            std::memcpy(input.p, &relation, 4);
            std::memcpy(span + 65532, &relation, 4);
            DWORD old;
            if (!VirtualProtect(span + 65536 - page, page, PAGE_READWRITE | PAGE_GUARD, &old)) ExitProcess(7);
            void *ip = role == 0 ? span + 65532 : input.p;
            void *op = role == 1 ? span + 65532 : output.p;
            auto *rp = reinterpret_cast<ULONG *>(role == 2 ? span + 65534 : result.p);
            ULONG exception = 0;
            LONG status = invoke(107, ip, role == 0 ? 8 : 4, op,
                                role == 1 ? 8 : 96, rp, &exception);
            MEMORY_BASIC_INFORMATION info;
            if (!VirtualQuery(span + 65536 - page, &info, sizeof info)) ExitProcess(8);
            std::printf("range-guard role=%u width=%zu status=%08lX exception=%08lX guard=%lu\n",
                role, sizeof(void *), static_cast<ULONG>(status), exception,
                info.Protect & PAGE_GUARD);
            if (!VirtualProtect(span + 65536 - page, page, PAGE_READWRITE, &old)) ExitProcess(9);
        }
        if (!VirtualFree(span, 0, MEM_RELEASE)) ExitProcess(10);
    }
}

int main() {
    SYSTEM_INFO info;
    GetSystemInfo(&info); page = info.dwPageSize;
    query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                 "NtQuerySystemInformationEx"));
    if (!query) return 5;
    std::printf("profile width=%zu page=%lu processor-count=%lu processor-mask=%llX\n",
                sizeof(void *), page, info.dwNumberOfProcessors,
                static_cast<unsigned long long>(info.dwActiveProcessorMask));
    std::printf("layout sdk-size=%zu group-size=%zu group-info-size=%zu group-offset=%zu info-offset=%zu mask-offset=%zu\n",
                sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX), sizeof(GROUP_RELATIONSHIP),
                sizeof(PROCESSOR_GROUP_INFO), offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Group),
                offsetof(GROUP_RELATIONSHIP, GroupInfo), offsetof(PROCESSOR_GROUP_INFO, ActiveProcessorMask));
    for (ULONG relation : {0ul,1ul,2ul,3ul,4ul,5ul,6ul,7ul,8ul,9ul,0xFFFFul,0xFFFFFFFFul})
        run("relationship", relation, 4, 16384);
    for (ULONG in_bytes : {0ul,1ul,2ul,3ul,4ul,5ul,8ul,16ul})
        run("input-length", 6, in_bytes, 16384);
    for (ULONG out_bytes : {0ul,1ul,4ul,31ul,32ul,43ul,44ul,45ul,47ul,48ul,49ul,64ul,96ul,16384ul})
        run("output-length", 6, 4, out_bytes);
    for (unsigned mode : {1u,2u,3u,4u,5u,6u,10u,11u,12u,13u,14u,15u,18u,19u,20u,21u,22u}) {
        run("fault-full", 6, 4, 16384, mode);
        run("fault-zero-output", 6, 4, 0, mode);
        run("fault-short-input", 6, 3, 16384, mode);
    }
    for (unsigned offset : {1u,2u,3u,4u,7u}) {
        for (unsigned mode : {7u,8u,9u}) run("alignment", 6, 4, 16384, mode, offset);
        run("input-cross-page", 6, 4, 16384, 16, offset);
        run("output-cross-page", 6, 4, 16384, 17, offset);
    }
    for (ULONG in_bytes : {0ul,1ul,3ul,4ul,8ul,16ul}) {
        for (unsigned mode : {23u,24u,25u}) run("fault-pair", 6, in_bytes, 16384, mode);
        run("input-extra-span", 6, in_bytes, 16384, 16, 4);
    }
    for (unsigned offset : {16u,32u,44u,48u,64u,96u})
        run("output-extra-span", 6, 4, 16384, 17, offset);
    for (unsigned offset : {4u,8u,12u,28u,30u,32u,36u,40u,44u})
        run("returned-output-alias", 6, 4, 16384, 26, offset);
    for (unsigned offset : {1u,2u,3u,4u})
        run("returned-cross-page", 6, 4, 16384, 27, offset);
    for (unsigned prefix = 1; prefix <= 64; ++prefix) {
        run("output-field-boundary", 6, 4, 16384, 17, prefix);
        run("output-field-readonly", 6, 4, 16384, 28, prefix);
    }
    for (ULONG length : {0ul,1ul,3ul,4ul,8ul,0xFFFFFFFFul}) {
        for (unsigned mode : {29u,30u,31u,32u,33u,34u,35u,36u}) run("input-address-range", 6, length, 0, mode, 4);
        run("input-huge-length", 6, length, 16384);
    }
    for (ULONG cls : {0ul,50ul,62ul,250ul,0xFFFFFFFFul}) run("class", 6, 4, 16384, 0, 0, cls);
    range_guards();
    std::printf("complete cases=%u\n", ordinal);
    return 0;
}
