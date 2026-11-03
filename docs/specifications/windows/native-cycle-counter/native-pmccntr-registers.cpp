// Derivative of the owned CurrentEL register-destination control.
// Reads only PMCCNTR_EL0 and the existing privileged negative controls.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <windows.h>

static uint32_t mov(unsigned dst, unsigned src) {
    return 0xAA0003E0u | (src << 16) | dst;
}

int main() {
    const uint64_t teb = reinterpret_cast<uint64_t>(NtCurrentTeb());
    unsigned allocations = 0, releases = 0, calls = 0, failures = 0;
    for (unsigned row = 0; row < 36; ++row) {
        uint32_t code[5] = {};
        unsigned count = 0;
        const unsigned rt = row < 32 ? row : 0;
        const uint32_t controls[] = {0xD5381000u, 0xD5382000u, 0xD5384200u,
                                     0xD5384100u};
        const uint32_t mrs = row < 32 ? 0xD53B9D00u | rt : controls[row - 32];
        if (rt > 0 && rt < 31) {
            const unsigned scratch = rt == 17 ? 16 : 17;
            code[count++] = mov(scratch, rt);
            code[count++] = mrs;
            code[count++] = mov(0, rt);
            code[count++] = mov(rt, scratch);
        } else {
            code[count++] = mrs;
            if (rt == 31)
                code[count++] = mov(0, 31);
        }
        code[count++] = 0xD65F03C0u;
        auto *page = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT,
                                 PAGE_READWRITE);
        if (!page)
            return 2;
        ++allocations;
        memcpy(page, code, count * sizeof(uint32_t));
        DWORD old = 0;
        if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old) ||
            !FlushInstructionCache(GetCurrentProcess(), page,
                                   count * sizeof(uint32_t)))
            return 3;
        unsigned long status = 0;
        uint64_t value = UINT64_MAX;
        ++calls;
        __try {
            value = reinterpret_cast<uint64_t (*)()>(page)();
        } __except (status = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        }
        const bool stable = memcmp(page, code, count * sizeof(uint32_t)) == 0;
        const bool teb_stable = reinterpret_cast<uint64_t>(NtCurrentTeb()) == teb;
        const bool ok = stable && teb_stable &&
            (row >= 32 ? status == 0xC000001Dul :
             status == 0 && (rt == 31 ? value == 0 :
                              value != 0 && value != UINT64_MAX && value != teb));
        failures += !ok;
        printf("row=%u rt=%u insn=%08lX words=%u status=%08lX value=%016llX "
               "stable=%u teb_stable=%u ok=%u code=",
               row, rt, static_cast<unsigned long>(mrs), count, status,
               static_cast<unsigned long long>(value), stable, teb_stable, ok);
        for (unsigned i = 0; i < count; ++i)
            printf("%08lX%s", static_cast<unsigned long>(code[i]),
                   i + 1 == count ? "\n" : ",");
        if (!VirtualFree(page, 0, MEM_RELEASE))
            return 4;
        ++releases;
    }
    printf("summary calls=%u allocations=%u releases=%u failures=%u\n", calls,
           allocations, releases, failures);
    return failures || allocations != releases ? 1 : 0;
}
