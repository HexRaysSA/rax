/*
 * Architecture Detection via Inline Assembly
 *
 * Uses architecture-specific instructions to detect CPU features.
 * Tests CPUID (x86), MRS (ARM), etc.
 *
 * Features exercised:
 *   - CPU identification
 *   - Feature flag detection
 *   - Architecture-specific registers
 */

#include <stdint.h>
#include <string.h>

volatile int64_t sink;

#if defined(__x86_64__) || defined(__i386__)

/* x86/x64 CPUID instruction */
typedef struct {
    uint32_t eax, ebx, ecx, edx;
} CpuidResult;

__attribute__((noinline))
void cpuid(uint32_t leaf, uint32_t subleaf, CpuidResult *result) {
    __asm__ volatile(
        "cpuid"
        : "=a"(result->eax), "=b"(result->ebx), "=c"(result->ecx), "=d"(result->edx)
        : "a"(leaf), "c"(subleaf)
    );
}

__attribute__((noinline))
void get_vendor_string(char *vendor) {
    CpuidResult r;
    cpuid(0, 0, &r);
    memcpy(vendor, &r.ebx, 4);
    memcpy(vendor + 4, &r.edx, 4);
    memcpy(vendor + 8, &r.ecx, 4);
    vendor[12] = '\0';
}

__attribute__((noinline))
uint32_t get_max_cpuid_leaf(void) {
    CpuidResult r;
    cpuid(0, 0, &r);
    return r.eax;
}

__attribute__((noinline))
int has_sse(void) {
    CpuidResult r;
    cpuid(1, 0, &r);
    return (r.edx >> 25) & 1;
}

__attribute__((noinline))
int has_sse2(void) {
    CpuidResult r;
    cpuid(1, 0, &r);
    return (r.edx >> 26) & 1;
}

__attribute__((noinline))
int has_avx(void) {
    CpuidResult r;
    cpuid(1, 0, &r);
    return (r.ecx >> 28) & 1;
}

__attribute__((noinline))
int has_avx2(void) {
    CpuidResult r;
    cpuid(7, 0, &r);
    return (r.ebx >> 5) & 1;
}

__attribute__((noinline))
int has_aes_ni(void) {
    CpuidResult r;
    cpuid(1, 0, &r);
    return (r.ecx >> 25) & 1;
}

__attribute__((noinline))
uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

__attribute__((noinline))
int64_t arch_specific_test(void) {
    int64_t result = 0;
    char vendor[16];

    get_vendor_string(vendor);
    for (int i = 0; i < 12; i++) {
        result += vendor[i];
    }

    result += get_max_cpuid_leaf();
    result += has_sse() * 100;
    result += has_sse2() * 200;
    result += has_avx() * 400;
    result += has_avx2() * 800;
    result += has_aes_ni() * 1600;

    uint64_t tsc1 = read_tsc();
    for (volatile int i = 0; i < 1000; i++) {}
    uint64_t tsc2 = read_tsc();
    result += (int64_t)(tsc2 - tsc1);

    return result;
}

#elif defined(__aarch64__)

/* AArch64 user-readable architecture probes.  Some EL1 ID registers trap in
 * user space on macOS and hardened Linux setups, so keep the runtime corpus on
 * registers/features that are safe from EL0. */
__attribute__((noinline))
uint64_t read_cntpct(void) {
    uint64_t cnt;
    __asm__ volatile("mrs %0, CNTVCT_EL0" : "=r"(cnt));
    return cnt;
}

__attribute__((noinline))
int has_aes(void) {
#if defined(__ARM_FEATURE_AES)
    return 1;
#else
    return 0;
#endif
}

__attribute__((noinline))
int has_sha1(void) {
#if defined(__ARM_FEATURE_SHA2)
    return 1;
#else
    return 0;
#endif
}

__attribute__((noinline))
int has_sha256(void) {
#if defined(__ARM_FEATURE_SHA2)
    return 1;
#else
    return 0;
#endif
}

__attribute__((noinline))
int has_crc32(void) {
#if defined(__ARM_FEATURE_CRC32)
    return 1;
#else
    return 0;
#endif
}

__attribute__((noinline))
int64_t arch_specific_test(void) {
    int64_t result = 0;

    result += has_aes() * 100;
    result += has_sha1() * 200;
    result += has_sha256() * 400;
    result += has_crc32() * 800;

    uint64_t cnt1 = read_cntpct();
    for (volatile int i = 0; i < 1000; i++) {}
    uint64_t cnt2 = read_cntpct();
    result += (int64_t)(cnt2 - cnt1);

    return result;
}

#elif defined(__arm__)

/* ARMv7 system register reads */
__attribute__((noinline))
uint32_t read_midr(void) {
    uint32_t midr;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(midr));
    return midr;
}

__attribute__((noinline))
uint32_t read_id_isar0(void) {
    uint32_t isar0;
    __asm__ volatile("mrc p15, 0, %0, c0, c2, 0" : "=r"(isar0));
    return isar0;
}

__attribute__((noinline))
int64_t arch_specific_test(void) {
    int64_t result = 0;

    uint32_t midr = read_midr();
    result += midr & 0xFFFF;

    uint32_t isar0 = read_id_isar0();
    result += isar0 & 0xFF;

    return result;
}

#elif defined(__riscv)

/* RISC-V CSR reads */
__attribute__((noinline))
uint64_t read_cycle(void) {
    uint64_t cycle;
    __asm__ volatile("rdcycle %0" : "=r"(cycle));
    return cycle;
}

__attribute__((noinline))
uint64_t read_time(void) {
    uint64_t time;
    __asm__ volatile("rdtime %0" : "=r"(time));
    return time;
}

__attribute__((noinline))
uint64_t read_instret(void) {
    uint64_t instret;
    __asm__ volatile("rdinstret %0" : "=r"(instret));
    return instret;
}

__attribute__((noinline))
int64_t arch_specific_test(void) {
    int64_t result = 0;

    uint64_t cycle1 = read_cycle();
    for (volatile int i = 0; i < 1000; i++) {}
    uint64_t cycle2 = read_cycle();
    result += (int64_t)(cycle2 - cycle1);

    uint64_t instret1 = read_instret();
    for (volatile int i = 0; i < 1000; i++) {}
    uint64_t instret2 = read_instret();
    result += (int64_t)(instret2 - instret1);

    return result;
}

#else

/* Generic fallback - no inline assembly */
__attribute__((noinline))
int64_t arch_specific_test(void) {
    return 0;
}

#endif

/* Generic computation */
__attribute__((noinline))
int64_t generic_compute(int n) {
    int64_t result = 0;
    for (int i = 0; i < n; i++) {
        result += i * i;
    }
    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 50; iter++) { /* rax: was 1000 */
        result += arch_specific_test();
        result += generic_compute(100);
    }

    sink = result;
    return 0;
}
