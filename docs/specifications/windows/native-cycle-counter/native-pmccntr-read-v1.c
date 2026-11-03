#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

__declspec(noinline) static unsigned long read_counter(uint64_t *value) {
    __try {
        *value = (uint64_t)_ReadStatusReg(ARM64_PMCCNTR_EL0);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return (unsigned long)GetExceptionCode();
    }
}

int main(void) {
    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency))
        return 2;
    printf("{\"kind\":\"host\",\"schema\":\"rax-native-pmccntr-read-v1\","
           "\"pointer_bytes\":%zu,\"qpc_frequency_hz\":%lld}\n",
           sizeof(void *), frequency.QuadPart);
    for (unsigned i = 0; i < 8; ++i) {
        LARGE_INTEGER qa, qb;
        ULONG64 ca = 0, cb = 0;
        uint64_t a = 0xa5a5a5a5a5a5a5a5ULL;
        uint64_t b = 0x5a5a5a5a5a5a5a5aULL;
        if (!QueryPerformanceCounter(&qa) ||
            !QueryThreadCycleTime(GetCurrentThread(), &ca))
            return 3;
        unsigned long sa = read_counter(&a);
        if (i & 1) {
            volatile uint64_t total = 0;
            for (unsigned n = 0; n < 100000; ++n)
                total += n;
            if (!total)
                return 4;
        } else {
            Sleep(10);
        }
        unsigned long sb = read_counter(&b);
        if (!QueryPerformanceCounter(&qb) ||
            !QueryThreadCycleTime(GetCurrentThread(), &cb))
            return 5;
        printf("{\"kind\":\"sample\",\"index\":%u,\"busy\":%u,"
               "\"status_before\":%lu,\"status_after\":%lu,"
               "\"counter_before\":%llu,\"counter_after\":%llu,"
               "\"qpc_before\":%lld,\"qpc_after\":%lld,"
               "\"thread_cycles_before\":%llu,\"thread_cycles_after\":%llu}\n",
               i, i & 1, sa, sb, (unsigned long long)a, (unsigned long long)b,
               qa.QuadPart, qb.QuadPart, ca, cb);
    }
    puts("{\"kind\":\"finished\",\"samples\":8}");
    return fflush(stdout) || ferror(stdout) ? 6 : 0;
}
