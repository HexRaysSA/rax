// Guaranteed tail calls (`[[clang::musttail]]`).
//
// A `musttail` call must be the last instruction before its `ret`, and the
// `ret` must forward the call's result.  Obfuscation passes that split the
// return block, insert before the return, or rewrite the return operand must
// leave these sequences alone or they produce IR that fails the verifier.
// Exercises that resilience across integer-returning trampolines.

#include <cstdint>
#include <cstdio>

__attribute__((noinline)) int leaf(int x) { return x * 3 + 1; }

__attribute__((noinline)) int trampoline(int x) {
    [[clang::musttail]] return leaf(x + 1);
}

__attribute__((noinline)) std::int64_t leaf64(std::int64_t x) {
    return (x ^ 0x5555) + 7;
}

__attribute__((noinline)) std::int64_t trampoline64(std::int64_t x) {
    if (x < 0)
        [[clang::musttail]] return leaf64(-x);
    [[clang::musttail]] return leaf64(x);
}

// A longer chain so the mutual-recursion style tail forwarding is present.
__attribute__((noinline)) unsigned countdown(unsigned n, unsigned acc) {
    if (n == 0)
        return acc;
    [[clang::musttail]] return countdown(n - 1, acc + n);
}

int main() {
    long sum = 0;
    for (int i = 0; i < 1000; ++i)
        sum += trampoline(i);
    for (std::int64_t i = -500; i < 500; ++i)
        sum += trampoline64(i);
    sum += countdown(100, 0);
    std::printf("%ld\n", sum);
    return 0;
}
