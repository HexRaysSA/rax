// Calls: recursion, mutual recursion, internal helpers the optimizer may or
// may not inline, and functions with many parameters.
#include <stdint.h>

uint64_t factorial(uint32_t n) {
  n &= 15;
  return n <= 1 ? 1 : n * factorial(n - 1);
}

uint64_t fib_recursive(uint32_t n) {
  n &= 15;
  return n < 2 ? n : fib_recursive(n - 1) + fib_recursive(n - 2);
}

static uint32_t ackermann_inner(uint32_t m, uint32_t n) {
  if (m == 0)
    return n + 1;
  if (n == 0)
    return ackermann_inner(m - 1, 1);
  return ackermann_inner(m - 1, ackermann_inner(m, n - 1));
}

uint32_t ackermann(uint32_t m, uint32_t n) { return ackermann_inner(m % 3, n & 7); }

static uint32_t is_odd(uint32_t n);

__attribute__((noinline)) static uint32_t is_even(uint32_t n) { return n == 0 ? 1 : is_odd(n - 1); }

__attribute__((noinline)) static uint32_t is_odd(uint32_t n) { return n == 0 ? 0 : is_even(n - 1); }

uint32_t parity_by_recursion(uint32_t n) { return is_even(n & 255) * 2 + is_odd(n & 63); }

__attribute__((noinline)) static uint64_t mix(uint64_t a, uint64_t b) { return (a ^ b) * 0x9e3779b97f4a7c15u + (a >> 7); }

__attribute__((noinline)) static uint64_t mix3(uint64_t a, uint64_t b, uint64_t c) { return mix(mix(a, b), mix(b, c)); }

uint64_t chain(uint64_t x, uint64_t y) { return mix3(x, y, mix(y, x)); }

__attribute__((noinline)) static uint32_t wide(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f,
                                               uint32_t g, uint32_t h, uint32_t i, uint32_t j) {
  return a - b * 3 + c * 5 - d * 7 + e * 11 - f * 13 + g * 17 - h * 19 + i * 23 - j * 29;
}

uint32_t many_arguments(uint32_t x, uint32_t y) {
  return wide(x, y, x + 1, y + 2, x ^ y, x & y, x | y, x - y, y - x, x * y);
}

__attribute__((noinline)) static void discard(uint32_t x) { (void)x; }

uint32_t calls_void(uint32_t x) {
  discard(x);
  discard(x + 1);
  return x * 2 + 1;
}
