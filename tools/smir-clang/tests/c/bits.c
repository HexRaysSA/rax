// Bit manipulation, including the idioms and builtins the optimizer turns
// into rotate, byte swap, count and min/max intrinsics.
#include <stdint.h>

uint32_t rotl32(uint32_t x, uint32_t n) { return x << (n & 31) | x >> (-n & 31); }

uint64_t rotr64(uint64_t x, uint64_t n) { return x >> (n & 63) | x << (-n & 63); }

uint32_t swap32(uint32_t x) { return __builtin_bswap32(x); }

uint64_t swap64(uint64_t x) { return __builtin_bswap64(x); }

uint32_t swap16(uint32_t x) { return (uint16_t)(x << 8 | (x & 0xffff) >> 8); }

uint32_t popcount_builtin(uint64_t x) { return (uint32_t)__builtin_popcountll(x); }

uint32_t popcount_loop(uint64_t x) {
  uint32_t count = 0;
  for (; x; x &= x - 1)
    count++;
  return count;
}

uint32_t leading_zeros(uint32_t x) { return x ? (uint32_t)__builtin_clz(x) : 32; }

uint32_t trailing_zeros(uint64_t x) { return x ? (uint32_t)__builtin_ctzll(x) : 64; }

uint32_t parity(uint64_t x) {
  x ^= x >> 32;
  x ^= x >> 16;
  x ^= x >> 8;
  x ^= x >> 4;
  return 0x6996 >> (x & 15) & 1;
}

uint32_t reverse_bits(uint32_t x) {
  uint32_t result = 0;
  for (int i = 0; i < 32; i++) {
    result = result << 1 | (x & 1);
    x >>= 1;
  }
  return result;
}

int32_t sign_extend_12(uint32_t x) { return (int32_t)((x & 0xfff) ^ 0x800) - 0x800; }

uint32_t absolute(int32_t x) { return x < 0 ? 0u - (uint32_t)x : (uint32_t)x; }

int32_t min_signed(int32_t a, int32_t b) { return a < b ? a : b; }

int32_t max_signed(int32_t a, int32_t b) { return a > b ? a : b; }

uint64_t min_unsigned(uint64_t a, uint64_t b) { return a < b ? a : b; }

uint64_t max_unsigned(uint64_t a, uint64_t b) { return a > b ? a : b; }

uint32_t saturating_add(uint32_t a, uint32_t b) {
  uint32_t sum = a + b;
  return sum < a ? 0xffffffffu : sum;
}

uint64_t saturating_subtract(uint64_t a, uint64_t b) { return a > b ? a - b : 0; }

uint32_t extract_field(uint64_t word, uint32_t position) {
  position &= 31;
  return (uint32_t)(word >> position) & 0x1ff;
}

uint32_t is_power_of_two(uint64_t x) { return x && !(x & (x - 1)); }

int64_t arithmetic_shift(int64_t x, uint32_t n) { return x >> (n & 63); }
