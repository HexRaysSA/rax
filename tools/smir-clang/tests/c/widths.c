// Narrow and wide integer types: promotions, truncating conversions, sign and
// zero extension, one-bit results and 128-bit intermediates.
#include <stdint.h>

uint8_t add8(uint8_t a, uint8_t b) { return (uint8_t)(a + b); }

int8_t negate8(int8_t x) { return (int8_t)(0u - (uint8_t)x); }

uint16_t multiply16(uint16_t a, uint16_t b) { return (uint16_t)((uint32_t)a * b); }

int16_t shift16(int16_t x, uint8_t n) { return (int16_t)(x >> (n & 15)); }

int64_t extend_signed(int8_t x) { return x; }

uint64_t extend_unsigned(uint8_t x) { return x; }

int64_t extend_through_16(int32_t x) { return (int16_t)x; }

uint64_t widening_multiply(uint32_t a, uint32_t b) { return (uint64_t)a * b; }

uint64_t multiply_high(uint64_t a, uint64_t b) { return (uint64_t)((unsigned __int128)a * b >> 64); }

uint64_t add_carry(uint64_t a, uint64_t b) {
  unsigned __int128 sum = (unsigned __int128)a + b;
  return (uint64_t)sum ^ (uint64_t)(sum >> 64);
}

int64_t signed_multiply_high(int64_t a, int64_t b) { return (int64_t)((__int128)a * b >> 64); }

_Bool less_signed(int32_t a, int32_t b) { return a < b; }

_Bool less_unsigned(uint32_t a, uint32_t b) { return a < b; }

uint32_t mixed_compare(int32_t a, uint32_t b) { return (a < 0) * 2 + ((uint32_t)a < b); }

uint8_t char_arithmetic(signed char a, unsigned char b) { return (uint8_t)(a * 3 - b / 2 + (a < 0)); }

uint32_t truncations(uint64_t x) {
  uint8_t byte = (uint8_t)x;
  uint16_t half = (uint16_t)(x >> 8);
  int8_t high = (int8_t)(x >> 56);
  return (uint32_t)byte + half * 2u + (uint32_t)(int32_t)high;
}
