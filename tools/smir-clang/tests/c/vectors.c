// Vector values, which the driver rewrites as operations on their elements:
// the compiler's vector extensions, and the vectors the optimizer makes of
// small structures.
#include <stdint.h>

typedef int32_t int4 __attribute__((vector_size(16)));
typedef uint8_t byte16 __attribute__((vector_size(16)));
typedef double double2 __attribute__((vector_size(16)));
typedef float float4 __attribute__((vector_size(16)));

uint32_t lanes(uint32_t a, uint32_t b) {
  int4 left = {(int32_t)a, (int32_t)(a >> 3), (int32_t)(b << 2), 7};
  int4 right = {(int32_t)b, 5, (int32_t)(a ^ b), (int32_t)(b >> 9)};
  // Unsigned lanes, so that the arithmetic wraps.
  typedef uint32_t uint4 __attribute__((vector_size(16)));
  uint4 sum = (uint4)left + (uint4)right, product = (uint4)left * (uint4)right;
  uint4 mixed = (sum ^ product) >> 3 | sum << 29;
  int4 greater = left > right;
  return mixed[0] + mixed[1] * 3 + mixed[2] * 5 + mixed[3] * 7 + (uint32_t)(greater[0] + greater[2] * 2 + greater[3] * 4);
}

uint32_t shuffled(uint32_t seed) {
  byte16 bytes;
  for (int i = 0; i < 16; i++) {
    seed = seed * 1103515245u + 12345u;
    bytes[i] = (uint8_t)(seed >> 16);
  }
  byte16 reversed = __builtin_shufflevector(bytes, bytes, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
  byte16 interleaved = __builtin_shufflevector(bytes, reversed, 0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23);
  byte16 combined = interleaved + (reversed & bytes);
  uint32_t hash = 0;
  for (int i = 0; i < 16; i++)
    hash = hash * 31 + combined[i];
  return hash;
}

double paired(double x, double y) {
  if (x != x || y != y)
    return 0.0;
  double2 point = {x, y}, scale = {0.5, -2.0}, offset = {1.0, 3.0};
  double2 moved = point * scale + offset;
  double2 swapped = __builtin_shufflevector(moved, moved, 1, 0);
  double2 total = moved - swapped * scale;
  return total[0] * 0.25 + total[1];
}

float converted(uint32_t a, uint32_t b) {
  int4 integers = {(int32_t)(a & 0xffff), -(int32_t)(b & 0xfff), (int32_t)(a >> 20), 3};
  float4 floats = __builtin_convertvector(integers, float4);
  floats = floats * 0.5f + (float4){1.0f, 2.0f, 3.0f, 4.0f};
  int4 back = __builtin_convertvector(floats, int4);
  return floats[0] + floats[1] + floats[2] + floats[3] + (float)(back[0] ^ back[3]);
}

// Structures of two doubles, which the optimizer copies as one vector.
struct complex {
  double real, imaginary;
};

__attribute__((noinline)) static void rotate(struct complex *values, uint32_t count) {
  for (uint32_t i = 0; i + 1 < count; i += 2) {
    struct complex swap = values[i];
    values[i] = values[i + 1];
    values[i + 1] = swap;
  }
}

double swapped_pairs(uint32_t seed) {
  struct complex values[6];
  for (int i = 0; i < 6; i++) {
    seed = seed * 1664525u + 1013904223u;
    values[i].real = (double)(seed >> 12) / 64.0;
    values[i].imaginary = (double)(int32_t)seed / 1024.0;
  }
  rotate(values, 6);
  double total = 0.0;
  for (int i = 0; i < 6; i++)
    total = total * 0.5 + values[i].real - values[i].imaginary * (double)(i + 1);
  return total;
}

// An empty assembly statement is only a barrier for the optimizer.
uint32_t barrier(uint32_t value) {
  uint32_t copy = value * 3;
  __asm__ __volatile__("" ::: "memory");
  return copy + value;
}
