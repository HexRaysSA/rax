// Variadic functions: reading arguments of several types, copying and
// passing on an argument list, and calling through a pointer.
#include <stdarg.h>
#include <stdint.h>

__attribute__((noinline)) static uint64_t sum_values(uint32_t count, ...) {
  va_list arguments;
  va_start(arguments, count);
  uint64_t total = 0;
  for (uint32_t i = 0; i < count; i++)
    total = total * 3 + va_arg(arguments, uint32_t);
  va_end(arguments);
  return total;
}

uint64_t fixed_counts(uint32_t a, uint32_t b) {
  return sum_values(0) + sum_values(1, a) * 5 + sum_values(2, a, b) * 7 + sum_values(5, b, a, 1u, 2u, a ^ b) * 11;
}

// Each argument's type is named by a letter of the format.
__attribute__((noinline)) static double fold(const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  double total = 0.0;
  for (; *format; format++) {
    switch (*format) {
    case 'i':
      total += (double)va_arg(arguments, int);
      break;
    case 'u':
      total += (double)va_arg(arguments, unsigned);
      break;
    case 'l':
      total += (double)va_arg(arguments, int64_t);
      break;
    case 'q':
      total += (double)(va_arg(arguments, uint64_t) >> 11);
      break;
    case 'd':
      total = total * 0.5 + va_arg(arguments, double);
      break;
    case 's': {
      // A string contributes the sum of its bytes.
      for (const char *text = va_arg(arguments, const char *); *text; text++)
        total += (double)(unsigned char)*text;
      break;
    }
    case 'p': {
      // A pointer to an integer to read and to update.
      int32_t *slot = va_arg(arguments, int32_t *);
      total += (double)*slot;
      *slot += 1;
      break;
    }
    case 'f': {
      uint32_t (*function)(uint32_t) = va_arg(arguments, uint32_t (*)(uint32_t));
      // The total is converted only when it is known to fit.
      total += (double)function(total >= 0.0 && total < 65536.0 ? (uint32_t)total : 7u);
      break;
    }
    }
  }
  va_end(arguments);
  return total;
}

static uint32_t triple(uint32_t value) { return value * 3 + 1; }

double mixed_types(int32_t a, double b) {
  int32_t slot = a / 3;
  // A char and a short are promoted to int, and a float to double.
  double result = fold("iudlqspfic", a, (unsigned)a >> 3, b, (int64_t)a * 100000, 0xfedcba9876543210ull, "portable",
                       &slot, triple, (short)a, (char)'x');
  return result + (double)slot + fold("d", (float)b * 0.0f + 0.25f) + fold("");
}

// An argument list read twice through a copy.
__attribute__((noinline)) static int64_t spread(uint32_t count, ...) {
  va_list first, second;
  va_start(first, count);
  va_copy(second, first);
  int64_t low = INT64_MAX, high = INT64_MIN;
  for (uint32_t i = 0; i < count; i++) {
    int64_t value = va_arg(first, int64_t);
    if (value < low)
      low = value;
  }
  va_end(first);
  for (uint32_t i = 0; i < count; i++) {
    int64_t value = va_arg(second, int64_t);
    if (value > high)
      high = value;
  }
  va_end(second);
  return (int64_t)((uint64_t)high - (uint64_t)low);
}

int64_t extremes(int64_t a, int64_t b) { return spread(4, a, b, (int64_t)-7, a ^ b) + spread(1, b); }

// An argument list handed to another function.
__attribute__((noinline)) static uint32_t digest_list(uint32_t count, va_list arguments) {
  uint32_t hash = 2166136261u;
  while (count--)
    hash = (hash ^ va_arg(arguments, uint32_t)) * 16777619u;
  return hash;
}

__attribute__((noinline)) static uint32_t digest(uint32_t count, ...) {
  va_list arguments;
  va_start(arguments, count);
  uint32_t first = digest_list(count / 2, arguments);
  // The callee advanced its own copy of the list; this one starts over.
  va_end(arguments);
  va_start(arguments, count);
  uint32_t all = digest_list(count, arguments);
  va_end(arguments);
  return first ^ all * 31;
}

uint32_t forwarded(uint32_t a, uint32_t b) { return digest(4, a, b, a + b, a * b); }

// Variadic calls in a loop reuse the storage of their call site.
uint64_t repeated(uint32_t seed, uint32_t rounds) {
  uint64_t total = 0;
  for (uint32_t i = 0; i < rounds % 50; i++) {
    seed = seed * 1664525u + 1013904223u;
    total += sum_values(3, seed, i, seed >> 16) ^ (uint64_t)extremes(seed, i);
  }
  return total;
}

// Through a pointer to a variadic function.
typedef uint64_t (*variadic)(uint32_t, ...);

__attribute__((noinline)) static uint64_t last_value(uint32_t count, ...) {
  va_list arguments;
  va_start(arguments, count);
  uint64_t value = 0;
  for (uint32_t i = 0; i < count; i++)
    value = va_arg(arguments, uint32_t);
  va_end(arguments);
  return value;
}

uint64_t through_pointer(uint32_t which, uint32_t a) {
  static const variadic functions[2] = {sum_values, last_value};
  return functions[which & 1](3, a, a + 1, a + 2) + functions[(which >> 1) & 1](1, which);
}

// Recursion: each activation has its own list.
__attribute__((noinline)) static uint32_t nested(uint32_t depth, ...) {
  va_list arguments;
  va_start(arguments, depth);
  uint32_t value = va_arg(arguments, uint32_t);
  uint32_t result = depth ? nested(depth - 1, value * 2 + 1, depth) + va_arg(arguments, uint32_t) : value;
  va_end(arguments);
  return result;
}

uint32_t recursive(uint32_t depth, uint32_t value) { return nested(depth % 9, value, 17u); }

// Sixteen-byte arguments between four-byte ones: each wide argument starts
// at a multiple of sixteen bytes, so the list has to skip the gap.
__attribute__((noinline)) static unsigned __int128 wide_sum(uint32_t count, ...) {
  va_list arguments;
  va_start(arguments, count);
  unsigned __int128 total = 0;
  for (uint32_t i = 0; i < count; i++) {
    total += va_arg(arguments, uint32_t);
    total = total * 3 + va_arg(arguments, unsigned __int128);
  }
  va_end(arguments);
  return total;
}

uint64_t wide_arguments(uint64_t a, uint64_t b) {
  unsigned __int128 wide = (unsigned __int128)a << 64 | b;
  unsigned __int128 total =
      wide_sum(2, (uint32_t)a, wide, (uint32_t)b, wide * 7 + 1) + wide_sum(1, 5u, (unsigned __int128)b);
  return (uint64_t)(total >> 64) ^ (uint64_t)total;
}

// Structures as variadic arguments: each is the callee's own copy.
struct sample {
  uint32_t a;
  uint64_t b;
  uint8_t c[5];
};

__attribute__((noinline)) static uint64_t take_structures(uint32_t count, ...) {
  va_list arguments;
  va_start(arguments, count);
  uint64_t total = 0;
  for (uint32_t i = 0; i < count; i++) {
    struct sample value = va_arg(arguments, struct sample);
    value.a += i;
    total = total * 31 + value.a + value.b + value.c[i % 5];
    total += va_arg(arguments, uint32_t);
  }
  va_end(arguments);
  return total;
}

uint64_t structures(uint32_t a, uint32_t b) {
  struct sample first = {a, (uint64_t)b << 20 | a, {1, 2, 3, 4, 5}};
  struct sample second = {b, a, {9, 8, 7, 6, (uint8_t)a}};
  uint64_t total = take_structures(2, first, 7u, second, b);
  // The caller's objects are as they were.
  return total + first.a + second.c[4];
}
