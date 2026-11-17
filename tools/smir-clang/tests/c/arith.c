// Integer arithmetic and loops. Every function is defined for all arguments:
// arithmetic is unsigned, divisors are checked and loops are bounded.
#include <stdint.h>

uint64_t gcd(uint64_t a, uint64_t b) {
  while (b) {
    uint64_t t = a % b;
    a = b;
    b = t;
  }
  return a;
}

uint64_t lcm(uint64_t a, uint64_t b) {
  uint64_t g = gcd(a, b);
  return g ? a / g * b : 0;
}

uint32_t pow_mod(uint32_t base, uint32_t exponent) {
  const uint64_t modulus = 1000000007u;
  uint64_t result = 1, power = base % modulus;
  while (exponent) {
    if (exponent & 1)
      result = result * power % modulus;
    power = power * power % modulus;
    exponent >>= 1;
  }
  return (uint32_t)result;
}

uint32_t isqrt(uint64_t n) {
  uint64_t low = 0, high = 0x100000000u;
  while (high - low > 1) {
    uint64_t middle = low + (high - low) / 2;
    if (middle * middle <= n)
      low = middle;
    else
      high = middle;
  }
  return (uint32_t)low;
}

uint32_t collatz_steps(uint64_t n) {
  uint32_t steps = 0;
  while (n > 1 && steps < 500) {
    n = n & 1 ? 3 * n + 1 : n / 2;
    steps++;
  }
  return steps;
}

uint32_t digit_sum(uint64_t n) {
  uint32_t sum = 0;
  do {
    sum += (uint32_t)(n % 10);
    n /= 10;
  } while (n);
  return sum;
}

uint32_t is_prime(uint32_t n) {
  n &= 0xffff;
  if (n < 2)
    return 0;
  for (uint32_t d = 2; d * d <= n; d++)
    if (n % d == 0)
      return 0;
  return 1;
}

uint64_t fib(uint32_t n) {
  uint64_t a = 0, b = 1;
  for (n &= 63; n; n--) {
    uint64_t t = a + b;
    a = b;
    b = t;
  }
  return a;
}

uint64_t triangle(uint32_t n) {
  uint64_t total = 0;
  n &= 31;
  for (uint32_t i = 0; i <= n; i++)
    for (uint32_t j = 0; j < i; j++)
      total += i ^ j;
  return total;
}

int64_t signed_div(int64_t a, int64_t b) {
  if (b == 0 || (a == INT64_MIN && b == -1))
    return 0;
  // The quotient can be as large as the dividend, so combine without signed
  // overflow.
  return (int64_t)((uint64_t)(a / b) * 3 + (uint64_t)(a % b));
}

// Three-way comparisons, which the optimizer recognizes as single operations.
int32_t order_signed(int64_t a, int64_t b) { return (a > b) - (a < b); }

int32_t order_unsigned(uint32_t a, uint32_t b) { return a < b ? -1 : a > b; }

int8_t order_narrow(int16_t a, int16_t b) { return (int8_t)((a > b) - (a < b)); }
