// Floating point: binary32 and binary64 arithmetic, comparison, conversion
// and classification, in numeric kernels whose results must equal the native
// build's bit for bit.
//
// Every function is defined for every argument, including infinities and
// NaNs: a float is converted to an integer only after a range check. Where a
// result is a NaN the test compares only that both sides produced one, so no
// function exposes the payload of a NaN it computed.
#include <stdint.h>

// Horner evaluation of a fixed polynomial.
double polynomial(double x) {
  static const double coefficients[6] = {0.5, -1.25, 3.0, 0.0078125, -2.0, 1.0};
  double value = 0.0;
  for (int i = 5; i >= 0; i--)
    value = value * x + coefficients[i];
  return value;
}

float polynomial_single(float x) {
  static const float coefficients[5] = {1.0f, -0.5f, 0.25f, -0.125f, 0.0625f};
  float value = 0.0f;
  for (int i = 4; i >= 0; i--)
    value = value * x + coefficients[i];
  return value;
}

// Newton's iteration for the square root, against the correctly rounded one.
double newton_root(double x) {
  if (!(x > 0.0) || x > 1.0e300)
    return -1.0;
  double guess = x > 1.0 ? x : 1.0;
  for (int i = 0; i < 40; i++)
    guess = 0.5 * (guess + x / guess);
  return guess - __builtin_sqrt(x);
}

float root_single(float x) { return __builtin_sqrtf(__builtin_fabsf(x)) + 1.0f; }

// A sum that carries its rounding error forward.
double compensated_sum(uint32_t seed, uint32_t count) {
  double sum = 0.0, carry = 0.0;
  count = count % 200 + 1;
  for (uint32_t i = 0; i < count; i++) {
    seed = seed * 1664525u + 1013904223u;
    double term = (double)(int32_t)seed / 65536.0 + (i % 7 ? 1.0e-9 : 1.0e9);
    double adjusted = term - carry;
    double next = sum + adjusted;
    carry = (next - sum) - adjusted;
    sum = next;
  }
  return sum;
}

float plain_sum_single(uint32_t seed, uint32_t count) {
  float sum = 0.0f;
  count = count % 100 + 1;
  for (uint32_t i = 0; i < count; i++) {
    seed = seed * 1103515245u + 12345u;
    sum += (float)(seed >> 8) * 0.001f - 8000.0f;
  }
  return sum;
}

// Matrices of doubles on the stack.
double determinant(uint32_t seed) {
  double m[3][3];
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++) {
      seed = seed * 22695477u + 1u;
      m[i][j] = (double)(int32_t)(seed >> 4) / 1048576.0;
    }
  return m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
         m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
}

struct vector3 {
  float x, y, z;
};

static struct vector3 cross(const struct vector3 *a, const struct vector3 *b) {
  struct vector3 result = {a->y * b->z - a->z * b->y, a->z * b->x - a->x * b->z, a->x * b->y - a->y * b->x};
  return result;
}

float triple_product(float x, float y) {
  struct vector3 a = {x, 2.0f, -1.5f}, b = {0.25f, y, 3.0f}, c = {x - y, 1.0f, y};
  struct vector3 normal = cross(&a, &b);
  return normal.x * c.x + normal.y * c.y + normal.z * c.z;
}

// Simpson's rule over a fixed function.
double integrate(uint32_t intervals, double upper) {
  if (!(upper > -1000.0 && upper < 1000.0))
    return 0.0;
  uint32_t n = (intervals % 50 + 1) * 2;
  double width = upper / (double)n, total = 0.0;
  for (uint32_t i = 0; i <= n; i++) {
    double x = width * (double)i;
    double y = x * x * 0.5 - 3.0 * x + 1.0 / (1.0 + x * x);
    total += (i == 0 || i == n) ? y : (i & 1) ? 4.0 * y : 2.0 * y;
  }
  return total * width / 3.0;
}

// Comparisons, with the unordered cases.
uint32_t relations(double a, double b) {
  uint32_t bits = 0;
  bits |= (uint32_t)(a < b) << 0;
  bits |= (uint32_t)(a <= b) << 1;
  bits |= (uint32_t)(a > b) << 2;
  bits |= (uint32_t)(a >= b) << 3;
  bits |= (uint32_t)(a == b) << 4;
  bits |= (uint32_t)(a != b) << 5;
  bits |= (uint32_t)!(a < b) << 6;
  bits |= (uint32_t)!(a >= b) << 7;
  bits |= (uint32_t)__builtin_isunordered(a, b) << 8;
  bits |= (uint32_t)__builtin_islessgreater(a, b) << 9;
  return bits;
}

uint32_t relations_single(float a, float b) {
  return (uint32_t)(a < b) | (uint32_t)(a == b) << 1 | (uint32_t)(a > b) << 2 | (uint32_t)(a != a || b != b) << 3;
}

// Classification, which the optimizer turns into tests of the encoding.
uint32_t classify(double x) {
  uint32_t bits = 0;
  bits |= (uint32_t)__builtin_isnan(x) << 0;
  bits |= (uint32_t)__builtin_isinf(x) << 1;
  bits |= (uint32_t)__builtin_isfinite(x) << 2;
  bits |= (uint32_t)__builtin_isnormal(x) << 3;
  bits |= (uint32_t)__builtin_signbit(x) << 4;
  bits |= (uint32_t)(x == 0.0) << 5;
  bits |= (uint32_t)(__builtin_fpclassify(1, 2, 3, 4, 5, x)) << 8;
  return bits;
}

uint32_t classify_single(float x) {
  return (uint32_t)__builtin_isnan(x) | (uint32_t)__builtin_isinf(x) << 1 | (uint32_t)__builtin_isnormal(x) << 2 |
         (uint32_t)__builtin_signbit(x) << 3 | (uint32_t)__builtin_fpclassify(1, 2, 3, 4, 5, x) << 8;
}

// Conversions from floats, guarded so that the value always fits.
int64_t to_integer(double x) {
  if (!(x > -9.0e18 && x < 9.0e18))
    return x != x ? 1 : x > 0 ? 2 : 3;
  return (int64_t)x * 4;
}

uint32_t to_unsigned_single(float x) {
  if (!(x >= 0.0f && x < 4.0e9f))
    return 0xfffffffeu;
  return (uint32_t)x;
}

int32_t round_half_away(double x) {
  if (!(x > -2.0e9 && x < 2.0e9))
    return 0;
  return (int32_t)(x < 0 ? x - 0.5 : x + 0.5);
}

// Conversions to floats, where wide integers round.
double from_integers(uint64_t bits) {
  return (double)bits + (double)(int64_t)bits * 0.5 + (double)(uint32_t)bits + (double)(int8_t)bits;
}

float from_integers_single(uint64_t bits) { return (float)bits - (float)(int64_t)bits + (float)(uint16_t)bits; }

// Between the two formats.
double widen_and_narrow(double x) {
  float narrow = (float)x;
  return (double)narrow * 3.0 - (double)(float)(x * 0.5);
}

// The encoding, examined and rebuilt as an integer.
uint64_t exponent_of(double x) {
  union {
    double value;
    uint64_t bits;
  } view = {x};
  uint64_t exponent = view.bits >> 52 & 0x7ff;
  view.bits = (view.bits & ~(0x7ffull << 52)) | 0x3ffull << 52;
  // A NaN stays a NaN under this change, so only its exponent is returned.
  return x != x ? exponent : exponent * 1000 + (uint64_t)(view.value * 100.0 >= 0 ? view.value * 100.0 : 0);
}

float sign_games(float x, float y) {
  float magnitude = __builtin_fabsf(x) + 1.0f;
  return __builtin_copysignf(magnitude, y) - -magnitude * 0.5f;
}

// A fused multiply-add, rounded once.
double fused(double a, double b) { return __builtin_fma(a, b, -a) + __builtin_fma(b, 0.5, 1.0); }

// The smaller and the larger, on numbers that are never both zeros.
double bounds(double a, double b) {
  if (a != a || b != b)
    return 0.0;
  double low = __builtin_fmin(a + 1.0, b + 3.0), high = __builtin_fmax(a + 1.0, b + 3.0);
  return low * 0.25 + high * 0.75;
}

// Globals of floats.
static const float weights[4] = {0.125f, 0.25f, 0.5f, 1.0f};
static double accumulator = 2.5;

double weighted(uint32_t which, float x) {
  accumulator = 2.5;
  for (uint32_t i = 0; i <= (which & 3); i++)
    accumulator = accumulator * (double)weights[i] + (double)x;
  return accumulator;
}

// A function pointer over doubles.
static double twice(double x) { return x + x; }
static double halve(double x) { return x * 0.5; }
static double square(double x) { return x * x; }
static double (*const maps[3])(double) = {twice, halve, square};

double mapped(uint32_t which, double x) { return maps[which % 3](maps[(which / 3) % 3](x)) + 1.0; }
