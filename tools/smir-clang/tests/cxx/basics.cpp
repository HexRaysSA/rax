// C++ without exceptions, run-time type information or a library: classes,
// virtual dispatch, templates, lambdas, constant evaluation, and objects
// with dynamic initialization.
//
// The entry points are the extern "C" functions. As in the C corpus, each
// test case runs in a fresh machine while the native reference calls every
// case in one process, so a function must reset the global state it reads.
#include <stdint.h>

// What the language's runtime would supply. Nothing here allocates.
void operator delete(void *, unsigned long) noexcept {}
extern "C" void __cxa_pure_virtual() { __builtin_trap(); }

namespace {

class Shape {
public:
  virtual ~Shape() = default;
  virtual uint32_t area() const = 0;
  virtual uint32_t corners() const { return 0; }
  uint32_t describe() const { return area() * 16 + corners(); }
};

class Rectangle : public Shape {
public:
  Rectangle(uint32_t width, uint32_t height) : width_(width), height_(height) {}
  uint32_t area() const override { return width_ * height_; }
  uint32_t corners() const override { return 4; }

protected:
  uint32_t width_, height_;
};

class Square final : public Rectangle {
public:
  explicit Square(uint32_t side) : Rectangle(side, side) {}
  uint32_t corners() const override { return 4 + (width_ & 1); }
};

class Disc : public Shape {
public:
  explicit Disc(uint32_t radius) : radius_(radius) {}
  uint32_t area() const override { return radius_ * radius_ * 355 / 113; }

private:
  uint32_t radius_;
};

__attribute__((noinline)) uint32_t total(const Shape *const *shapes, unsigned count) {
  uint32_t sum = 0;
  for (unsigned i = 0; i < count; i++)
    sum = sum * 31 + shapes[i]->describe();
  return sum;
}

// A second base, so that one of the calls adjusts `this`.
class Named {
public:
  virtual uint32_t name() const { return 0x4e; }
  uint32_t tag = 7;
};

class Labelled : public Rectangle, public Named {
public:
  Labelled(uint32_t width, uint32_t height, uint32_t label) : Rectangle(width, height), label_(label) {}
  uint32_t name() const override { return label_ + area(); }

private:
  uint32_t label_;
};

__attribute__((noinline)) uint32_t name_of(const Named &named) { return named.name() * 3 + named.tag; }

// Templates and operator overloading.
template <typename T, unsigned N> class Ring {
public:
  void push(T value) {
    items_[next_ % N] = value;
    next_++;
  }
  T fold() const {
    T result{};
    for (unsigned i = 0; i < N; i++)
      result = result * T(3) + items_[i];
    return result;
  }

private:
  T items_[N] = {};
  unsigned next_ = 0;
};

struct Fraction {
  int64_t numerator, denominator;
  constexpr Fraction(int64_t n = 0, int64_t d = 1) : numerator(n), denominator(d) {}
  constexpr Fraction operator+(Fraction other) const {
    return {numerator * other.denominator + other.numerator * denominator, denominator * other.denominator};
  }
  constexpr Fraction operator*(Fraction other) const {
    return {numerator * other.numerator, denominator * other.denominator};
  }
};

template <typename T> constexpr T power(T base, unsigned exponent) {
  T result = 1;
  while (exponent--)
    result *= base;
  return result;
}

// Evaluated by the compiler.
constexpr uint32_t squares[8] = {power(1u, 2), power(2u, 2), power(3u, 2), power(4u, 2),
                                 power(5u, 2), power(6u, 2), power(7u, 2), power(8u, 2)};

template <typename Function> __attribute__((noinline)) uint32_t repeat(unsigned times, uint32_t value, Function step) {
  for (unsigned i = 0; i < times; i++)
    value = step(value, i);
  return value;
}

// Objects whose constructors run before the program's first function.
struct Counter {
  uint32_t value;
  explicit Counter(uint32_t start) : value(start * 3 + 1) {}
};

__attribute__((noinline)) uint32_t seed_value() { return 41; }

Counter first_counter(seed_value());
Counter second_counter(first_counter.value + 5);
uint32_t table[4] = {seed_value(), first_counter.value, second_counter.value, 9};

// Initialized the first time the function runs, and counted when it is.
uint32_t &lazily(uint32_t &runs) {
  static uint32_t value = (runs++, seed_value() * 2);
  return value;
}

} // namespace

extern "C" {

uint32_t dispatch(uint32_t a, uint32_t b) {
  Rectangle rectangle(a & 0xff, b & 0xff);
  Square square(a >> 8 & 0x3f);
  Disc disc(b >> 8 & 0x3f);
  const Shape *shapes[3] = {&rectangle, &square, &disc};
  return total(shapes, 3) ^ total(shapes + (a & 1), 2);
}

uint32_t adjusted(uint32_t a, uint32_t b) {
  Labelled labelled(a & 0xfff, b & 0xfff, a ^ b);
  Named plain;
  const Shape &shape = labelled;
  return name_of(labelled) + name_of(plain) * 5 + shape.describe();
}

uint64_t generic(uint32_t seed) {
  Ring<uint64_t, 5> wide;
  Ring<uint8_t, 3> narrow;
  for (unsigned i = 0; i < 9; i++) {
    seed = seed * 1664525u + 1013904223u;
    wide.push(seed);
    narrow.push(static_cast<uint8_t>(seed >> 24));
  }
  return wide.fold() ^ static_cast<uint64_t>(narrow.fold()) << 40;
}

int64_t fractions(int32_t a, int32_t b) {
  Fraction sum = Fraction(a, 3) + Fraction(b, 7) * Fraction(2, 5);
  constexpr Fraction fixed = Fraction(1, 2) + Fraction(1, 3);
  return sum.numerator * 1000 + sum.denominator + fixed.numerator * 7 + fixed.denominator;
}

uint32_t closures(uint32_t value, uint32_t times) {
  uint32_t offset = value >> 16;
  auto mix = [offset](uint32_t current, unsigned round) { return (current ^ offset) * 2654435761u + round; };
  uint32_t calls = 0;
  auto counting = [&calls](uint32_t current, unsigned) {
    calls++;
    return current + squares[calls & 7];
  };
  return repeat(times % 20, value, mix) + repeat(times % 7, value, counting) + calls;
}

uint32_t initialized(uint32_t which) {
  // The constructors ran, in order, before this function.
  return table[which & 3] + first_counter.value * 100 + second_counter.value * 10000;
}

uint32_t lazy(uint32_t start) {
  // Whether this is the first call depends on what ran before, so the
  // result uses only what holds either way: the initializer runs at most
  // once, and a later call does not undo an assignment.
  uint32_t runs = 0;
  uint32_t &first = lazily(runs);
  first = start;
  uint32_t &second = lazily(runs);
  return second * 4 + (runs <= 1) + (&first == &second) * 2;
}

} // extern "C"
