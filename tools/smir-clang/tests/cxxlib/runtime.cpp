// What the language leaves to its runtime: pointers to member functions, a
// function's static variables when several threads reach them at once, and
// storage that runs out.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <new>
#include <stdexcept>
#include <thread>
#include <vector>

struct Shape {
  virtual ~Shape() = default;
  virtual int area() const { return 0; }
  int plain(int x) const { return x + tag; }
  int tag = 5;
};
struct Square : Shape {
  int side = 3;
  int area() const override { return side * side; }
  int twice(int x) const { return 2 * x + side; }
};
struct Other {
  virtual int f() { return 1; }
  long pad = 9;
};
struct Both : Other, Square {
  int area() const override { return 100; }
};
typedef int (Shape::*Area)() const;
typedef int (Shape::*Plain)(int) const;

[[gnu::noinline]] static int apply(const Shape &shape, Area area, Plain plain) {
  return (shape.*area)() + (shape.*plain)(10);
}

int Shape::*field = &Shape::tag;

static void members() {
  Square square;
  Both both;
  Shape shape;
  Area area = &Shape::area;
  Plain plain = &Shape::plain;
  std::printf("%d %d %d\n", apply(shape, area, plain), apply(square, area, plain), apply(both, area, plain));
  int (Square::*twice)(int) const = &Square::twice;
  int (Both::*up)(int) const = twice;
  std::printf("%d %d\n", (square.*twice)(4), (both.*up)(4));
  std::printf("%d %d %d\n", area == &Shape::area, plain != nullptr, square.*field);
  auto bound = std::mem_fn(&Square::twice);
  std::function<int(const Square &, int)> wrapped = &Square::twice;
  std::printf("%d %d\n", bound(square, 1), wrapped(square, 2));
  Area none = nullptr;
  std::printf("%d\n", none == nullptr);
  // A table of them, chosen at run time.
  static const Plain table[] = {&Shape::plain, static_cast<Plain>(&Square::twice)};
  volatile int index = 1;
  std::printf("%d\n", (square.*table[index])(20));
}

static std::atomic<int> constructions;

struct Slow {
  int value;
  Slow() {
    ++constructions;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    value = 42;
  }
};

static Slow &shared() {
  static Slow slow;
  return slow;
}

static int attempts;

static int &fragile() {
  static int value = ++attempts < 3 ? throw std::runtime_error("not yet") : attempts * 10;
  return value;
}

static void statics() {
  std::atomic<int> sum{0};
  std::vector<std::thread> threads;
  for (int index = 0; index < 8; ++index)
    threads.emplace_back([&] { sum += shared().value; });
  for (std::thread &thread : threads)
    thread.join();
  std::printf("%d constructed, sum %d\n", constructions.load(), sum.load());
  for (int round = 0; round < 4; ++round) {
    try {
      std::printf("%d\n", fragile());
    } catch (const std::runtime_error &error) {
      std::printf("%s\n", error.what());
    }
  }
  std::printf("%d attempts\n", attempts);
}

static int handled;

// Out of line, so that the compiler does not drop the allocation with its
// release.
[[gnu::noinline]] static char *grab(std::size_t count) { return new char[count]; }

static void storage() {
  // More than any heap has.
  std::size_t huge = SIZE_MAX / 4;
  try {
    char *bytes = grab(huge);
    std::puts("allocated");
    delete[] bytes;
  } catch (const std::bad_alloc &) {
    std::puts("bad_alloc");
  }
  std::printf("%d\n", ::operator new(huge, std::nothrow) == nullptr);
  char *small = grab(100);
  small[99] = 7;
  std::printf("%d\n", small[99]);
  delete[] small;
  // A handler is asked for more first, as long as there is one.
  std::set_new_handler([] {
    ++handled;
    std::set_new_handler(nullptr);
  });
  try {
    delete[] grab(huge);
  } catch (const std::bad_alloc &) {
    std::printf("bad_alloc after %d\n", handled);
  }
}

int main() {
  members();
  statics();
  storage();
}
