// Exceptions: a constructor that fails after some members are built, a
// handler that throws again, handlers that catch by base class, by pointer,
// by value and anything, exceptions the library throws, an exception kept
// and thrown again later, handlers inside handlers, and `new` giving its
// storage back when the constructor fails. Every object built is destroyed
// once, in the order the language says.
#include <cstdio>
#include <exception>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

static int live = 0;
struct Tracked {
  int id;
  explicit Tracked(int i) : id(i) { ++live; std::printf("+%d ", id); }
  Tracked(const Tracked &o) : id(o.id + 100) { ++live; std::printf("c%d ", id); }
  ~Tracked() { --live; std::printf("-%d ", id); }
};
struct Failing {
  Tracked a;
  Tracked b;
  Failing(int k) : a(k), b(k + 1) { if (k % 2) throw std::runtime_error("odd " + std::to_string(k)); }
};
struct Base { virtual ~Base() = default; virtual const char *who() const { return "base"; } };
struct Middle : Base { const char *who() const override { return "middle"; } };
struct Leaf : Middle { const char *who() const override { return "leaf"; } };

static void rethrower(int k) {
  try {
    Tracked t(50 + k);
    if (k == 0) throw Leaf();
    if (k == 1) throw std::out_of_range("range");
    if (k == 2) throw 3.5;
    if (k == 3) throw "text";
    if (k == 4) throw new Middle();
    std::vector<int> v(3);
    v.at(10) = 1;
  } catch (const std::logic_error &e) {
    std::printf("[logic %s] ", e.what());
    throw;
  } catch (double d) {
    std::printf("[double %.1f] ", d);
    throw std::runtime_error("from double");
  }
}

int main() {
  for (int k = 0; k < 4; ++k) {
    try {
      Failing f(k);
      std::printf("built %d ", k);
    } catch (const std::exception &e) {
      std::printf("caught %s ", e.what());
    }
    std::printf("live %d\n", live);
  }
  for (int k = 0; k < 6; ++k) {
    try {
      rethrower(k);
    } catch (const Middle &m) {
      std::printf("middle& %s", m.who());
    } catch (const Base *b) {
      std::printf("base* %s", b->who());
      delete b;
    } catch (const std::out_of_range &e) {
      std::printf("out_of_range %s", e.what());
    } catch (const std::exception &e) {
      std::printf("exception %s", e.what());
    } catch (const char *s) {
      std::printf("chars %s", s);
    } catch (...) {
      std::printf("anything");
    }
    std::printf(" | live %d uncaught %d\n", live, std::uncaught_exceptions());
  }
  // An exception kept and thrown again later; nested handlers.
  std::exception_ptr kept;
  try {
    try {
      throw std::invalid_argument("inner");
    } catch (...) {
      kept = std::current_exception();
      try {
        throw std::length_error("second");
      } catch (const std::length_error &e) {
        std::printf("nested %s ", e.what());
      }
      throw;
    }
  } catch (const std::invalid_argument &e) {
    std::printf("outer %s\n", e.what());
  }
  try {
    std::rethrow_exception(kept);
  } catch (const std::logic_error &e) {
    std::printf("kept %s\n", e.what());
  }
  // new that fails in a constructor gives its storage back.
  try {
    std::unique_ptr<Failing> p(new Failing(7));
  } catch (const std::runtime_error &e) {
    std::printf("new: %s live %d\n", e.what(), live);
  }
  return 0;
}
