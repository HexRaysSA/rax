// Objects with static storage: their constructors run before `main` in the
// order they are written, their destructors after it in the reverse order,
// and a function's static object is constructed when control first passes
// it. Also arrays of objects made with `new`, and an object built in place.
#include <cstdio>
#include <new>

struct Noisy {
  const char *name;
  explicit Noisy(const char *n) : name(n) { std::printf("construct %s\n", name); }
  ~Noisy() { std::printf("destroy %s\n", name); }
};

static Noisy first("first");
static Noisy second("second");

static Noisy &lazy() {
  static Noisy instance("lazy");
  return instance;
}

struct Counted {
  static int alive;
  int value = 7;
  Counted() { ++alive; }
  ~Counted() { --alive; }
};
int Counted::alive = 0;

int main() {
  std::printf("main begins\n");
  lazy();
  lazy();
  Counted *several = new Counted[5];
  std::printf("alive %d\n", Counted::alive);
  delete[] several;
  alignas(Counted) unsigned char storage[sizeof(Counted)];
  Counted *placed = new (storage) Counted;
  std::printf("alive %d, value %d\n", Counted::alive, placed->value);
  placed->~Counted();
  std::printf("alive %d\nmain ends\n", Counted::alive);
  return 0;
}
