// Run-time type information: `dynamic_cast` down, across and to the most
// derived object, through single, multiple and virtual inheritance, with
// the failures that give null or throw; `typeid` of objects and types, and
// the names it gives.
#include <cstdio>
#include <typeinfo>

struct Animal { virtual ~Animal() = default; int legs = 4; };
struct Dog : Animal { int tricks = 3; };
struct Puppy : Dog { int age = 1; };
struct Cat : Animal { int lives = 9; };

struct Swimmer { virtual ~Swimmer() = default; int depth = 20; };
struct Flyer { virtual ~Flyer() = default; int height = 300; };
struct Duck : Animal, Swimmer, Flyer { int quacks = 7; };

struct Root { virtual ~Root() = default; int id = 1; };
struct Left : virtual Root { int left = 2; };
struct Right : virtual Root { int right = 3; };
struct Diamond : Left, Right { int both = 4; };

static const char *kind(const Animal *animal) {
  if (dynamic_cast<const Puppy *>(animal)) return "puppy";
  if (dynamic_cast<const Dog *>(animal)) return "dog";
  if (dynamic_cast<const Cat *>(animal)) return "cat";
  if (dynamic_cast<const Duck *>(animal)) return "duck";
  return "animal";
}

int main() {
  Animal animal; Dog dog; Puppy puppy; Cat cat; Duck duck; Diamond diamond;
  const Animal *animals[] = {&animal, &dog, &puppy, &cat, &duck};
  for (const Animal *each : animals)
    std::printf("%s is %s, same type as dog %d, as itself %d\n", typeid(*each).name(), kind(each),
                typeid(*each) == typeid(Dog), typeid(*each) == typeid(*each));

  // Across the bases of one object, and back to the whole.
  Swimmer *swimmer = &duck;
  Flyer *flyer = dynamic_cast<Flyer *>(swimmer);
  Duck *whole = dynamic_cast<Duck *>(flyer);
  Animal *base = dynamic_cast<Animal *>(swimmer);
  std::printf("cross %d %d %d, most derived %d\n", flyer ? flyer->height : -1, whole ? whole->quacks : -1,
              base ? base->legs : -1, dynamic_cast<void *>(swimmer) == static_cast<void *>(&duck));
  std::printf("not a swimmer: %d\n", dynamic_cast<Swimmer *>(static_cast<Animal *>(&dog)) == nullptr);

  // Through a virtual base, to a sibling and down.
  Root *root = &diamond;
  Left *left = dynamic_cast<Left *>(root);
  Right *right = dynamic_cast<Right *>(left);
  Diamond *down = dynamic_cast<Diamond *>(root);
  std::printf("diamond %d %d %d %d\n", left ? left->left : -1, right ? right->right : -1, down ? down->both : -1,
              static_cast<Root *>(left) == static_cast<Root *>(right));

  // A reference that is not what it is cast to.
  try {
    Animal &reference = cat;
    Dog &wrong = dynamic_cast<Dog &>(reference);
    std::printf("unexpected %d\n", wrong.tricks);
  } catch (const std::bad_cast &) {
    std::printf("bad_cast\n");
  }
  // The type of what a null pointer points to.
  try {
    Animal *none = nullptr;
    std::printf("unexpected %s\n", typeid(*none).name());
  } catch (const std::bad_typeid &) {
    std::printf("bad_typeid\n");
  }
  std::printf("%s %s %s %d\n", typeid(int).name(), typeid(const char *).name(), typeid(Diamond).name(),
              typeid(int).before(typeid(int)));
  return 0;
}
