// formatted [NAME...]: a table printed with a small printf. The exit status
// is the number of bytes printed, modulo 256.
#include "print.h"

#include <stdint.h>

struct planet {
  const char *name;
  double mass;
  double radius;
  int moons;
};

static const struct planet planets[] = {
    {"Mercury", 0.330, 2439.7, 0}, {"Venus", 4.87, 6051.8, 0},   {"Earth", 5.97, 6371.0, 1},
    {"Mars", 0.642, 3389.5, 2},    {"Jupiter", 1898.0, 69911.0, 95}, {"Saturn", 568.0, 58232.0, 146},
};

static double density(const struct planet *planet) {
  double radius = planet->radius * 1000.0;
  double volume = 4.0 / 3.0 * 3.141592653589793 * radius * radius * radius;
  return planet->mass * 1.0e24 / volume;
}

int main(int argc, char **argv) {
  int bytes = print("%10s %12s %10s %5s %s\n", "name", "mass", "radius", "moons", "density");
  for (unsigned i = 0; i < sizeof planets / sizeof planets[0]; i++) {
    const struct planet *planet = &planets[i];
    bytes += print("%10s %f %f %05d %f\n", planet->name, planet->mass, planet->radius, planet->moons,
                   density(planet));
  }
  bytes += print("integers: %d %i %u %x %ld %lu %lx %c%c %%\n", -42, 2147483647, 4000000000u, 0xbeefu,
                 -9000000000000000000L, 18446744073709551615ul, 0xfedcba9876543210ul, 'o', 'k');
  bytes += print("padding: [%5d] [%05d] [%3d] [%3x] [%08lx] [%2s] [%0d]\n", -42, -42, 7, 255, 0xabcdefL, "wide", 0);
  bytes += print("doubles: %f %f %f %f %f %f\n", 0.0, -1.5, 0.9999995, 123456.789, 1.0e-7, 1.0e30);
  bytes += print("nothing to convert, and a stray %");
  bytes += print("\n%d argument%s:", argc - 1, argc == 2 ? "" : "s");
  for (int i = 1; i < argc; i++)
    bytes += print(" [%s]", argv[i]);
  bytes += print("\n");
  return bytes & 0xff;
}
