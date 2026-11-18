// A program that needs `geometry`: a member function and a function of a
// namespace, both of another module.
#include <cstdio>

namespace geometry {
struct Box {
  int width, height;
  int area() const;
};
int total(const Box *boxes, int count);
}  // namespace geometry

int main() {
  geometry::Box boxes[3] = {{1, 2}, {3, 4}, {5, 6}};
  std::printf("%d %d\n", boxes[1].area(), geometry::total(boxes, 3));
  return 0;
}
