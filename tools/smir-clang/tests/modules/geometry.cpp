// A module in C++: its functions are known to others by their mangled names.
namespace geometry {
struct Box {
  int width, height;
  int area() const;
};
int Box::area() const { return width * height; }
int total(const Box *boxes, int count) {
  int sum = 0;
  for (int index = 0; index < count; ++index)
    sum += boxes[index].area();
  return sum;
}
}  // namespace geometry
