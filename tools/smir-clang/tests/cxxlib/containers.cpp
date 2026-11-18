// The containers and vocabulary types of the C++ library: a vector that is
// sorted and summed, strings that grow, a map keyed by strings, owning
// pointers to a class with virtual functions, a function object, an
// optional, a variant and a tuple.
#include <algorithm>
#include <array>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

struct Shape {
  virtual ~Shape() = default;
  virtual double area() const = 0;
};
struct Square : Shape {
  double side;
  explicit Square(double s) : side(s) {}
  double area() const override { return side * side; }
};

int main() {
  std::vector<int> numbers;
  for (int i = 0; i < 100; ++i) numbers.push_back((i * 37) % 101);
  std::sort(numbers.begin(), numbers.end());
  long sum = std::accumulate(numbers.begin(), numbers.end(), 0L);
  std::string text = "hello";
  text += ", world";
  text.append(std::to_string(sum));
  std::map<std::string, int> counts;
  for (char c : text) counts[std::string(1, c)]++;
  std::unique_ptr<Shape> shape = std::make_unique<Square>(3.0);
  std::function<int(int)> twice = [](int x) { return 2 * x; };
  std::optional<int> maybe = twice(21);
  std::variant<int, std::string> either = text;
  std::tuple<int, double> pair{numbers[50], shape->area()};
  std::printf("%s %zu %ld %d %zu %d %.1f %zu\n", text.c_str(), counts.size(), sum, *maybe,
              std::get<std::string>(either).size(), std::get<0>(pair), std::get<1>(pair), numbers.size());
  return 0;
}
