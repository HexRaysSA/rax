// Conversions between numbers and text, formatting, and regular
// expressions: the parts of the library that are compiled separately and
// that the stream classes do not need.
#include <charconv>
#include <cstdio>
#include <format>
#include <print>
#include <regex>
#include <string>
#include <system_error>
#include <vector>

static void conversions() {
  char buffer[96];
  const double values[] = {0.0, -0.0, 1.0, 3.14159, 1e100, 2.5e-7, 123456789.125, 0.1};
  for (double value : values) {
    auto shortest = std::to_chars(buffer, buffer + sizeof buffer, value);
    *shortest.ptr = 0;
    std::printf("%s", buffer);
    auto scientific = std::to_chars(buffer, buffer + sizeof buffer, value, std::chars_format::scientific, 4);
    *scientific.ptr = 0;
    std::printf(" %s", buffer);
    auto fixed = std::to_chars(buffer, buffer + sizeof buffer, static_cast<float>(value), std::chars_format::fixed);
    *fixed.ptr = 0;
    std::printf(" %s\n", buffer);
  }
  const char *texts[] = {"2.5e3", "-0.125", "1e400", "nope", "42 tail", "0x1p4"};
  for (const char *text : texts) {
    double parsed = -1;
    std::string_view view(text);
    auto result = std::from_chars(view.data(), view.data() + view.size(), parsed);
    // What is left in `parsed` when the value is out of range has changed
    // between versions of the library.
    bool range = result.ec == std::errc::result_out_of_range;
    std::printf("%s -> %g (%d%d%d, %d)\n", text, range ? 0.0 : parsed, result.ec == std::errc(), range,
                result.ec == std::errc::invalid_argument, static_cast<int>(result.ptr - view.data()));
  }
  int integer = 0;
  auto overflow = std::from_chars("99999999999", "99999999999" + 11, integer);
  std::printf("%d %d\n", integer, overflow.ec == std::errc::result_out_of_range);
  auto hex = std::to_chars(buffer, buffer + sizeof buffer, 0xdeadbeefu, 16);
  *hex.ptr = 0;
  std::printf("%s\n", buffer);
}

struct Point {
  int x, y;
};

template <> struct std::formatter<Point> : std::formatter<int> {
  auto format(const Point &point, std::format_context &context) const {
    auto out = std::format_to(context.out(), "(");
    out = std::formatter<int>::format(point.x, context);
    out = std::format_to(out, ", ");
    context.advance_to(out);
    out = std::formatter<int>::format(point.y, context);
    return std::format_to(out, ")");
  }
};

static void formatting() {
  std::string line = std::format("{:>8}|{:<6}|{:^7}|", "right", "left", "mid");
  std::puts(line.c_str());
  std::puts(std::format("{:#x} {:#o} {:#b} {:+d} {:05d} {:c}", 255, 8, 5, 7, -42, 65).c_str());
  std::puts(std::format("{:.3f} {:e} {:g} {:10.2f}| {}", 2.0 / 3, 12345.678, 0.00001234, 3.14159, 1e21).c_str());
  std::puts(std::format("{} {} {:s} {}", true, 'x', "text", static_cast<void *>(nullptr)).c_str());
  std::puts(std::format("{1} {0} {1}", "a", "b").c_str());
  std::puts(std::format("{:03} {}", Point{1, 2}, Point{-3, 4}).c_str());
  std::puts(std::format("{}", std::vector<int>{1, 2, 3}).c_str());
  std::puts(std::format("{:*^12.3}", 3.14159f).c_str());
  try {
    std::string spec = "{:d}";
    std::puts(std::vformat(spec, std::make_format_args("text")).c_str());
  } catch (const std::format_error &error) {
    std::puts("format_error");
  }
  std::println("{} + {} = {}", 1, 2, 3);
  std::print("{:6.2f}|{:<4}|\n", 3.14159, 7);
  std::println(stderr, "to the error stream: {}", 404);
}

static void expressions() {
  std::regex word("([a-z]+)-(\\d+)");
  std::string text = "alpha-12 beta-7 gamma delta-100";
  for (std::sregex_iterator it(text.begin(), text.end(), word), end; it != end; ++it)
    std::printf("%s=%s at %d\n", (*it)[1].str().c_str(), (*it)[2].str().c_str(), static_cast<int>(it->position()));
  std::puts(std::regex_replace(text, word, "$2:$1").c_str());
  std::printf("%d %d\n", std::regex_match("2026-11-18", std::regex("\\d{4}-\\d{2}-\\d{2}")),
              std::regex_match("2026-11-1", std::regex("\\d{4}-\\d{2}-\\d{2}")));
  std::smatch found;
  std::string mail = "write to someone@example.org today";
  if (std::regex_search(mail, found, std::regex("(\\w+)@(\\w+)\\.([a-z]+)", std::regex::icase)))
    std::printf("%s | %s | %s | %s\n", found[1].str().c_str(), found[2].str().c_str(), found[3].str().c_str(),
                found.suffix().str().c_str());
  try {
    std::regex broken("(unclosed");
    std::puts("accepted");
  } catch (const std::regex_error &error) {
    std::printf("regex_error %d\n", error.code() == std::regex_constants::error_paren);
  }
  std::regex separators("[,;]\\s*");
  std::string list = "one, two;three,  four";
  for (std::sregex_token_iterator it(list.begin(), list.end(), separators, -1), end; it != end; ++it)
    std::printf("[%s]", it->str().c_str());
  std::puts("");
}

int main() {
  conversions();
  formatting();
  expressions();
}
