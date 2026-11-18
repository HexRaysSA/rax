// The stream classes: formatted output to the standard streams and to
// strings, with the manipulators for base, width, fill and precision, and
// formatted input from a string, including what fails to parse.
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

struct Point {
  int x, y;
};

std::ostream &operator<<(std::ostream &out, const Point &point) { return out << '(' << point.x << ", " << point.y << ')'; }

int main() {
  std::ostringstream text;
  text << "dec " << 255 << " hex " << std::hex << std::showbase << 255 << " oct " << std::oct << 8 << std::dec
       << std::noshowbase << '\n';
  text << std::setw(8) << std::setfill('.') << 42 << '|' << std::left << std::setw(8) << "ab" << '|' << std::right
       << std::setfill(' ') << '\n';
  text << std::fixed << std::setprecision(3) << 3.14159265 << ' ' << std::scientific << 12345.678 << ' '
       << std::defaultfloat << std::setprecision(6) << 0.1 + 0.2 << '\n';
  text << std::boolalpha << true << ' ' << false << ' ' << Point{3, -4} << ' ' << -1LL << ' ' << 18446744073709551615ULL
       << '\n';
  std::cout << text.str();

  std::istringstream input("12 -7 0x1f 2.5 word  spaced line\nsecond line\nnot-a-number 9");
  int first = 0, second = 0, third = 0;
  double real = 0;
  std::string word, rest, line;
  input >> first >> second >> std::hex >> third >> std::dec >> real >> word;
  std::getline(input, rest);
  std::getline(input, line);
  std::cout << first << ' ' << second << ' ' << third << ' ' << real << " [" << word << "] [" << rest << "] [" << line
            << "]\n";
  int failed = -1;
  input >> failed;
  std::cout << "failed " << input.fail() << ' ' << failed << " eof " << input.eof() << '\n';
  input.clear();
  std::string skipped;
  input >> skipped >> failed;
  std::cout << skipped << ' ' << failed << " eof " << input.eof() << '\n';

  std::vector<std::string> words;
  std::istringstream sentence("the quick brown fox");
  for (std::string each; sentence >> each;)
    words.push_back(each);
  std::cerr << "words " << words.size() << '\n';
  std::cout << words.back() << ' ' << words.front().size() << std::endl;
  return 0;
}
