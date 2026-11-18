// The library's file streams: files written and read as text and as bytes,
// positions, the states a stream gets into, and a stream that is both.
// Run in a directory of its own; what it leaves there is `report.txt` and
// `values.bin`.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

struct Entry {
  std::string name;
  int count;
  double weight;
};

static void text() {
  const std::vector<Entry> entries{{"alpha", 3, 1.5}, {"beta", 14, 0.25}, {"gamma", 159, 2.75}};
  {
    std::ofstream out("report.txt");
    out << "# name count weight\n";
    for (const Entry &entry : entries)
      out << std::left << std::setw(8) << entry.name << std::right << std::setw(5) << entry.count << ' '
          << std::fixed << std::setprecision(3) << entry.weight << '\n';
    std::cout << "written: " << out.good() << " at " << out.tellp() << '\n';
  }
  std::ifstream in("report.txt");
  std::string line;
  std::getline(in, line);
  std::cout << line << '\n';
  Entry entry;
  int total = 0;
  double weight = 0;
  while (in >> entry.name >> entry.count >> entry.weight) {
    total += entry.count;
    weight += entry.weight;
  }
  std::cout << total << ' ' << weight << " eof " << in.eof() << " fail " << in.fail() << '\n';
  // A stream that failed reads again once it is cleared and moved.
  in.clear();
  in.seekg(0);
  std::cout << std::count(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), '\n')
            << " lines\n";
  in.close();
  // Appending, and the whole file at once.
  std::ofstream("report.txt", std::ios::app) << "delta   26535 9.000\n";
  std::ifstream again("report.txt");
  std::stringstream whole;
  whole << again.rdbuf();
  std::cout << whole.str().size() << " bytes, last line: "
            << whole.str().substr(whole.str().rfind("delta")) ;
}

static void bytes() {
  std::vector<std::uint32_t> values(5000);
  for (std::size_t index = 0; index < values.size(); ++index)
    values[index] = static_cast<std::uint32_t>(index * 2654435761u);
  {
    std::ofstream out("values.bin", std::ios::binary);
    out.write(reinterpret_cast<const char *>(values.data()),
              static_cast<std::streamsize>(values.size() * sizeof values[0]));
  }
  std::ifstream in("values.bin", std::ios::binary | std::ios::ate);
  std::cout << "size " << in.tellg() << '\n';
  std::uint32_t value = 0;
  in.seekg(4321 * sizeof value);
  in.read(reinterpret_cast<char *>(&value), sizeof value);
  std::cout << (value == values[4321]) << ' ' << in.gcount() << '\n';
  in.seekg(-4, std::ios::end);
  in.read(reinterpret_cast<char *>(&value), sizeof value);
  std::cout << (value == values.back()) << '\n';
  // Past the end: fewer bytes than asked, and the stream says so.
  char more[8];
  in.read(more, sizeof more);
  std::cout << in.gcount() << " eof " << in.eof() << " fail " << in.fail() << '\n';
}

static void both() {
  std::fstream file("scratch.txt", std::ios::in | std::ios::out | std::ios::trunc);
  file << "0123456789";
  file.seekp(3);
  file << "abc";
  file.seekg(0);
  std::string content;
  file >> content;
  std::cout << content << '\n';
  file.close();
  std::cout << "is_open " << file.is_open() << '\n';
  std::remove("scratch.txt");
  // What is not there does not open, and says so without throwing.
  std::ifstream missing("scratch.txt");
  std::cout << "missing: open " << missing.is_open() << " fail " << missing.fail() << '\n';
  // Unless it is asked to.
  std::ifstream strict;
  strict.exceptions(std::ios::failbit);
  try {
    strict.open("scratch.txt");
    std::cout << "opened\n";
  } catch (const std::ios_base::failure &) {
    std::cout << "failure thrown\n";
  }
}

int main() {
  text();
  bytes();
  both();
}
