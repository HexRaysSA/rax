#include "codec.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 3;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        return 3;
    }
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    auto result = rax::smir::framing::decode(bytes);
    if (result.error != 0) {
        std::cout << "SMIR-E" << std::setfill('0') << std::setw(3)
                  << result.error << '\n';
        return 2;
    }
    std::cout << "OK " << result.kind << ' ' << result.entry << '\n';
    for (const auto &section : result.sections) {
        std::cout << std::dec << section.kind << ' ' << section.required << ' ';
        for (auto byte : section.payload) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << static_cast<unsigned>(byte);
        }
        std::cout << '\n';
    }
}
