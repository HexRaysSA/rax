// Native binary32/64 oracle. Strict FP compilation and observable fenv required.
#pragma STDC FENV_ACCESS ON
#include <bit>
#include <cfenv>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

template<class Float, class UInt>
void evaluate(const std::string &op, UInt a_bits, UInt b_bits, UInt c_bits) {
    volatile Float a = std::bit_cast<Float>(a_bits);
    volatile Float b = std::bit_cast<Float>(b_bits);
    volatile Float c = std::bit_cast<Float>(c_bits);
    std::feclearexcept(FE_ALL_EXCEPT);
    Float result;
    if (op == "add") {
        result = a + b;
    } else if (op == "sub") {
        result = a - b;
    } else if (op == "mul") {
        result = a * b;
    } else if (op == "div") {
        result = a / b;
    } else if (op == "fma") {
        result = std::fma(a, b, c);
    } else {
        throw std::runtime_error("unknown operation");
    }
    const int exceptions = std::fetestexcept(FE_ALL_EXCEPT);
    std::cout << std::hex << std::bit_cast<UInt>(result) << ' ';
    if (exceptions & FE_DIVBYZERO) std::cout << "divide_by_zero,";
    if (exceptions & FE_INEXACT) std::cout << "inexact,";
    if (exceptions & FE_INVALID) std::cout << "invalid,";
    if (exceptions & FE_OVERFLOW) std::cout << "overflow,";
    if (exceptions & FE_UNDERFLOW) std::cout << "underflow,";
    std::cout << '\n';
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        unsigned width;
        std::string op, rounding;
        std::uint64_t a, b, c;
        if (!(input >> std::dec >> width >> op >> rounding >> std::hex >> a >> b >> c)) {
            return 2;
        }
        const int mode = rounding == "nearest_even" ? FE_TONEAREST
            : rounding == "toward_zero" ? FE_TOWARDZERO
            : rounding == "upward" ? FE_UPWARD
            : rounding == "downward" ? FE_DOWNWARD : -1;
        if (mode < 0 || std::fesetround(mode) != 0) return 3;
        if (width == 32) {
            evaluate<float, std::uint32_t>(op, a, b, c);
        } else if (width == 64) {
            evaluate<double, std::uint64_t>(op, a, b, c);
        } else {
            return 4;
        }
    }
}
