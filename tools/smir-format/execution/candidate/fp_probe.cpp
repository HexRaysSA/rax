// Independent strict native sqrt/fmod/conversion witness; no portable JIT claim.
#pragma STDC FENV_ACCESS ON
#include <bit>
#include <cfenv>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

template<class Float, class UInt>
void probe(const std::string &op, UInt left, UInt right) {
    volatile Float a = std::bit_cast<Float>(left);
    volatile Float b = std::bit_cast<Float>(right);
    std::feclearexcept(FE_ALL_EXCEPT);
    Float result = op == "sqrt" ? std::sqrt(a) : std::fmod(a, b);
    const int flags = std::fetestexcept(FE_ALL_EXCEPT);
    std::cout << std::hex << std::bit_cast<UInt>(result) << ' ';
    if (flags & FE_DIVBYZERO) std::cout << "divide_by_zero,";
    if (flags & FE_INEXACT) std::cout << "inexact,";
    if (flags & FE_INVALID) std::cout << "invalid,";
    if (flags & FE_OVERFLOW) std::cout << "overflow,";
    if (flags & FE_UNDERFLOW) std::cout << "underflow,";
    std::cout << '\n';
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        unsigned width;
        std::string op, mode;
        std::uint64_t a, b;
        if (!(input >> std::dec >> width >> op >> mode >> std::hex >> a >> b)) return 2;
        const int rounding = mode == "nearest_even" ? FE_TONEAREST
            : mode == "toward_zero" ? FE_TOWARDZERO
            : mode == "upward" ? FE_UPWARD : mode == "downward" ? FE_DOWNWARD : -1;
        if (rounding < 0 || std::fesetround(rounding) != 0) return 3;
        if (width == 32) probe<float, std::uint32_t>(op, a, b);
        else if (width == 64) probe<double, std::uint64_t>(op, a, b);
        else return 4;
    }
}
