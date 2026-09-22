// Scalar register values use native C++ types; raw buffers use little-endian
// register bytes on every host. Compare the two interfaces independently.
#include "rax.hpp"
#include <array>
#include <cstdio>

int main() {
    try {
        rax::Engine e(rax::Arch::X86, RAX_MODE_64);
        e.setReg<uint32_t>(RAX_X86_REG_EAX, 0x12345678u);
        if (e.regU64(RAX_X86_REG_RAX) != 0x12345678u) return 1;
        if (e.regBytes(RAX_X86_REG_EAX) != std::vector<uint8_t>{0x78, 0x56, 0x34, 0x12}) return 2;
        e.setReg(RAX_X86_REG_RAX, uint64_t(0x8877665544332211ULL));
        if (e.reg<uint64_t>(RAX_X86_REG_RAX) != 0x8877665544332211ULL) return 3;
        if (e.reg<uint32_t>(RAX_X86_REG_EAX) != 0x44332211u) return 4;
        if (e.reg<uint16_t>(RAX_X86_REG_AX) != 0x2211u) return 5;
        if (e.reg<uint8_t>(RAX_X86_REG_AL) != 0x11u) return 6;
        e.setReg<int16_t>(RAX_X86_REG_AX, -2);
        if (e.regU64(RAX_X86_REG_AX) != 0xfffeu || e.reg<int16_t>(RAX_X86_REG_AX) != -2) return 7;
        // Marshaling must preserve representations, including signed zero,
        // subnormals, infinities, and quiet/signaling NaN payloads. No FP
        // arithmetic participates in these expected results.
        for (uint32_t bits : {0u, 0x80000000u, 1u, 0x007fffffu, 0x00800000u,
                              0x3f800000u, 0x7f800000u, 0xff800000u, 0x7fc12345u, 0x7f812345u}) {
            float value;
            std::memcpy(&value, &bits, sizeof(value));
            e.setReg<float>(RAX_X86_REG_EAX, value);
            if (e.regU64(RAX_X86_REG_EAX) != bits) return 8;
            value = e.reg<float>(RAX_X86_REG_EAX);
            uint32_t observed;
            std::memcpy(&observed, &value, sizeof(observed));
            if (observed != bits) return 9;
        }
        for (uint64_t bits : {0ULL, 0x8000000000000000ULL, 1ULL, 0x000fffffffffffffULL,
                              0x0010000000000000ULL, 0xc000000000000000ULL,
                              0x7ff0000000000000ULL, 0xfff0000000000000ULL,
                              0x7ff8123456789abcULL, 0x7ff0123456789abcULL}) {
            double value;
            std::memcpy(&value, &bits, sizeof(value));
            e.setReg<double>(RAX_X86_REG_RAX, value);
            if (e.regU64(RAX_X86_REG_RAX) != bits) return 10;
            value = e.reg<double>(RAX_X86_REG_RAX);
            uint64_t observed;
            std::memcpy(&observed, &value, sizeof(observed));
            if (observed != bits) return 11;
        }
        enum class Scalar : uint32_t { Value = 0x12345678u };
        e.setReg<Scalar>(RAX_X86_REG_EAX, Scalar::Value);
        if (e.regU64(RAX_X86_REG_EAX) != 0x12345678u || e.reg<Scalar>(RAX_X86_REG_EAX) != Scalar::Value) return 12;
        const std::array<uint8_t, 16> bytes{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        e.setReg(RAX_X86_XMM(0), bytes);
        if (e.reg<std::array<uint8_t, 16>>(RAX_X86_XMM(0)) != bytes) return 13;
        std::puts("scalar and raw register byte order: OK");
        return 0;
    } catch (const rax::Error& err) {
        std::fprintf(stderr, "%s\n", err.what());
        return 14;
    }
}
