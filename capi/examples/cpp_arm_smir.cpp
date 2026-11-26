#include "rax.hpp"
#include <cassert>
#include <iostream>
int main() {
    const unsigned char bytes[] = {0x03,0x10,0xc1,0xa8};
    auto lifted = rax::liftArm(rax::Arch::Arm64, RAX_MODE_LITTLE_ENDIAN, 0x14, bytes, sizeof(bytes));
    assert(lifted.instruction.flags == RAX_SMIR_COMPLETE);
    assert(!lifted.operations.empty() && lifted.operations[0].opcode == RAX_SMIR_LOAD_PAIR);
    std::cout << "C++ ARM SMIR: " << lifted.operations.size() << " operations\n";
    const unsigned char conditional[] = {0x38,0x00,0x9f,0x05};
    auto guarded = rax::liftArm(rax::Arch::Arm, RAX_MODE_ARM, 0x1054, conditional, sizeof(conditional));
    assert(guarded.operations.size() == 2 && guarded.operations[0].opcode == RAX_SMIR_GUARD_CC);
}
