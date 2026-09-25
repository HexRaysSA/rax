// SPDX-License-Identifier: MIT
/*
 * Setjmp/longjmp threaded bytecode VM.
 *
 * This stays within portable C11 control-flow constructs while still making
 * dispatch awkward: every interpreter state is a saved continuation, and the
 * bytecode handlers bounce between them with longjmp instead of a loop.
 */

#include <inttypes.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    SLOT_BOOT = 0,
    SLOT_FETCH,
    SLOT_ALU,
    SLOT_MEM,
    SLOT_BRANCH,
    SLOT_CALL,
    SLOT_TWIST,
    SLOT_HALT,
    SLOT_COUNT
} JumpSlot;

typedef enum {
    OP_LIT = 1,
    OP_ALU,
    OP_MEM,
    OP_JUMP,
    OP_JZ,
    OP_LOOP,
    OP_CALL,
    OP_RET,
    OP_TWIST,
    OP_HALT
} Opcode;

typedef struct {
    uint8_t op;
    uint8_t arg;
} Insn;

typedef struct {
    uint8_t ret_pc;
    uint32_t salt;
} Frame;

typedef struct {
    jmp_buf env[SLOT_COUNT];
    uint32_t regs[4];
    uint32_t stack[16];
    uint32_t mem[16];
    Frame frames[4];
    uint32_t trace;
    uint32_t opcode;
    uint32_t operand;
    uint8_t pc;
    uint8_t sp;
    uint8_t fp;
    uint8_t loop;
    uint8_t fuel;
    uint8_t phase;
} Vm;

typedef uint32_t (*AluFn)(uint32_t, uint32_t);

volatile uint32_t cf_longjmp_threaded_vm_fence;
volatile uint64_t cf_longjmp_threaded_vm_sink;

static uint32_t rotl32(uint32_t value, unsigned amount) {
    amount &= 31u;
    return amount == 0u ? value : (value << amount) | (value >> (32u - amount));
}

static uint32_t mix32(uint32_t value) {
    value ^= value >> 16u;
    value *= UINT32_C(0x7feb352d);
    value ^= value >> 15u;
    value *= UINT32_C(0x846ca68b);
    value ^= value >> 16u;
    return value;
}

__attribute__((noinline))
static uint32_t alu_addfold(uint32_t a, uint32_t b) {
    return mix32(a + rotl32(b, 5u));
}

__attribute__((noinline))
static uint32_t alu_xorlace(uint32_t a, uint32_t b) {
    return rotl32(a ^ mix32(b + UINT32_C(0x9e3779b9)), (a >> 27u) + 1u);
}

__attribute__((noinline))
static uint32_t alu_mulbias(uint32_t a, uint32_t b) {
    return (a | 1u) * (b ^ UINT32_C(0x45d9f3b)) + rotl32(a, 11u);
}

__attribute__((noinline))
static uint32_t alu_mux(uint32_t a, uint32_t b) {
    uint32_t mask = 0u - ((a ^ b) & 1u);
    return (a & mask) | (rotl32(b, 13u) & ~mask);
}

static AluFn alu_table[4] = {
    alu_addfold,
    alu_xorlace,
    alu_mulbias,
    alu_mux
};

__attribute__((noinline))
static void vm_jump(Vm *vm, JumpSlot slot) {
    cf_longjmp_threaded_vm_fence = vm->trace ^ (uint32_t)slot;
    longjmp(vm->env[slot], (int)slot + 1);
}

static void push(Vm *vm, uint32_t value) {
    if (vm->sp < 16u) {
        vm->stack[vm->sp++] = value;
    } else {
        vm->trace ^= mix32(value ^ vm->stack[(value >> 3u) & 15u]);
    }
}

static uint32_t pop(Vm *vm) {
    if (vm->sp != 0u) {
        return vm->stack[--vm->sp];
    }
    vm->trace = mix32(vm->trace + UINT32_C(0x31415927));
    return vm->trace;
}

static void init_vm(Vm *vm, uint32_t seed) {
    vm->regs[0] = seed ^ UINT32_C(0x243f6a88);
    vm->regs[1] = mix32(seed + UINT32_C(0x85a308d3));
    vm->regs[2] = UINT32_C(0x13198a2e);
    vm->regs[3] = UINT32_C(0x03707344) ^ (seed << 1u);
    vm->trace = mix32(seed ^ UINT32_C(0xa4093822));
    vm->opcode = 0u;
    vm->operand = 0u;
    vm->pc = 0u;
    vm->sp = 0u;
    vm->fp = 0u;
    vm->loop = (uint8_t)(13u + (seed & 7u));
    vm->fuel = 0u;
    vm->phase = (uint8_t)((seed >> 5u) & 3u);

    for (uint32_t i = 0u; i < 16u; ++i) {
        vm->stack[i] = 0u;
        vm->mem[i] = mix32(seed + i * UINT32_C(0x10204081));
    }
    for (uint32_t i = 0u; i < 4u; ++i) {
        vm->frames[i].ret_pc = 0u;
        vm->frames[i].salt = mix32(seed ^ (i + UINT32_C(0x55aa00ff)));
    }
}

__attribute__((noinline))
static uint32_t run_threaded_vm(const Insn *code, uint8_t code_len, uint32_t seed) {
    static Vm vm;

    init_vm(&vm, seed);

    if (setjmp(vm.env[SLOT_BOOT]) != 0) {
        goto Boot;
    }
    if (setjmp(vm.env[SLOT_FETCH]) != 0) {
        goto Fetch;
    }
    if (setjmp(vm.env[SLOT_ALU]) != 0) {
        goto Alu;
    }
    if (setjmp(vm.env[SLOT_MEM]) != 0) {
        goto Mem;
    }
    if (setjmp(vm.env[SLOT_BRANCH]) != 0) {
        goto Branch;
    }
    if (setjmp(vm.env[SLOT_CALL]) != 0) {
        goto Call;
    }
    if (setjmp(vm.env[SLOT_TWIST]) != 0) {
        goto Twist;
    }
    if (setjmp(vm.env[SLOT_HALT]) != 0) {
        goto Halt;
    }
    vm_jump(&vm, SLOT_BOOT);

#define VM_BURN() do {                         \
        if (vm.fuel++ >= 220u) {               \
            vm_jump(&vm, SLOT_HALT);           \
        }                                      \
    } while (0)

Boot:
    VM_BURN();
    vm.trace ^= rotl32(vm.regs[0] + vm.regs[1], 7u);
    push(&vm, vm.trace ^ UINT32_C(0x6a09e667));
    vm_jump(&vm, SLOT_FETCH);

Fetch:
    VM_BURN();
    if (vm.pc >= code_len) {
        vm_jump(&vm, SLOT_HALT);
    } else {
        const Insn ins = code[vm.pc++];
        vm.opcode = ins.op;
        vm.operand = ins.arg;
        vm.phase = (uint8_t)((vm.phase + ins.op + (ins.arg & 3u)) & 3u);
        vm.trace += mix32(((uint32_t)ins.op << 8u) | ins.arg | vm.regs[vm.phase]);

        switch (ins.op) {
            case OP_LIT:
                push(&vm, mix32((uint32_t)ins.arg + vm.trace));
                vm_jump(&vm, (vm.trace & 8u) != 0u ? SLOT_TWIST : SLOT_FETCH);
            case OP_ALU:
                vm_jump(&vm, SLOT_ALU);
            case OP_MEM:
                vm_jump(&vm, SLOT_MEM);
            case OP_JUMP:
            case OP_JZ:
            case OP_LOOP:
                vm_jump(&vm, SLOT_BRANCH);
            case OP_CALL:
            case OP_RET:
                vm_jump(&vm, SLOT_CALL);
            case OP_TWIST:
                vm_jump(&vm, SLOT_TWIST);
            default:
                vm_jump(&vm, SLOT_HALT);
        }
    }

Alu:
    VM_BURN();
    {
        uint32_t b = pop(&vm);
        uint32_t a = pop(&vm);
        AluFn fn = alu_table[(vm.operand ^ vm.phase ^ vm.sp) & 3u];
        uint32_t out = fn(a ^ vm.regs[1], b + vm.regs[2]);
        uint32_t slot = (out ^ vm.operand ^ vm.trace) & 3u;

        vm.regs[slot] ^= out + rotl32(vm.trace, slot + 3u);
        vm.trace = mix32(vm.trace ^ out ^ vm.regs[(slot + 1u) & 3u]);
        push(&vm, out);

        switch ((out >> 29u) & 3u) {
            case 0u:
                vm_jump(&vm, SLOT_FETCH);
            case 1u:
                vm_jump(&vm, SLOT_MEM);
            case 2u:
                vm_jump(&vm, SLOT_TWIST);
            default:
                vm_jump(&vm, SLOT_FETCH);
        }
    }

Mem:
    VM_BURN();
    {
        uint32_t index = (vm.operand ^ vm.regs[0] ^ vm.trace) & 15u;
        uint32_t mode = (vm.operand >> 4u) & 3u;

        switch (mode) {
            case 0u:
                vm.mem[index] = pop(&vm) ^ rotl32(vm.trace, index & 15u);
                break;
            case 1u:
                push(&vm, vm.mem[index] + mix32(vm.regs[index & 3u]));
                break;
            case 2u:
                {
                    uint32_t other = (index + 7u + vm.phase) & 15u;
                    uint32_t tmp = vm.mem[index];
                    vm.mem[index] = vm.mem[other] ^ vm.trace;
                    vm.mem[other] = tmp + vm.regs[other & 3u];
                }
                break;
            default:
                vm.mem[index] ^= alu_table[index & 3u](vm.trace, vm.regs[vm.phase]);
                push(&vm, vm.mem[index]);
                break;
        }

        vm.trace ^= mix32(vm.mem[index] + index + vm.sp);
        if (((vm.trace ^ vm.regs[2]) & 11u) == 3u) {
            vm_jump(&vm, SLOT_TWIST);
        }
        vm_jump(&vm, SLOT_FETCH);
    }

Branch:
    VM_BURN();
    switch (vm.opcode) {
        case OP_JUMP:
            vm.pc = (uint8_t)(vm.operand % code_len);
            vm.trace ^= UINT32_C(0xb7e15162);
            vm_jump(&vm, SLOT_FETCH);
        case OP_JZ:
            if ((pop(&vm) & 1u) == 0u) {
                vm.pc = (uint8_t)(vm.operand % code_len);
                vm.trace += UINT32_C(0x9e3779b9);
                vm_jump(&vm, SLOT_TWIST);
            }
            vm_jump(&vm, SLOT_FETCH);
        case OP_LOOP:
            vm.loop = (uint8_t)(vm.loop - 1u);
            if (vm.loop != 0u) {
                vm.pc = (uint8_t)(vm.operand % code_len);
                vm.trace = rotl32(vm.trace ^ vm.loop, (vm.loop & 7u) + 1u);
                vm_jump(&vm, (vm.loop & 1u) != 0u ? SLOT_FETCH : SLOT_MEM);
            }
            vm_jump(&vm, SLOT_FETCH);
        default:
            vm_jump(&vm, SLOT_HALT);
    }

Call:
    VM_BURN();
    if (vm.opcode == OP_CALL) {
        if (vm.fp < 4u) {
            Frame *frame = &vm.frames[vm.fp++];
            frame->ret_pc = vm.pc;
            frame->salt = vm.trace ^ vm.regs[vm.fp & 3u];
            vm.pc = (uint8_t)(vm.operand % code_len);
            vm.trace += mix32(frame->salt + vm.fp);
            vm_jump(&vm, SLOT_FETCH);
        }
        vm_jump(&vm, SLOT_TWIST);
    } else {
        if (vm.fp != 0u) {
            Frame *frame = &vm.frames[--vm.fp];
            vm.pc = frame->ret_pc;
            vm.trace ^= mix32(frame->salt ^ vm.pc);
            vm_jump(&vm, SLOT_FETCH);
        }
        vm_jump(&vm, SLOT_HALT);
    }

Twist:
    VM_BURN();
    {
        uint32_t lane = (vm.operand + vm.phase + vm.fuel) & 3u;
        uint32_t folded = mix32(vm.trace ^ vm.regs[lane] ^ vm.mem[(vm.operand + lane) & 15u]);
        vm.regs[lane] = rotl32(vm.regs[lane] + folded, (vm.operand & 15u) + 1u);
        vm.mem[(folded >> 4u) & 15u] ^= vm.regs[lane] + vm.sp;
        push(&vm, folded ^ vm.regs[(lane + 1u) & 3u]);

        switch ((folded ^ vm.trace) & 7u) {
            case 0u:
            case 5u:
                vm_jump(&vm, SLOT_ALU);
            case 2u:
                vm_jump(&vm, SLOT_MEM);
            default:
                vm_jump(&vm, SLOT_FETCH);
        }
    }

Halt:
#undef VM_BURN
    {
        uint32_t out = vm.trace ^ ((uint32_t)vm.sp << 24u) ^ vm.loop;
        for (uint32_t i = 0u; i < 4u; ++i) {
            out ^= rotl32(vm.regs[i], i * 5u + 3u);
            out += mix32(vm.mem[i * 3u] ^ vm.mem[i * 3u + 1u]);
        }
        return mix32(out);
    }
}

int main(void) {
    static const Insn program[] = {
        {OP_LIT, 0x31u}, {OP_LIT, 0x07u}, {OP_ALU, 0x00u},
        {OP_MEM, 0x02u}, {OP_CALL, 0x12u}, {OP_MEM, 0x1du},
        {OP_ALU, 0x05u}, {OP_JZ, 0x0cu},  {OP_TWIST, 0xa3u},
        {OP_CALL, 0x18u}, {OP_LOOP, 0x04u}, {OP_JUMP, 0x1du},
        {OP_TWIST, 0x5eu}, {OP_MEM, 0x2bu}, {OP_ALU, 0x12u},
        {OP_LOOP, 0x06u}, {OP_HALT, 0x00u}, {OP_TWIST, 0x91u},
        {OP_LIT, 0x0bu}, {OP_ALU, 0x23u}, {OP_MEM, 0x35u},
        {OP_RET, 0x00u}, {OP_LIT, 0xc7u}, {OP_ALU, 0x31u},
        {OP_TWIST, 0x44u}, {OP_MEM, 0x4fu}, {OP_RET, 0x00u},
        {OP_LIT, 0x55u}, {OP_ALU, 0x02u}, {OP_HALT, 0x00u}
    };
    uint64_t checksum = UINT64_C(0xcbf29ce484222325);

    for (uint32_t round = 0u; round < 12u; ++round) { /* rax: was 64u */
        uint32_t seed = mix32((uint32_t)checksum ^ round * UINT32_C(0x9e3779b9));
        uint32_t out = run_threaded_vm(program, (uint8_t)(sizeof(program) / sizeof(program[0])), seed);
        checksum ^= (uint64_t)out + UINT64_C(0x100000001b3);
        checksum = (checksum << 9u) | (checksum >> 55u);
    }

    cf_longjmp_threaded_vm_sink = checksum;
    printf("cf_longjmp_threaded_vm %016" PRIx64 "\n", cf_longjmp_threaded_vm_sink);
    return 0;
}
