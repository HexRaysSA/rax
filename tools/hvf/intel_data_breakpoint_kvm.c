/* Independent guest data-breakpoint observations. No RAX library is linked.
 * SDM086 Vol.3B 19.2.1, 19.2.4-19.2.6 and 19.3.1.2.
 * Reuse the bounded protected-mode fixture and its checked resource operations.
 */
#define main reserved_fixture_main
#include "intel_reserved_msr_kvm.c"
#undef main

#define DATA 0x4000
extern const unsigned char data_db_start[], data_db_end[];
__asm__(
    ".section .rodata\n.code32\n.global data_db_start,data_db_end\n"
    "data_db_start:\n"
    "push %eax\nincl 0x6000\n"
    "mov 4(%esp),%eax\nmov %eax,0x6004\n"
    "mov 12(%esp),%eax\nmov %eax,0x6008\n"
    "mov %dr6,%eax\nmov %eax,0x600c\n"
    "mov $0x400,%eax\nmov %eax,%dr7\n"
    "andl $0xfffffeff,12(%esp)\n"
    "pop %eax\niret\n"
    "data_db_end:\n.code64\n.text\n");

static int data_case(int kvm, unsigned index, unsigned size, unsigned watch_size,
                      unsigned offset, unsigned slot, unsigned enabled,
                      unsigned rw, unsigned action, unsigned tf, unsigned rf)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create data VM");
    require(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create data irqchip");
    unsigned char *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(ram != MAP_FAILED, "data RAM");
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM_SIZE,
        .userspace_addr = (uintptr_t)ram,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "map data RAM");
    memset(ram + DATA, 0x55, 32);
    unsigned char instruction[16];
    size_t length = 0;
    if (size == 8) {
        /* MOVQ XMM0,[disp32] / MOVQ [disp32],XMM0 in protected mode. */
        instruction[length++] = action == 0 ? 0xf3 : 0x66;
        instruction[length++] = 0x0f;
        instruction[length++] = action == 0 ? 0x7e : 0xd6;
        instruction[length++] = 0x05;
    } else if (action >= 2) {
        if (size == 2) instruction[length++] = 0x66;
        instruction[length++] = size == 1 ? 0xc0 : 0xc1;
        instruction[length++] = 0x25; /* SHL [disp32], imm8. */
    } else {
        if (size == 2) instruction[length++] = 0x66;
        instruction[length++] = (unsigned char)((size == 1 ? 0xa0 : 0xa1) + (action ? 2 : 0));
    }
    put32(instruction, length, DATA + offset);
    length += 4;
    if (action >= 2) instruction[length++] = action == 2 ? 0 : 1;
    memcpy(ram + CODE, instruction, length);
    const unsigned char finish[] = {0xbb, 0xaa, 0x55, 0xaa, 0x55, 0xe6, 0xe9, 0xf4};
    memcpy(ram + CODE + length, finish, sizeof(finish));
    require((uintptr_t)data_db_end >= (uintptr_t)data_db_start, "data handler order");
    size_t handler_size = (size_t)((uintptr_t)data_db_end - (uintptr_t)data_db_start);
    require(handler_size < 0x100, "data handler bounds");
    memcpy(ram + HANDLER, data_db_start, handler_size);
    uint64_t gate = (HANDLER & 0xffffu) | (UINT64_C(8) << 16) | (UINT64_C(0x8e) << 40)
                    | ((uint64_t)(HANDLER >> 16) << 48);
    memcpy(ram + IDT + 8, &gate, sizeof(gate));
    const uint64_t descriptors[] = {0, UINT64_C(0x00cf9b000000ffff), UINT64_C(0x00cf93000000ffff)};
    memcpy(ram + GDT, descriptors, sizeof(descriptors));
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create data CPU");
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(bytes > 0, "data run size");
    struct kvm_run *run = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    require(run != MAP_FAILED, "data run mapping");
    struct kvm_sregs sr;
    require(ioctl(cpu, KVM_GET_SREGS, &sr) == 0, "get data segments");
    struct kvm_segment segment = {
        .base = 0, .limit = UINT32_MAX, .selector = 16, .type = 3,
        .present = 1, .db = 1, .s = 1, .g = 1,
    };
    sr.cs = segment;
    sr.cs.selector = 8;
    sr.cs.type = 11;
    sr.ds = sr.es = sr.ss = sr.fs = sr.gs = segment;
    sr.cr0 = 0x60000031;
    sr.cr3 = sr.efer = 0;
    sr.cr4 = 0x608; /* DE plus OSFXSR/OSXMMEXCPT for the 8-byte MOVQ controls. */
    sr.gdt.base = GDT;
    sr.gdt.limit = sizeof(descriptors) - 1;
    sr.idt.base = IDT;
    sr.idt.limit = 256 * 8 - 1;
    require(ioctl(cpu, KVM_SET_SREGS, &sr) == 0, "set data segments");
    unsigned len = watch_size == 1 ? 0 : watch_size == 2 ? 1 : watch_size == 4 ? 3 : 2;
    uint64_t dr7 = 0x400 | ((uint64_t)enabled << (slot * 2))
                   | ((uint64_t)(rw | (len << 2)) << (16 + slot * 4));
    struct kvm_debugregs debug = {.dr6 = 0xffff0ff0, .dr7 = dr7};
    debug.db[slot] = DATA + 8;
    require(ioctl(cpu, KVM_SET_DEBUGREGS, &debug) == 0, "set data debug registers");
    struct kvm_regs regs = {
        .rip = CODE, .rsp = 0xf000, .rflags = 2 | (tf << 8) | (rf << 16), .rax = LOW,
    };
    require(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set data registers");
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "execute data guest");
    alarm(0);
    require(run->exit_reason == KVM_EXIT_IO && run->io.port == 0xe9 &&
            run->io.direction == KVM_EXIT_IO_OUT, "data guest completion");
    require(ioctl(cpu, KVM_GET_REGS, &regs) == 0 && regs.rbx == MARKER, "data marker");
    uint32_t observed[4];
    memcpy(observed, ram + OBSERVATIONS, sizeof(observed));
    int overlap = offset < 8 + watch_size && offset + size > 8;
    int hit = enabled != 0 && overlap && (rw == 3 || (rw == 1 && action != 0));
    int passed = observed[0] == (unsigned)(hit || tf);
    if (hit || tf) {
        passed = passed && observed[1] == CODE + length && (observed[2] & 0x10100) == (tf << 8)
                 && (!enabled || (observed[3] & (1u << slot)) == (hit ? 1u << slot : 0))
                 && (observed[3] & 0x4000) == (tf ? 0x4000 : 0);
    }
    printf("{\"case\":%u,\"size\":%u,\"watch_size\":%u,\"offset\":%u,\"slot\":%u,"
           "\"enabled\":%u,\"rw\":%u,\"action\":%u,\"tf\":%u,\"rf\":%u,\"dr7\":%llu,"
           "\"db_count\":%u,\"saved_rip\":%u,\"saved_flags\":%u,\"dr6\":%u,\"passed\":%s}\n",
           index, size, watch_size, offset, slot, enabled, rw, action, tf, rf,
           (unsigned long long)dr7, observed[0], observed[1], observed[2], observed[3],
           passed ? "true" : "false");
    require(fflush(stdout) == 0, "retain data observation");
    require(munmap(run, (size_t)bytes) == 0 && close(cpu) == 0 && close(vm) == 0 &&
            munmap(ram, RAM_SIZE) == 0, "release data resources");
    return passed;
}

int main(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "data KVM API");
    unsigned index = 0;
    unsigned failures = 0;
    const unsigned widths[] = {1, 2, 4, 8};
    const unsigned offsets[] = {0, 7, 8, 9, 15, 16};
    for (unsigned size = 0; size < 4; size++) {
        for (unsigned watch = 0; watch < 4; watch++) {
            for (unsigned offset = 0; offset < 6; offset++) {
                for (unsigned action = 0; action < (size == 3 ? 2u : 4u); action++) {
                    failures += !data_case(kvm, index, widths[size], widths[watch], offsets[offset],
                              index % 4, (index / 16) % 4, 1 + 2 * ((index / 4) % 2), action,
                              (index / 4) % 2, (index / 8) % 2);
                    index++;
                }
            }
        }
    }
    require(close(kvm) == 0, "release data KVM");
    fprintf(stderr, "data-breakpoint cases=%u mismatches=%u\n", index, failures);
    return failures == 0 ? 0 : 3;
}
