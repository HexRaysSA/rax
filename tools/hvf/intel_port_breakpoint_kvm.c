/* Independent 64-bit guest I/O debug observations, no RAX linked. */
#define main reserved_fixture_main
#include "intel_reserved_msr_kvm.c"
#undef main

extern const unsigned char port_db_start[], port_db_end[];
__asm__(
    ".section .rodata\n.code64\n.global port_db_start,port_db_end\n"
    "port_db_start:\n"
    "push %rax\nincq 0x6000\n"
    "mov 8(%rsp),%rax\nmov %rax,0x6008\n"
    "mov 24(%rsp),%rax\nmov %rax,0x6010\n"
    "mov %dr6,%rax\nmov %rax,0x6018\n"
    "mov $0x400,%eax\nmov %rax,%dr7\n"
    "andq $-257,24(%rsp)\n"
    "pop %rax\niretq\n"
    "port_db_end:\n.text\n");

static void port_case(int kvm, unsigned index, unsigned size, unsigned watch_size,
                      unsigned port, uint64_t address, unsigned slot, unsigned enabled,
                      unsigned rw, unsigned de, unsigned input, unsigned tf, unsigned rf)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create port VM");
    require(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create port irqchip");
    unsigned char *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(ram != MAP_FAILED, "port RAM");
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM_SIZE,
        .userspace_addr = (uintptr_t)ram,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "map port RAM");
    unsigned char instruction[2];
    unsigned length = 0;
    if (size == 2) {
        instruction[length++] = 0x66;
    }
    instruction[length++] = (unsigned char)((input ? 0xec : 0xee) + (size != 1));
    memcpy(ram + CODE, instruction, length);
    const unsigned char finish[] = {0xbb, 0xaa, 0x55, 0xaa, 0x55, 0xe6, 0xe9, 0xf4};
    memcpy(ram + CODE + length, finish, sizeof(finish));
    require((uintptr_t)port_db_end >= (uintptr_t)port_db_start, "port handler order");
    size_t handler_size = (size_t)((uintptr_t)port_db_end - (uintptr_t)port_db_start);
    require(handler_size < 0x100, "port handler bounds");
    memcpy(ram + HANDLER, port_db_start, handler_size);
    uint64_t gate[2] = {(HANDLER & 0xffffu) | (UINT64_C(8) << 16)
                      | (UINT64_C(0x8e) << 40) | ((uint64_t)(HANDLER >> 16) << 48), 0};
    memcpy(ram + IDT + 16, gate, sizeof(gate));
    const uint64_t descriptors[] = {0, UINT64_C(0x00af9b000000ffff), UINT64_C(0x00cf93000000ffff)};
    memcpy(ram + GDT, descriptors, sizeof(descriptors));
    const uint64_t tables[] = {0xa003, 0xb003, 0x83};
    for (unsigned i = 0; i < 3; i++) {
        memcpy(ram + 0x9000 + i * 0x1000, &tables[i], sizeof(uint64_t));
    }
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create port CPU");
    int bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(bytes > 0, "port run size");
    struct kvm_run *run = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    require(run != MAP_FAILED, "port run mapping");
    struct kvm_sregs sr;
    require(ioctl(cpu, KVM_GET_SREGS, &sr) == 0, "get port segments");
    struct kvm_segment data = {
        .base = 0, .limit = UINT32_MAX, .selector = 16, .type = 3,
        .present = 1, .db = 1, .s = 1, .g = 1,
    };
    sr.ds = sr.es = sr.ss = sr.fs = sr.gs = data;
    sr.cs = data;
    sr.cs.selector = 8;
    sr.cs.type = 11;
    sr.cs.db = 0;
    sr.cs.l = 1;
    sr.cr0 = 0x80000031;
    sr.cr3 = 0x9000;
    sr.cr4 = 0x20 | (de << 3);
    sr.efer = 0x500;
    sr.gdt.base = GDT;
    sr.gdt.limit = sizeof(descriptors) - 1;
    sr.idt.base = IDT;
    sr.idt.limit = 256 * 16 - 1;
    require(ioctl(cpu, KVM_SET_SREGS, &sr) == 0, "set port segments");
    unsigned len = watch_size == 1 ? 0 : watch_size == 2 ? 1 : watch_size == 4 ? 3 : 2;
    uint64_t dr7 = 0x400 | ((uint64_t)enabled << (slot * 2))
                   | ((uint64_t)(rw | (len << 2)) << (16 + slot * 4));
    struct kvm_debugregs debug = {.dr6 = 0xffff0ff0, .dr7 = dr7};
    debug.db[slot] = address;
    require(ioctl(cpu, KVM_SET_DEBUGREGS, &debug) == 0, "set port debug registers");
    struct kvm_regs regs = {
        .rip = CODE, .rsp = 0xf000, .rflags = 2 | (tf << 8) | (rf << 16),
        .rax = LOW, .rdx = port,
    };
    require(ioctl(cpu, KVM_SET_REGS, &regs) == 0, "set port registers");
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "execute port guest");
    alarm(0);
    require(run->exit_reason == KVM_EXIT_IO && run->io.port == port &&
            run->io.size == size && run->io.count == 1 &&
            run->io.direction == (input ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT), "port device frontier");
    uint64_t before;
    memcpy(&before, ram + OBSERVATIONS, sizeof(before));
    require(before == 0, "port trap must follow actual device completion");
    require(run->io.data_offset <= (uint64_t)bytes &&
            size <= (uint64_t)bytes - run->io.data_offset, "port payload bounds");
    if (input) {
        memset((unsigned char *)run + run->io.data_offset, 0x5a, size);
    }
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "complete port guest");
    alarm(0);
    require(run->exit_reason == KVM_EXIT_IO && run->io.port == 0xe9 &&
            run->io.direction == KVM_EXIT_IO_OUT, "port completion marker");
    require(ioctl(cpu, KVM_GET_REGS, &regs) == 0 && regs.rbx == MARKER, "port marker register");
    uint64_t observed[4];
    memcpy(observed, ram + OBSERVATIONS, sizeof(observed));
    require(observed[0] <= 1, "bounded port debug count");
    if (observed[0]) {
        require(observed[1] == CODE + length, "port debug saved IP");
        require((observed[2] & 0x10100) == (tf << 8), "port saved TF/RF");
    }
    printf("{\"case\":%u,\"size\":%u,\"watch_size\":%u,\"port\":%u,\"address\":%llu,"
           "\"slot\":%u,\"enabled\":%u,\"rw\":%u,\"de\":%u,\"input\":%u,\"tf\":%u,"
           "\"rf\":%u,\"dr7\":%llu,\"db_count\":%llu,\"saved_rip\":%llu,\"saved_flags\":%llu,"
           "\"dr6\":%llu,\"rax\":%llu}\n", index, size, watch_size, port,
           (unsigned long long)address, slot, enabled, rw, de, input, tf, rf,
           (unsigned long long)dr7, (unsigned long long)observed[0],
           (unsigned long long)observed[1], (unsigned long long)observed[2],
           (unsigned long long)observed[3], (unsigned long long)regs.rax);
    require(fflush(stdout) == 0, "retain port observation");
    require(munmap(run, (size_t)bytes) == 0 && close(cpu) == 0 && close(vm) == 0 &&
            munmap(ram, RAM_SIZE) == 0, "release port resources");
}

int main(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "port KVM API");
    unsigned index = 0;
    const unsigned widths[] = {1, 2, 4};
    const unsigned watches[] = {1, 2, 4, 8};
    const unsigned ports[] = {0x3f0, 0x3f7, 0x3f8, 0x3f9, 0x3ff, 0x400};
    for (unsigned s = 0; s < 3; s++) {
        for (unsigned w = 0; w < 4; w++) {
            for (unsigned p = 0; p < 6; p++) {
                for (unsigned input = 0; input < 2; input++) {
                    port_case(kvm, index, widths[s], watches[w], ports[p], 0x3f8,
                              index % 4, 1, 2, 1, input, 0, 1);
                    index++;
                }
            }
        }
    }
    for (unsigned s = 0; s < 3; s++) {
        for (unsigned rw = 0; rw < 4; rw++) {
            for (unsigned de = 0; de < 2; de++) {
                for (unsigned enable = 0; enable < 4; enable++) {
                    for (unsigned tf = 0; tf < 2; tf++) {
                        for (unsigned rf = 0; rf < 2; rf++) {
                            for (unsigned input = 0; input < 2; input++) {
                                port_case(kvm, index++, widths[s], 1, 0x3f8, 0x3f8,
                                          2, enable, rw, de, input, tf, rf);
                            }
                        }
                    }
                }
            }
        }
    }
    const uint64_t addresses[] = {0x3f8, 0x103f8, 0x1000003f8, 0};
    for (unsigned a = 0; a < 4; a++) {
        for (unsigned s = 0; s < 3; s++) {
            for (unsigned input = 0; input < 2; input++) {
                for (unsigned tf = 0; tf < 2; tf++) {
                    port_case(kvm, index++, widths[s], 1, 0x3f8, addresses[a], 1, 1, 2, 1,
                              input, tf, 1);
                }
            }
        }
    }
    require(close(kvm) == 0, "release port KVM");
    fprintf(stderr, "port-breakpoint observations=%u\n", index);
    return 0;
}
