// Independent CPL0 guest MSR fault observations. KVM supplies the MSR policy;
// this neither links RAX nor qualifies Intel macOS Hypervisor.framework.
#if !defined(__linux__) || !defined(__x86_64__)
#error This control requires Linux x86-64 and /dev/kvm.
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define RAM_SIZE 0x10000
#define CODE 0x1000
#define HANDLER 0x3000
#define IDT 0x5000
#define OBSERVATIONS 0x6000
#define GDT 0x7000
#define LOW 0x11223344u
#define HIGH 0x55667788u
#define MARKER 0x55aa55aau

extern const unsigned char guest_gp_start[], guest_gp_end[];
__asm__(
    ".section .rodata\n"
    ".code32\n"
    ".global guest_gp_start, guest_gp_end\n"
    "guest_gp_start:\n"
    "push %eax\n"
    "incl 0x6000\n"
    "mov 4(%esp), %eax\n"
    "mov %eax, 0x6004\n"
    "mov 8(%esp), %eax\n"
    "mov %eax, 0x6008\n"
    "mov (%esp), %eax\n"
    "mov %eax, 0x600c\n"
    "mov %edx, 0x6010\n"
    "addl $2, 8(%esp)\n"
    "pop %eax\n"
    "add $4, %esp\n"
    "iret\n"
    "guest_gp_end:\n"
    ".code64\n"
    ".text\n");

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "MSR control failed: %s (errno=%d)\n", operation, errno);
        exit(1);
    }
}

static void put32(unsigned char *memory, size_t offset, uint32_t value)
{
    memcpy(memory + offset, &value, sizeof(value));
}

static void observe(int kvm, unsigned int index, uint32_t msr, int write, int fault)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create VM");
    require(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create irqchip");
    unsigned char *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(ram != MAP_FAILED, "guest RAM");
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM_SIZE,
        .userspace_addr = (uintptr_t)ram,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
    unsigned char code[] = {
        0xb9, 0, 0, 0, 0, // MOV ECX, index.
        0xb8, 0, 0, 0, 0, // MOV EAX, low.
        0xba, 0, 0, 0, 0, // MOV EDX, high.
        0x0f, 0,           // RDMSR/WRMSR.
        0xbb, 0, 0, 0, 0, // MOV EBX, completion marker.
        0xe6, 0xe9,       // OUT 0xe9, AL: userspace completion frontier.
        0xf4,
    };
    put32(code, 1, msr);
    put32(code, 6, LOW);
    put32(code, 11, HIGH);
    code[16] = write ? 0x30 : 0x32;
    put32(code, 18, MARKER);
    memcpy(ram + CODE, code, sizeof(code));
    require((uintptr_t)guest_gp_end >= (uintptr_t)guest_gp_start, "handler ordering");
    size_t handler_size = (size_t)((uintptr_t)guest_gp_end - (uintptr_t)guest_gp_start);
    require(handler_size < IDT - HANDLER, "handler bounds");
    memcpy(ram + HANDLER, guest_gp_start, handler_size);
    uint64_t gate = (HANDLER & 0xffffu) | (UINT64_C(8) << 16)
                    | (UINT64_C(0x8e) << 40) | ((uint64_t)(HANDLER >> 16) << 48);
    memcpy(ram + IDT + 13 * 8, &gate, sizeof(gate));
    const uint64_t descriptors[] = {0, UINT64_C(0x00cf9b000000ffff),
                                   UINT64_C(0x00cf93000000ffff)};
    memcpy(ram + GDT, descriptors, sizeof(descriptors));

    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create CPU");
    int mapping_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(mapping_size > 0, "run size");
    struct kvm_run *run = mmap(NULL, (size_t)mapping_size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, cpu, 0);
    require(run != MAP_FAILED, "run mapping");
    struct kvm_sregs special;
    require(ioctl(cpu, KVM_GET_SREGS, &special) == 0, "GET_SREGS");
    struct kvm_segment data = {
        .base = 0, .limit = UINT32_MAX, .selector = 16, .type = 3,
        .present = 1, .db = 1, .s = 1, .g = 1,
    };
    special.cs = data;
    special.cs.selector = 8;
    special.cs.type = 11;
    special.ds = special.es = special.ss = special.fs = special.gs = data;
    special.cr0 = 0x60000011;
    special.cr3 = special.cr4 = special.efer = 0;
    special.gdt.base = GDT;
    special.gdt.limit = sizeof(descriptors) - 1;
    special.idt.base = IDT;
    special.idt.limit = 256 * 8 - 1;
    require(ioctl(cpu, KVM_SET_SREGS, &special) == 0, "SET_SREGS");
    struct kvm_regs registers = {.rip = CODE, .rsp = 0xf000, .rflags = 2};
    require(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "SET_REGS");
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "KVM_RUN");
    alarm(0);
    // With an in-kernel irqchip HLT can block inside KVM_RUN. An intercepted
    // port output instead exposes the already executed post-MSR marker.
    require(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT
            && run->io.port == 0xe9 && run->io.size == 1 && run->io.count == 1,
            "guest completion port output");
    require(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "GET_REGS");
    uint32_t observed[5];
    memcpy(observed, ram + OBSERVATIONS, sizeof(observed));
    // KVM's I/O operation is still pending. Record its raw RIP without claiming
    // that this separate instruction has completed at the userspace boundary.
    require((registers.rip == CODE + 22 || registers.rip == CODE + 24)
            && registers.rbx == MARKER, "post-MSR marker and I/O frontier");
    require(registers.rflags == 2, "RFLAGS preservation");
    require(observed[0] == (uint32_t)fault, "expected exception count");
    if (fault) {
        require(observed[1] == 0 && observed[2] == CODE + 15,
                "#GP error code and faulting RIP");
        require(observed[3] == LOW && observed[4] == HIGH
                && registers.rax == LOW && registers.rdx == HIGH,
                "fault preserves both destinations");
    } else if (write) {
        require(registers.rax == LOW && registers.rdx == HIGH,
                "valid WRMSR preserves inputs");
    }
    printf("{\"case\":%u,\"msr\":%u,\"write\":%s,\"faults\":%u,"
           "\"error\":%u,\"fault_rip\":%u,\"eax\":%llu,\"edx\":%llu,"
           "\"rip\":%llu,\"passed\":true}\n", index, msr, write ? "true" : "false",
           observed[0], observed[1], observed[2], (unsigned long long)registers.rax,
           (unsigned long long)registers.rdx, (unsigned long long)registers.rip);
    require(fflush(stdout) == 0, "retain completed observation");
    require(munmap(run, (size_t)mapping_size) == 0, "release run mapping");
    require(close(cpu) == 0 && close(vm) == 0, "release native handles");
    require(munmap(ram, RAM_SIZE) == 0, "release RAM");
}

int main(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0, "open KVM");
    require(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
    unsigned int count = 0;
    const uint32_t reserved[] = {0xffffffffu, 0xfffffffeu, 0xdeadbeefu, 0x20000000u};
    for (size_t index = 0; index < sizeof(reserved) / sizeof(reserved[0]); index++) {
        for (int write = 0; write <= 1; write++) {
            observe(kvm, count++, reserved[index], write, 1);
        }
    }
    observe(kvm, count++, 0x10, 0, 0);
    observe(kvm, count++, 0x10, 1, 0);
    require(close(kvm) == 0, "release KVM");
    require(count == 10, "case count");
    return 0;
}
