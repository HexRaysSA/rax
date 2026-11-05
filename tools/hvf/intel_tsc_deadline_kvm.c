// Independent CPL0 TSC-deadline observations. Does not link RAX or qualify HVF.
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
#include <time.h>
#include <unistd.h>

#define RAM_SIZE 0x10000
#define CODE 0x1000
#define GDT 0x7000
#define OBSERVATIONS 0x6000
#define VECTOR 0x51

extern const unsigned char deadline_guest_start[], deadline_guest_end[];
__asm__(
    ".section .rodata\n.code32\n"
    ".global deadline_guest_start, deadline_guest_end\n"
    "deadline_guest_start:\n"
    // EBX selects the scenario; IF remains zero so pending IRQs are observable.
    "push %ebx\n mov $1, %eax\n xor %ecx, %ecx\n cpuid\n"
    "mov %ecx, 0x6028\n pop %ebx\n"
    "movl $0x1ff, 0xfee000f0\n"
    "movl $0x10000, 0xfee00350\n"
    "movl $0x10000, 0xfee00360\n"
    "mov $0x40051, %esi\n"
    "cmp $0, %ebx\n jne 1f\n mov $0x51, %esi\n"
    "1: cmp $1, %ebx\n jne 2f\n mov $0x20051, %esi\n"
    "2: cmp $9, %ebx\n jb 3f\n or $0x10000, %esi\n"
    "3: mov %esi, 0xfee00320\n mfence\n"
    "mov $0x6e0, %ecx\n"
    "mov $-1, %eax\n mov $-1, %edx\n"
    "cmp $8, %ebx\n jb 4f\n mov $1, %eax\n xor %edx, %edx\n"
    "4: wrmsr\n"
    "cmp $3, %ebx\n jne 5f\n xor %eax, %eax\n xor %edx, %edx\n wrmsr\n"
    "5: cmp $4, %ebx\n jne 6f\n movl $0x51, 0xfee00320\n mfence\n"
    "6: cmp $5, %ebx\n jne 7f\n movl $0x20051, 0xfee00320\n mfence\n"
    "7: cmp $6, %ebx\n jne 8f\n movl $0x12345678, 0xfee00380\n mfence\n"
    "8: cmp $7, %ebx\n jne 9f\n movl $0x50061, 0xfee00320\n mfence\n"
    "9: rdmsr\n mov %eax, 0x6000\n mov %edx, 0x6004\n"
    "mov 0xfee00390, %eax\n mov %eax, 0x6008\n"
    "rdtsc\n mov %eax, 0x6010\n mov %edx, 0x6014\n"
    "out %al, $0xe9\n"
    // Userspace waits before reentry; the second observation is after expiry.
    "mov $0x6e0, %ecx\n rdmsr\n"
    "mov %eax, 0x6018\n mov %edx, 0x601c\n"
    "out %al, $0xe9\n"
    "cmp $10, %ebx\n jne 10f\n"
    "movl $0x40051, 0xfee00320\n mfence\n"
    "10: mov $0x6e0, %ecx\n rdmsr\n"
    "mov %eax, 0x6020\n mov %edx, 0x6024\n"
    "out %al, $0xe9\n hlt\n"
    "deadline_guest_end:\n.code64\n.text\n");

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "deadline control failed: %s (errno=%d)\n", operation, errno);
        exit(1);
    }
}

static uint64_t read64(const unsigned char *ram, size_t offset)
{
    uint64_t value;
    memcpy(&value, ram + offset, sizeof(value));
    return value;
}

static unsigned int pending(int cpu)
{
    struct kvm_lapic_state apic;
    require(ioctl(cpu, KVM_GET_LAPIC, &apic) == 0, "GET_LAPIC");
    uint32_t word;
    memcpy(&word, apic.regs + 0x200 + (VECTOR / 32) * 16, sizeof(word));
    return (word >> (VECTOR % 32)) & 1;
}

static void frontier(int cpu, struct kvm_run *run)
{
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "KVM_RUN");
    alarm(0);
    require(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT
            && run->io.port == 0xe9 && run->io.size == 1 && run->io.count == 1,
            "guest observation port output");
}

static void observe(int kvm, unsigned int scenario, const struct kvm_cpuid2 *cpuid)
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
    require((uintptr_t)deadline_guest_end > (uintptr_t)deadline_guest_start,
            "guest code ordering");
    size_t code_size = (size_t)((uintptr_t)deadline_guest_end - (uintptr_t)deadline_guest_start);
    require(code_size < OBSERVATIONS - CODE, "guest code bounds");
    memcpy(ram + CODE, deadline_guest_start, code_size);
    const uint64_t descriptors[] = {0, UINT64_C(0x00cf9b000000ffff),
                                   UINT64_C(0x00cf93000000ffff)};
    memcpy(ram + GDT, descriptors, sizeof(descriptors));
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create CPU");
    require(ioctl(cpu, KVM_SET_CPUID2, cpuid) == 0, "SET_CPUID2");
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
    special.idt.base = 0;
    special.idt.limit = 0;
    require(ioctl(cpu, KVM_SET_SREGS, &special) == 0, "SET_SREGS");
    struct kvm_regs registers = {.rip = CODE, .rsp = 0xf000, .rflags = 2, .rbx = scenario};
    require(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "SET_REGS");
    frontier(cpu, run);
    struct timespec interval = {.tv_sec = 0, .tv_nsec = 20000000};
    while (nanosleep(&interval, &interval) != 0) {
        require(errno == EINTR, "observation interval");
    }
    frontier(cpu, run);
    unsigned int pending_before_unmask = pending(cpu);
    frontier(cpu, run);
    unsigned int pending_after_unmask = pending(cpu);
    uint64_t initial = read64(ram, OBSERVATIONS);
    uint64_t tsc = read64(ram, OBSERVATIONS + 16);
    uint64_t expired = read64(ram, OBSERVATIONS + 24);
    uint64_t after_unmask = read64(ram, OBSERVATIONS + 32);
    uint32_t current;
    memcpy(&current, ram + OBSERVATIONS + 8, sizeof(current));
    uint32_t guest_features;
    memcpy(&guest_features, ram + OBSERVATIONS + 40, sizeof(guest_features));
    require((guest_features & (1u << 24)) != 0, "guest sees TSC-deadline support");
    if (scenario < 8) {
        uint64_t expected = (scenario <= 1 || (scenario >= 3 && scenario <= 5))
                            ? 0 : UINT64_MAX;
        require(initial == expected && expired == expected && after_unmask == expected,
                "mode, roundtrip and disarm controls");
        if (scenario == 6) {
            require(current == 0, "deadline current count remains zero");
        }
    }
    require(tsc > 1, "expiry target precedes sampled TSC");
    printf("{\"case\":%u,\"initial_deadline\":%llu,\"sampled_tsc\":%llu,"
           "\"after_wait_deadline\":%llu,\"after_unmask_deadline\":%llu,"
           "\"guest_cpuid_1_ecx\":%u,\"current_count\":%u,"
           "\"irr_before_unmask\":%u,\"irr_after_unmask\":%u,"
           "\"control_passed\":%s}\n", scenario,
           (unsigned long long)initial, (unsigned long long)tsc,
           (unsigned long long)expired, (unsigned long long)after_unmask,
           guest_features, current, pending_before_unmask, pending_after_unmask,
           scenario < 8 ? "true" : "null");
    require(fflush(stdout) == 0, "retain observations");
    require(munmap(run, (size_t)mapping_size) == 0, "release run mapping");
    require(close(cpu) == 0 && close(vm) == 0, "release native handles");
    require(munmap(ram, RAM_SIZE) == 0, "release RAM");
}

int main(void)
{
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0, "open KVM");
    require(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
    const size_t maximum = 256;
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + maximum * sizeof(cpuid->entries[0]));
    require(cpuid != NULL, "CPUID allocation");
    cpuid->nent = maximum;
    require(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0, "GET_SUPPORTED_CPUID");
    // Linux 6.8 omits this bit from GET_SUPPORTED_CPUID. The documented
    // capability plus the in-kernel irqchip admits enabling it explicitly.
    require(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_TSC_DEADLINE_TIMER) > 0,
            "KVM_CAP_TSC_DEADLINE_TIMER");
    unsigned int deadline_supported = 0;
    for (unsigned int i = 0; i < cpuid->nent; i++) {
        if (cpuid->entries[i].function == 1) {
            cpuid->entries[i].ecx |= 1u << 24;
            deadline_supported = 1;
        }
    }
    require(deadline_supported, "CPUID leaf 1 present");
    for (unsigned int scenario = 0; scenario < 11; scenario++) {
        observe(kvm, scenario, cpuid);
    }
    free(cpuid);
    require(close(kvm) == 0, "release KVM");
    return 0;
}
