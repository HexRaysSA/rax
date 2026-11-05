/* Independent KVM control for the native Intel consumer's initial RAM guest.
 * No RAX library is linked. This validates guest setup, not macOS HVF.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define RAM UINT64_C(0x200000)
#define CODE UINT64_C(0x10000)
#define SEED UINT64_C(0x1122334455667788)
#define MARKER UINT64_C(0xa1b2c3d4e5f60718)

static void require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "%s: %s\n", operation, strerror(errno));
        exit(1);
    }
}

static void word(uint8_t *memory, uint64_t address, uint64_t value) {
    require(address <= RAM - sizeof(value), "guest word bounds");
    memcpy(memory + address, &value, sizeof(value));
}

int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0, "open KVM");
    require(ioctl(kvm, KVM_GET_API_VERSION, 0) == 12, "KVM API version");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create VM");
    uint8_t *memory = mmap(NULL, RAM, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "allocate guest RAM");
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM,
        .userspace_addr = (uintptr_t)memory,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
    word(memory, 0x1000, 0x2003);
    for (uint64_t gigabyte = 0; gigabyte < 2; ++gigabyte) {
        uint64_t directory = 0x3000 + gigabyte * 0x1000;
        word(memory, 0x2000 + gigabyte * 8, directory | 3);
        for (uint64_t page = 0; page < 512; ++page) {
            word(memory, directory + page * 8,
                 (gigabyte << 30) | (page << 21) | 0x83);
        }
    }
    word(memory, 0x9008, UINT64_C(0x00af9b000000ffff));
    word(memory, 0x9010, UINT64_C(0x00cf93000000ffff));
    word(memory, 0x9018, UINT64_C(0x00008b0080000067));
    word(memory, 0x8004, RAM - 0x1000);
    uint16_t iomap = 0x68;
    memcpy(memory + 0x8066, &iomap, sizeof(iomap));
    memory[CODE] = 0x49;
    memory[CODE + 1] = 0xba;
    word(memory, CODE + 2, MARKER);
    memory[CODE + 10] = 0xf4;

    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create CPU");
    size_t cpuid_bytes = sizeof(struct kvm_cpuid2) +
                         256 * sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2 *cpuid = calloc(1, cpuid_bytes);
    require(cpuid != NULL, "allocate CPUID");
    cpuid->nent = 256;
    require(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0, "supported CPUID");
    require(ioctl(cpu, KVM_SET_CPUID2, cpuid) == 0, "set CPUID");
    free(cpuid);

    struct kvm_sregs special = {0};
    special.cs = (struct kvm_segment) {
        .selector = 8, .limit = UINT32_MAX, .type = 11,
        .present = 1, .s = 1, .l = 1, .g = 1,
    };
    struct kvm_segment data = {
        .selector = 16, .limit = UINT32_MAX, .type = 3,
        .present = 1, .s = 1, .db = 1, .g = 1,
    };
    special.ds = special.es = special.ss = special.fs = special.gs = data;
    special.tr = (struct kvm_segment) {
        .selector = 24, .base = 0x8000, .limit = 0x67,
        .type = 11, .present = 1,
    };
    special.ldt.unusable = 1;
    special.gdt.base = 0x9000;
    special.gdt.limit = 47;
    special.cr0 = 0x80010033;
    special.cr3 = 0x1000;
    special.cr4 = 0x220;
    special.efer = 0x500;
    special.apic_base = 0xfee00900;
    require(ioctl(cpu, KVM_SET_SREGS, &special) == 0, "set system registers");
    struct kvm_regs registers = {
        .rip = CODE, .rsp = RAM - 0x1000, .rflags = 2,
        .rax = SEED, .rdi = 0x40000080,
    };
    require(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "set registers");
    struct kvm_debugregs debug = {.dr6 = 0xffff0ff0, .dr7 = 0x400};
    require(ioctl(cpu, KVM_SET_DEBUGREGS, &debug) == 0, "set debug registers");
    int run_bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(run_bytes > 0, "CPU run mapping size");
    struct kvm_run *run = mmap(NULL, (size_t)run_bytes, PROT_READ | PROT_WRITE,
                               MAP_SHARED, cpu, 0);
    require(run != MAP_FAILED, "map CPU run state");
    alarm(5);
    require(ioctl(cpu, KVM_RUN, 0) == 0, "run RAM control");
    alarm(0);
    require(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "read registers");
    int passed = run->exit_reason == KVM_EXIT_HLT &&
                 registers.rip == CODE + 11 && registers.r10 == MARKER &&
                 registers.rax == SEED && registers.rdi == 0x40000080 &&
                 registers.rflags == 2;
    printf("{\"exit_reason\":%u,\"rip\":\"0x%" PRIx64
           "\",\"r10\":\"0x%" PRIx64 "\",\"passed\":%s}\n",
           run->exit_reason, (uint64_t)registers.rip, (uint64_t)registers.r10,
           passed ? "true" : "false");
    require(munmap(run, (size_t)run_bytes) == 0, "unmap run state");
    require(close(cpu) == 0, "close CPU");
    require(close(vm) == 0, "close VM");
    require(munmap(memory, RAM) == 0, "unmap RAM");
    require(close(kvm) == 0, "close KVM");
    return passed ? 0 : 1;
}
