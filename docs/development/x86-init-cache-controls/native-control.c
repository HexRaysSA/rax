// Native KVM INIT and CR0 readback; no RAX implementation is linked.
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static void require(int condition, const char *operation)
{
    if (!condition) {
        perror(operation);
        exit(1);
    }
}

static void control(int kvm, unsigned int count, uint64_t cache)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create VM");
    require(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create IRQ chip");
    size_t ram_size = 2u * 1024u * 1024u;
    unsigned char *ram = mmap(NULL, ram_size, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    require(ram != MAP_FAILED, "allocate RAM");
    struct kvm_userspace_memory_region region = {
        .memory_size = ram_size, .userspace_addr = (uintptr_t)ram,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
    // MOV EAX,CR0; MOV DX,0xe9; OUT DX,EAX; HLT, in 16-bit code.
    const unsigned char code[] = {0x0f, 0x20, 0xc0, 0xba, 0xe9, 0x00, 0x66, 0xef, 0xf4};
    memcpy(ram + 0x1000, code, sizeof(code));
    int cpus[4];
    for (unsigned int id = 0; id < count; ++id) {
        cpus[id] = ioctl(vm, KVM_CREATE_VCPU, id);
        require(cpus[id] >= 0, "create CPU");
        size_t bytes = sizeof(struct kvm_cpuid2) + 256 * sizeof(struct kvm_cpuid_entry2);
        struct kvm_cpuid2 *cpuid = calloc(1, bytes);
        require(cpuid != NULL, "allocate CPUID");
        cpuid->nent = 256;
        require(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0, "get CPUID");
        for (unsigned int index = 0; index < cpuid->nent; ++index) {
            struct kvm_cpuid_entry2 *entry = &cpuid->entries[index];
            if (entry->function == 1) {
                entry->ebx = (entry->ebx & 0x00ffffffu) | (id << 24);
            } else if (entry->function == 0xb || entry->function == 0x1f) {
                entry->edx = id;
            }
        }
        require(ioctl(cpus[id], KVM_SET_CPUID2, cpuid) == 0, "set CPUID");
        free(cpuid);
        struct kvm_sregs special;
        require(ioctl(cpus[id], KVM_GET_SREGS, &special) == 0, "read initial CR0");
        require(special.cr0 == 0x60000010u, "native initial CR0 reset flags");
        special.cr0 = cache | 0x00010031u; // WP, NE, ET, PE before INIT.
        require(ioctl(cpus[id], KVM_SET_SREGS, &special) == 0, "seed CR0");
        struct kvm_regs regs = {.rax = 0xa5, .rip = 0x1000, .rflags = 2};
        require(ioctl(cpus[id], KVM_SET_REGS, &regs) == 0, "seed registers");
        struct kvm_mp_state mp = {.mp_state = KVM_MP_STATE_RUNNABLE};
        require(ioctl(cpus[id], KVM_SET_MP_STATE, &mp) == 0, "prepare CPU");
        struct kvm_lapic_state apic;
        require(ioctl(cpus[id], KVM_GET_LAPIC, &apic) == 0, "read APIC identity");
        uint32_t apic_id;
        memcpy(&apic_id, apic.regs + 0x20, sizeof(apic_id));
        fprintf(stderr, "INIT_FIXTURE count=%u id=%u apic_id=%u apic_base=%llx\n",
                count, id, apic_id >> 24, (unsigned long long)special.apic_base);
        require(apic_id == id << 24, "configured physical APIC identity");
    }
    int mapped_bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(mapped_bytes >= (int)sizeof(struct kvm_run), "run mapping size");
    struct kvm_msi init = {
        .address_lo = 0xfeeff000u, .data = 0x4500,
    };
    int delivered = ioctl(vm, KVM_SIGNAL_MSI, &init);
    fprintf(stderr, "INIT_DELIVERY count=%u delivered=%d\n", count, delivered);
    require(delivered == (int)count, "deliver broadcast INIT");
    for (unsigned int id = 0; id < count; ++id) {
        struct kvm_mp_state mp;
        require(ioctl(cpus[id], KVM_GET_MP_STATE, &mp) == 0, "accept pending INIT");
        struct kvm_regs regs;
        struct kvm_sregs special;
        require(ioctl(cpus[id], KVM_GET_REGS, &regs) == 0, "read INIT registers");
        require(ioctl(cpus[id], KVM_GET_SREGS, &special) == 0, "read INIT CR0");
        uint64_t expected = cache | 0x10;
        require(regs.rax == 0 && regs.rip == 0xfff0, "INIT reset occurred");
        require(special.cr0 == expected, "INIT preserves cache controls");
        // Execute a direct CR0 observation from an explicitly prepared CPU.
        // This does not claim architectural AP startup through SIPI.
        special.cs.base = 0;
        special.cs.selector = 0;
        require(ioctl(cpus[id], KVM_SET_SREGS, &special) == 0, "prepare readback CS");
        regs.rip = 0x1000;
        require(ioctl(cpus[id], KVM_SET_REGS, &regs) == 0, "prepare readback PC");
        mp.mp_state = KVM_MP_STATE_RUNNABLE;
        require(ioctl(cpus[id], KVM_SET_MP_STATE, &mp) == 0, "prepare readback entry");
        struct kvm_run *run = mmap(NULL, (size_t)mapped_bytes, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, cpus[id], 0);
        require(run != MAP_FAILED, "map run buffer");
        require(ioctl(cpus[id], KVM_RUN, 0) == 0, "execute CR0 readback");
        require(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
                    run->io.port == 0xe9 && run->io.size == 4 && run->io.count == 1 &&
                    run->io.data_offset <= (uint64_t)mapped_bytes - 4,
                "bounded native output");
        uint32_t observed;
        memcpy(&observed, (unsigned char *)run + run->io.data_offset, sizeof(observed));
        require(observed == expected, "guest observes preserved CR0");
        printf("{\"cpus\":%u,\"id\":%u,\"cache\":%llu,\"expected\":%llu,"
               "\"after_init\":%llu,\"guest_cr0\":%u}\n", count, id,
               (unsigned long long)cache, (unsigned long long)expected,
               (unsigned long long)special.cr0, observed);
        require(munmap(run, (size_t)mapped_bytes) == 0, "unmap run buffer");
    }
    for (unsigned int id = 0; id < count; ++id) {
        require(close(cpus[id]) == 0, "close CPU");
    }
    require(close(vm) == 0 && munmap(ram, ram_size) == 0, "release native graph");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
    alarm(10);
    for (unsigned int count = 1; count <= 4; count *= 2) {
        for (unsigned int mode = 0; mode < 3; ++mode) {
            const uint64_t modes[] = {0, 0x40000000, 0x60000000};
            control(kvm, count, modes[mode]);
        }
    }
    alarm(0);
    require(close(kvm) == 0, "close KVM");
    return 0;
}
