// Independent Linux KVM IOAPIC transitions; no RAX code is linked.
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

#define PIN 20
#define VECTOR 0x51

static void need(int condition, const char *what) {
    if (!condition) { perror(what); exit(1); }
}
static uint32_t reg(const struct kvm_lapic_state *state, unsigned int offset) {
    uint32_t value; memcpy(&value, state->regs + offset, 4); return value;
}
static void put(struct kvm_lapic_state *state, unsigned int offset, uint32_t value) {
    memcpy(state->regs + offset, &value, 4);
}
static void line(int vm, int asserted) {
    struct kvm_irq_level input = {.irq = PIN, .level = (uint32_t)asserted};
    need(ioctl(vm, KVM_IRQ_LINE, &input) == 0, "KVM_IRQ_LINE");
}
static void observe(int vm, int cpu, int level, const char *phase) {
    struct kvm_irqchip chip = {.chip_id = KVM_IRQCHIP_IOAPIC};
    struct kvm_lapic_state apic;
    need(ioctl(vm, KVM_GET_IRQCHIP, &chip) == 0, "GET_IRQCHIP");
    need(ioctl(cpu, KVM_GET_LAPIC, &apic) == 0, "GET_LAPIC");
    unsigned int offset = (VECTOR / 32) * 16;
    unsigned int bit = 1u << (VECTOR % 32);
    printf("{\"level\":%d,\"phase\":\"%s\",\"remote_irr\":%d,\"pending\":%d,\"in_service\":%d,\"trigger\":%d,\"ioapic_irr\":%u}\n",
           level, phase, !!(chip.chip.ioapic.redirtbl[PIN].bits & (1u << 14)),
           !!(reg(&apic, 0x200 + offset) & bit), !!(reg(&apic, 0x100 + offset) & bit),
           !!(reg(&apic, 0x180 + offset) & bit), chip.chip.ioapic.irr);
}
static void guest_entry(int cpu, struct kvm_run *run, uint64_t rip) {
    struct kvm_sregs special;
    need(ioctl(cpu, KVM_GET_SREGS, &special) == 0, "GET_SREGS");
    struct kvm_segment data = {.base = 0, .limit = UINT32_MAX, .selector = 16,
        .type = 3, .present = 1, .db = 1, .s = 1, .g = 1};
    special.cs = data; special.cs.selector = 8; special.cs.type = 11;
    special.ds = special.es = special.ss = special.fs = special.gs = data;
    special.cr0 = 0x60000011; special.cr3 = 0; special.cr4 = 0; special.efer = 0;
    need(ioctl(cpu, KVM_SET_SREGS, &special) == 0, "SET_SREGS");
    struct kvm_regs registers = {.rip = rip, .rsp = 0x1ff0, .rflags = 2};
    need(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "SET_REGS");
    alarm(5);
    need(ioctl(cpu, KVM_RUN, 0) == 0, "KVM_RUN EOI");
    alarm(0);
    need(run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
         run->io.port == 0xe9 && run->io.size == 1 && run->io.count == 1, "EOI guest canary");
}
static void eoi(int vm, int cpu, struct kvm_run *run) {
    struct kvm_lapic_state apic;
    need(ioctl(cpu, KVM_GET_LAPIC, &apic) == 0, "GET_LAPIC before EOI");
    unsigned int offset = (VECTOR / 32) * 16;
    unsigned int bit = 1u << (VECTOR % 32);
    // Install the accepted architectural interrupt frontier. The original
    // IRQ delivery and the EOI guest instruction are independent native paths.
    put(&apic, 0x200 + offset, reg(&apic, 0x200 + offset) & ~bit);
    put(&apic, 0x100 + offset, reg(&apic, 0x100 + offset) | bit);
    need(ioctl(cpu, KVM_SET_LAPIC, &apic) == 0, "SET_LAPIC in-service frontier");
    guest_entry(cpu, run, 0x1000);
    (void)vm;
}
int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC); need(kvm >= 0, "open KVM");
    need(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
    for (int level = 0; level <= 1; ++level) {
        int vm = ioctl(kvm, KVM_CREATE_VM, 0); need(vm >= 0, "create VM");
        need(ioctl(vm, KVM_CREATE_IRQCHIP, 0) == 0, "create irqchip");
        void *ram = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        need(ram != MAP_FAILED, "guest RAM");
        struct kvm_userspace_memory_region region = {.slot=0, .guest_phys_addr=0, .memory_size=8192, .userspace_addr=(uintptr_t)ram};
        need(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
        // mov dword [0xfee000b0],0; mov dx,0xe9; xor eax,eax; out dx,al; hlt
        const unsigned char code[] = {0xc7,0x05,0xb0,0x00,0xe0,0xfe,0,0,0,0,0x66,0xba,0xe9,0,0x31,0xc0,0xee,0xf4};
        memcpy((unsigned char *)ram + 0x1000, code, sizeof(code));
        int cpu = ioctl(vm, KVM_CREATE_VCPU, 0); need(cpu >= 0, "create CPU");
        int mapping_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0); need(mapping_size > 0, "run size");
        struct kvm_run *run = mmap(NULL, (size_t)mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
        need(run != MAP_FAILED, "run mapping");
        struct kvm_lapic_state apic; need(ioctl(cpu, KVM_GET_LAPIC, &apic) == 0, "initial LAPIC");
        put(&apic, 0xf0, 0x1ff); need(ioctl(cpu, KVM_SET_LAPIC, &apic) == 0, "enable LAPIC");
        struct kvm_irqchip chip = {.chip_id = KVM_IRQCHIP_IOAPIC};
        need(ioctl(vm, KVM_GET_IRQCHIP, &chip) == 0, "initial IOAPIC");
        chip.chip.ioapic.redirtbl[PIN].bits = VECTOR | (level ? 1u << 15 : 0) | (1u << 16);
        need(ioctl(vm, KVM_SET_IRQCHIP, &chip) == 0, "configure IOAPIC");
        observe(vm,cpu,level,"initial");
        line(vm,1); observe(vm,cpu,level,"masked_assert");
        unsigned char unmask[] = {0xc7,0x05,0,0,0xc0,0xfe,0x38,0,0,0,
            0xc7,0x05,0x10,0,0xc0,0xfe,VECTOR,0,0,0,
            0x66,0xba,0xe9,0,0x31,0xc0,0xee,0xf4};
        unmask[17] = level ? 0x80 : 0;
        memcpy((unsigned char *)ram + 0x1100, unmask, sizeof(unmask));
        guest_entry(cpu,run,0x1100); observe(vm,cpu,level,"native_unmask");
        run->immediate_exit = 1; errno = 0;
        need(ioctl(cpu,KVM_RUN,0)==-1 && errno==EINTR,"unmask OUT completion");
        run->immediate_exit = 0;
        line(vm,0); line(vm,1); observe(vm,cpu,level,"assert");
        line(vm,1); observe(vm,cpu,level,"repeat_assert");
        eoi(vm,cpu,run); observe(vm,cpu,level,"eoi_asserted");
        line(vm,0); observe(vm,cpu,level,"deassert");
        // Complete only the prior OUT, then a second explicit guest entry.
        run->immediate_exit = 1; errno = 0;
        need(ioctl(cpu, KVM_RUN, 0) == -1 && errno == EINTR, "entry-only OUT completion");
        run->immediate_exit = 0;
        eoi(vm,cpu,run); observe(vm,cpu,level,"eoi_deasserted");
        line(vm,1); observe(vm,cpu,level,"new_assert");
        need(munmap(run,(size_t)mapping_size)==0 && close(cpu)==0 && close(vm)==0 && munmap(ram,8192)==0, "release native graph");
    }
    need(close(kvm)==0,"close KVM"); return 0;
}
