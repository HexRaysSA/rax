/* Independent KVM userspace-controller feasibility control. No RAX is linked.
 * Native APIC MMIO and filtered deadline MSRs leave the kernel IRQ chip absent.
 * This observes access routing, not timer expiry, interrupt delivery or restore.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define RAM UINT64_C(0x200000)
#define CODE UINT64_C(0x10000)
#define DEADLINE UINT64_C(0x1122334455667788)
#define LVT UINT64_C(0xfee00320)

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "%s: %s\n", operation, strerror(errno));
        exit(1);
    }
}

static void word(uint8_t *memory, uint64_t address, uint64_t value)
{
    require(address <= RAM - sizeof(value), "guest word bounds");
    memcpy(memory + address, &value, sizeof(value));
}

static const uint8_t xapic_code[] = {
    0x48, 0xbf, 0x20, 0x03, 0xe0, 0xfe, 0, 0, 0, 0, /* MOV RDI, LVT. */
    0xc7, 0x07, 0x41, 0x00, 0x04, 0x00, /* MOV [RDI], deadline-mode LVT. */
    0xb9, 0xe0, 0x06, 0, 0, /* MOV ECX, IA32_TSC_DEADLINE. */
    0xb8, 0x88, 0x77, 0x66, 0x55, /* MOV EAX, low deadline. */
    0xba, 0x44, 0x33, 0x22, 0x11, /* MOV EDX, high deadline. */
    0x44, 0x01, 0xe0, /* ADD EAX, R12D: distinct per-CPU deadline. */
    0x0f, 0x30, /* WRMSR. */
    0x31, 0xc0, 0x31, 0xd2, /* Clear EAX and EDX before readback. */
    0x0f, 0x32, /* RDMSR. */
    0x49, 0x89, 0xc2, 0x49, 0x89, 0xd3, /* MOV R10,RAX; MOV R11,RDX. */
    0xf4, /* HLT. */
};

static const uint8_t x2apic_code[] = {
    0xb9, 0x32, 0x08, 0, 0, /* MOV ECX, x2APIC LVT timer. */
    0xb8, 0x41, 0x00, 0x04, 0, 0x31, 0xd2, 0x0f, 0x30, /* WRMSR LVT. */
    0x31, 0xc0, 0x0f, 0x32, 0x49, 0x89, 0xc5, /* RDMSR; MOV R13,RAX. */
    0xb9, 0xe0, 0x06, 0, 0,
    0xb8, 0x88, 0x77, 0x66, 0x55,
    0xba, 0x44, 0x33, 0x22, 0x11,
    0x44, 0x01, 0xe0, 0x0f, 0x30,
    0x31, 0xc0, 0x31, 0xd2, 0x0f, 0x32,
    0x49, 0x89, 0xc2, 0x49, 0x89, 0xd3, 0xf4,
};

static void populate(uint8_t *memory, bool x2apic)
{
    word(memory, 0x1000, 0x2003);
    /* Four GiB identity translation includes the APIC address, not RAM there. */
    for (uint64_t gigabyte = 0; gigabyte < 4; gigabyte++) {
        uint64_t directory = 0x3000 + gigabyte * 0x1000;
        word(memory, 0x2000 + gigabyte * 8, directory | 3);
        for (uint64_t page = 0; page < 512; page++) {
            word(memory, directory + page * 8,
                 (gigabyte << 30) | (page << 21) | 0x83);
        }
    }
    word(memory, 0x9008, UINT64_C(0x00af9b000000ffff));
    word(memory, 0x9010, UINT64_C(0x00cf93000000ffff));
    word(memory, 0x9018, UINT64_C(0x00008b0080000067));
    if (x2apic) memcpy(memory + CODE, x2apic_code, sizeof(x2apic_code));
    else memcpy(memory + CODE, xapic_code, sizeof(xapic_code));
}

static void setup_cpu(int cpu, int kvm, unsigned id, bool x2apic)
{
    size_t bytes = sizeof(struct kvm_cpuid2) + 256 * sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2 *cpuid = calloc(1, bytes);
    require(cpuid != NULL, "allocate CPUID");
    cpuid->nent = 256;
    require(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0, "supported CPUID");
    require(ioctl(cpu, KVM_SET_CPUID2, cpuid) == 0, "set CPUID");
    free(cpuid);
    struct kvm_sregs s = {0};
    s.cs = (struct kvm_segment) {
        .selector = 8, .limit = UINT32_MAX, .type = 11,
        .present = 1, .s = 1, .l = 1, .g = 1,
    };
    struct kvm_segment data = {
        .selector = 16, .limit = UINT32_MAX, .type = 3,
        .present = 1, .s = 1, .db = 1, .g = 1,
    };
    s.ds = s.es = s.ss = s.fs = s.gs = data;
    s.tr = (struct kvm_segment) {
        .selector = 24, .base = 0x8000, .limit = 0x67,
        .type = 11, .present = 1,
    };
    s.ldt.unusable = 1;
    s.gdt.base = 0x9000;
    s.gdt.limit = 47;
    s.cr0 = 0x80010033;
    s.cr3 = 0x1000;
    s.cr4 = 0x220;
    s.efer = 0x500;
    s.apic_base = x2apic ? 0xfee00d00 : 0xfee00900;
    require(ioctl(cpu, KVM_SET_SREGS, &s) == 0, "set system registers");
    struct kvm_regs r = {.rip = CODE, .rsp = RAM - 0x1000, .rflags = 2, .r12 = id};
    require(ioctl(cpu, KVM_SET_REGS, &r) == 0, "set registers");
}

int main(int argc, char **argv)
{
    require((argc == 2 || argc == 3) && strlen(argv[1]) == 1 &&
            (argv[1][0] == '1' || argv[1][0] == '2' || argv[1][0] == '4'),
            "expected CPU count 1, 2 or 4");
    unsigned count = (unsigned)(argv[1][0] - '0');
    bool kernel_timer_path = argc == 3 && strcmp(argv[2], "--kernel-timer-path") == 0;
    bool x2apic = argc == 3 && strcmp(argv[2], "--x2apic") == 0;
    require(argc == 2 || kernel_timer_path || x2apic, "unknown control variant");
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == 12, "open KVM API12");
    require(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_USER_SPACE_MSR) > 0,
            "userspace MSR capability");
    require(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_MSR_FILTER) > 0,
            "MSR filter capability");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create VM without IRQ chip");
    int disable_exits = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_DISABLE_EXITS);
    require(disable_exits >= 0 && (disable_exits & KVM_X86_DISABLE_EXITS_MWAIT) != 0,
            "per-VM MWAIT exit control");
    /* Linux v6.8 kvm_can_use_hv_timer() excludes this per-VM mode. It avoids
     * the deadline WRMSR fast path that consumed the first two controls before
     * the generic MSR filter. No MWAIT instruction executes in this guest.
     */
    struct kvm_enable_cap timer_path = {
        .cap = KVM_CAP_X86_DISABLE_EXITS, .args = {KVM_X86_DISABLE_EXITS_MWAIT},
    };
    if (!kernel_timer_path) {
        require(ioctl(vm, KVM_ENABLE_CAP, &timer_path) == 0, "select per-VM timer path");
    }
    struct kvm_enable_cap cap = {
        .cap = KVM_CAP_X86_USER_SPACE_MSR, .args = {KVM_MSR_EXIT_REASON_VALID_MASK},
    };
    require(ioctl(vm, KVM_ENABLE_CAP, &cap) == 0, "enable filtered MSR exits");
    uint8_t deny = 0;
    struct kvm_msr_filter filter = {
        .flags = KVM_MSR_FILTER_DEFAULT_ALLOW,
        .ranges = {{
            .flags = KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE,
            .nmsrs = 1, .base = 0x6e0, .bitmap = &deny,
        }},
    };
    require(ioctl(vm, KVM_X86_SET_MSR_FILTER, &filter) == 0, "install deadline filter");
    uint8_t *memory = mmap(NULL, RAM, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "allocate RAM");
    populate(memory, x2apic);
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM,
        .userspace_addr = (uintptr_t)memory,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
    int run_bytes = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(run_bytes > 0, "CPU run mapping size");
    int cpus[4];
    struct kvm_run *runs[4];
    int lapic_errors[4];
    for (unsigned id = 0; id < count; id++) {
        cpus[id] = ioctl(vm, KVM_CREATE_VCPU, id);
        require(cpus[id] >= 0, "create CPU");
        setup_cpu(cpus[id], kvm, id, x2apic);
        struct kvm_lapic_state lapic = {0};
        errno = 0;
        require(ioctl(cpus[id], KVM_GET_LAPIC, &lapic) < 0, "kernel LAPIC must be absent");
        lapic_errors[id] = errno;
        runs[id] = mmap(NULL, (size_t)run_bytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, cpus[id], 0);
        require(runs[id] != MAP_FAILED, "map CPU run state");
    }
    /* Refresh the live CPU policy after setup; the second control establishes
     * that this refresh alone does not fix the earlier missing write exit.
     */
    require(ioctl(vm, KVM_X86_SET_MSR_FILTER, &filter) == 0, "refresh live CPU MSR filters");
    printf("{\"kernel_irqchip_created\":false,\"mwait_exit_disabled\":%s,"
           "\"x2apic\":%s,\"cpus\":[", kernel_timer_path ? "false" : "true",
           x2apic ? "true" : "false");
    for (unsigned id = 0; id < count; id++) {
        struct kvm_run *run = runs[id];
        uint64_t saved_deadline = 0;
        unsigned observed = 0;
        unsigned native_entries = 0, x2_writes = 0, x2_reads = 0;
        uint32_t x2_write_reason = 0, x2_read_reason = 0;
        int halted = 0;
        alarm(5);
        for (unsigned entry = 0; entry < 8; entry++) {
            require(ioctl(cpus[id], KVM_RUN, 0) == 0, "native guest entry");
            native_entries++;
            if (x2apic && observed < 2) {
                require(run->msr.index == 0x832, "x2APIC LVT index");
                require(run->msr.reason == KVM_MSR_EXIT_REASON_INVAL ||
                        run->msr.reason == KVM_MSR_EXIT_REASON_UNKNOWN, "x2APIC exit reason");
                if (observed == 0) {
                    require(run->exit_reason == KVM_EXIT_X86_WRMSR &&
                            run->msr.data == 0x40041, "userspace x2APIC LVT write");
                    x2_writes++;
                    x2_write_reason = run->msr.reason;
                } else {
                    require(run->exit_reason == KVM_EXIT_X86_RDMSR, "userspace x2APIC LVT read");
                    run->msr.data = 0x40041;
                    x2_reads++;
                    x2_read_reason = run->msr.reason;
                }
                run->msr.error = 0;
                observed++;
                continue;
            }
            unsigned phase = observed - (x2apic ? 1 : 0);
            if (phase == 0 && run->exit_reason == KVM_EXIT_MMIO) {
                uint32_t lvt = 0;
                memcpy(&lvt, run->mmio.data, sizeof(lvt));
                require(run->mmio.is_write && run->mmio.phys_addr == LVT &&
                        run->mmio.len == 4 && lvt == 0x40041, "userspace APIC write");
            } else if (phase == 1 && run->exit_reason == KVM_EXIT_X86_WRMSR) {
                require(run->msr.index == 0x6e0 && run->msr.reason == KVM_MSR_EXIT_REASON_FILTER &&
                        run->msr.data == DEADLINE + id, "userspace deadline write");
                saved_deadline = run->msr.data;
                run->msr.error = 0;
            } else if (phase == 2 && run->exit_reason == KVM_EXIT_X86_RDMSR) {
                require(run->msr.index == 0x6e0 && run->msr.reason == KVM_MSR_EXIT_REASON_FILTER,
                        "userspace deadline read");
                run->msr.data = saved_deadline;
                run->msr.error = 0;
            } else if (phase == 3 && run->exit_reason == KVM_EXIT_HLT) {
                halted = 1;
                break;
            } else {
                fprintf(stderr, "unexpected exit %u at observation %u\n", run->exit_reason, observed);
                if (run->exit_reason == KVM_EXIT_X86_RDMSR || run->exit_reason == KVM_EXIT_X86_WRMSR) {
                    fprintf(stderr, "MSR index=%#x reason=%#x data=%#" PRIx64 "\n",
                            run->msr.index, run->msr.reason, (uint64_t)run->msr.data);
                }
                exit(1);
            }
            observed++;
        }
        alarm(0);
        struct kvm_regs r;
        require(ioctl(cpus[id], KVM_GET_REGS, &r) == 0, "read CPU registers");
        size_t code_size = x2apic ? sizeof(x2apic_code) : sizeof(xapic_code);
        require(halted && r.rip == CODE + code_size &&
                r.r10 == (uint32_t)(DEADLINE + id) && r.r11 == DEADLINE >> 32,
                "native guest readback and HLT");
        require(!x2apic || r.r13 == 0x40041, "x2APIC LVT guest readback");
        printf("%s{\"id\":%u,\"lapic_query_errno\":%d,\"apic_write_exits\":%u,"
               "\"deadline_write_exits\":1,\"deadline_read_exits\":1,"
               "\"x2apic_write_exits\":%u,\"x2apic_read_exits\":%u,\"native_entries\":%u,"
               "\"deadline\":%" PRIu64 ",\"rip\":%" PRIu64 ",\"r10\":%" PRIu64
               ",\"r11\":%" PRIu64 ",\"r13\":%" PRIu64 ",\"x2apic_write_reason\":",
               id ? "," : "", id, lapic_errors[id], x2apic ? 0 : 1, x2_writes, x2_reads,
               native_entries, saved_deadline, (uint64_t)r.rip,
               (uint64_t)r.r10, (uint64_t)r.r11, (uint64_t)r.r13);
        if (x2apic) printf("%u", x2_write_reason); else printf("null");
        printf(",\"x2apic_read_reason\":");
        if (x2apic) printf("%u", x2_read_reason); else printf("null");
        printf(",\"passed\":true}");
    }
    printf("],\"cpu_count\":%u,\"timer_expiry_qualified\":false,"
           "\"checkpoint_restore_qualified\":false}\n", count);
    for (unsigned id = 0; id < count; id++) {
        require(munmap(runs[id], (size_t)run_bytes) == 0, "unmap run state");
        require(close(cpus[id]) == 0, "close CPU");
    }
    require(close(vm) == 0, "close VM");
    require(munmap(memory, RAM) == 0, "unmap RAM");
    require(close(kvm) == 0, "close KVM");
    return 0;
}
