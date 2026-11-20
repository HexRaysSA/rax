// Independent KVM control for a future one-shot with a zero exported count.
// Based on the adjacent settled-phase control, which observes expiry and EOI.
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef KVM_CAP_X86_APIC_BUS_CYCLES_NS
#define KVM_CAP_X86_APIC_BUS_CYCLES_NS 237
#endif

#define APIC_BUS_CYCLE_NS UINT64_C(20000000)
#define APIC_DIVIDE_BY_128 0xa
#define ONE_COUNT_NS (APIC_BUS_CYCLE_NS * UINT64_C(128))

struct graph {
    int vm;
    int cpu;
    unsigned char *memory;
    struct kvm_run *run;
    size_t run_size;
};

static volatile sig_atomic_t timed_out;

static void alarm_handler(int signal_number)
{
    (void)signal_number;
    timed_out = 1;
}

static int checked(int value, const char *operation)
{
    if (value < 0) {
        perror(operation);
        exit(1);
    }
    return value;
}

static struct graph create_graph(int kvm)
{
    struct graph graph = {0};
    graph.vm = checked(ioctl(kvm, KVM_CREATE_VM, 0), "create vm");
    checked(ioctl(graph.vm, KVM_CREATE_IRQCHIP, 0), "create irqchip");
    struct kvm_enable_cap capability = {
        .cap = KVM_CAP_X86_APIC_BUS_CYCLES_NS,
        .args = {APIC_BUS_CYCLE_NS},
    };
    checked(ioctl(graph.vm, KVM_ENABLE_CAP, &capability), "configure APIC bus cycle");
    graph.memory = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (graph.memory == MAP_FAILED) {
        perror("mmap guest");
        exit(1);
    }
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .memory_size = 2 * 1024 * 1024,
        .userspace_addr = (uintptr_t)graph.memory,
    };
    checked(ioctl(graph.vm, KVM_SET_USER_MEMORY_REGION, &region), "register memory");
    graph.cpu = checked(ioctl(graph.vm, KVM_CREATE_VCPU, 0), "create cpu");
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + 256 * sizeof(cpuid->entries[0]));
    if (!cpuid) {
        perror("calloc cpuid");
        exit(1);
    }
    cpuid->nent = 256;
    checked(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid), "supported cpuid");
    checked(ioctl(graph.cpu, KVM_SET_CPUID2, cpuid), "set cpuid");
    free(cpuid);
    graph.run_size = (size_t)checked(ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0), "run size");
    graph.run = mmap(NULL, graph.run_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, graph.cpu, 0);
    if (graph.run == MAP_FAILED) {
        perror("mmap run");
        exit(1);
    }
    const unsigned char main_code[] = {0xfb, 0xf4, 0xeb, 0xfd};
    const unsigned char handler[] = {
        0xb0, 0xa5, 0xe6, 0xe9,
        0x67, 0x66, 0xc7, 0x05, 0xb0, 0x00, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00,
        0xcf,
    };
    const unsigned char vector[] = {0x00, 0x20, 0x00, 0x00};
    memcpy(graph.memory + 0x1000, main_code, sizeof(main_code));
    memcpy(graph.memory + 0x2000, handler, sizeof(handler));
    memcpy(graph.memory + 0x41 * 4, vector, sizeof(vector));
    struct kvm_sregs special = {0};
    checked(ioctl(graph.cpu, KVM_GET_SREGS, &special), "get special");
    special.cs.base = 0;
    special.cs.selector = 0;
    special.ds.base = 0;
    special.ds.selector = 0;
    special.ds.limit = 0xffffffff;
    special.ds.g = 1;
    special.ss.base = 0;
    special.ss.selector = 0;
    special.idt.base = 0;
    special.idt.limit = 0x3ff;
    checked(ioctl(graph.cpu, KVM_SET_SREGS, &special), "set special");
    struct kvm_regs regs = {.rip = 0x1000, .rsp = 0x8000, .rflags = 2};
    checked(ioctl(graph.cpu, KVM_SET_REGS, &regs), "set regs");
    return graph;
}

static void set_register(struct kvm_lapic_state *lapic, size_t offset, uint32_t value)
{
    memcpy(lapic->regs + offset, &value, sizeof(value));
}

static uint32_t get_register(const struct kvm_lapic_state *lapic, size_t offset)
{
    uint32_t value;
    memcpy(&value, lapic->regs + offset, sizeof(value));
    return value;
}

static int observe_timer(struct graph *graph)
{
    timed_out = 0;
    struct itimerval timer = {.it_value = {.tv_usec = 200000}};
    checked(setitimer(ITIMER_REAL, &timer, NULL), "arm timeout");
    int result = ioctl(graph->cpu, KVM_RUN, 0);
    int error = errno;
    struct itimerval disarm = {0};
    checked(setitimer(ITIMER_REAL, &disarm, NULL), "disarm timeout");
    if (result < 0 && error == EINTR && timed_out) {
        return 0;
    }
    if (result < 0) {
        errno = error;
        checked(result, "run guest");
    }
    if (graph->run->exit_reason != KVM_EXIT_IO ||
        graph->run->io.direction != KVM_EXIT_IO_OUT ||
        graph->run->io.port != 0xe9 || graph->run->io.size != 1 ||
        graph->run->io.count != 1) {
        fprintf(stderr, "unexpected exit %u\n", graph->run->exit_reason);
        exit(1);
    }
    unsigned char *data = (unsigned char *)graph->run + graph->run->io.data_offset;
    if (*data != 0xa5) {
        fprintf(stderr, "unexpected timer payload %u\n", *data);
        exit(1);
    }
    return 1;
}

static void destroy_graph(struct graph *graph)
{
    checked(munmap(graph->run, graph->run_size), "unmap run");
    checked(close(graph->cpu), "close cpu");
    checked(close(graph->vm), "close vm");
    checked(munmap(graph->memory, 2 * 1024 * 1024), "unmap guest");
}

static uint64_t monotonic_ns(void)
{
    struct timespec now = {0};
    checked(clock_gettime(CLOCK_MONOTONIC, &now), "monotonic clock");
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static void require_control(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static struct graph create_slow_graph(int kvm, int x2apic)
{
    struct graph graph = create_graph(kvm);
    if (x2apic) {
        struct kvm_sregs special = {0};
        checked(ioctl(graph.cpu, KVM_GET_SREGS, &special), "read APIC base");
        special.apic_base |= 3u << 10;
        checked(ioctl(graph.cpu, KVM_SET_SREGS, &special), "enable x2APIC");
        checked(ioctl(graph.cpu, KVM_GET_SREGS, &special), "verify x2APIC base");
        require_control((special.apic_base & (3u << 10)) == (3u << 10),
                        "x2APIC enable was ignored");
        // mov al,a5h; out e9h,al; mov ecx,80bh; xor eax,eax; xor edx,edx;
        // wrmsr; iret. The handler reports delivery before acknowledging it.
        const unsigned char eoi[] = {
            0xb0, 0xa5, 0xe6, 0xe9,
            0x66, 0xb9, 0x0b, 0x08, 0x00, 0x00,
            0x66, 0x31, 0xc0, 0x66, 0x31, 0xd2, 0x0f, 0x30, 0xcf,
        };
        memcpy(graph.memory + 0x2000, eoi, sizeof(eoi));
    }
    return graph;
}

static void zero_count_control(int kvm, int x2apic)
{
    struct graph graph = create_slow_graph(kvm, x2apic);
    struct kvm_lapic_state armed = {0}, early = {0}, done = {0};
    checked(ioctl(graph.cpu, KVM_GET_LAPIC, &armed), "read reset LAPIC");
    set_register(&armed, 0xf0, 0x1ff);
    set_register(&armed, 0x350, 1u << 16);
    set_register(&armed, 0x320, 0x41);
    set_register(&armed, 0x3e0, APIC_DIVIDE_BY_128);
    set_register(&armed, 0x380, 1);
    set_register(&armed, 0x390, 1);
    uint64_t start = monotonic_ns();
    checked(ioctl(graph.cpu, KVM_SET_LAPIC, &armed), "program one-count timer");
    checked(ioctl(graph.cpu, KVM_GET_LAPIC, &early), "read early LAPIC");
    uint64_t sample = monotonic_ns() - start;
    require_control(sample < ONE_COUNT_NS / 2, "early sample missed its time window");
    require_control(get_register(&early, 0x380) == 1, "early TMICT differs");
    require_control(get_register(&early, 0x390) == 0, "early TMCCT is not zero");
    require_control((get_register(&early, 0x220) & 2) == 0, "early IRR asserted");
    require_control((get_register(&early, 0x120) & 2) == 0, "early ISR asserted");
    require_control(observe_timer(&graph) == 0, "timer fired in the early window");
    require_control(monotonic_ns() - start < ONE_COUNT_NS,
                    "first no-delivery observation exceeded the scheduled period");

    uint64_t delivery;
    do {
        require_control(monotonic_ns() - start < 2 * ONE_COUNT_NS, "timer never delivered");
        if (observe_timer(&graph)) {
            delivery = monotonic_ns() - start;
            break;
        }
    } while (1);
    require_control(delivery >= ONE_COUNT_NS, "timer delivered before the programmed period");

    // The next actual entry completes OUT, EOI, IRET, and returns to HLT.
    require_control(observe_timer(&graph) == 0, "one-shot produced a duplicate");
    struct kvm_regs final = {0};
    checked(ioctl(graph.cpu, KVM_GET_REGS, &final), "read final RIP");
    require_control(final.rip == 0x1002, "guest did not finish EOI and IRET");
    checked(ioctl(graph.cpu, KVM_GET_LAPIC, &done), "read completed LAPIC");
    require_control(get_register(&done, 0x380) == 1, "final TMICT differs");
    require_control(get_register(&done, 0x390) == 0, "final TMCCT differs");
    require_control((get_register(&done, 0x220) & 2) == 0, "final IRR asserted");
    require_control((get_register(&done, 0x120) & 2) == 0, "final ISR asserted");
    unsigned difference = 0;
    for (size_t i = 0; i < sizeof(early.regs); ++i)
        difference += early.regs[i] != done.regs[i];
    printf("{\"x2apic\":%d,\"programmed_ns\":%llu,\"early_sample_ns\":%llu,"
           "\"delivery_observed_ns\":%llu,\"early_tmict\":1,\"early_tmcct\":0,"
           "\"final_tmict\":1,\"final_tmcct\":0,\"early_vector_irr\":0,"
           "\"final_vector_irr\":0,\"lapic_record_different_bytes\":%u}\n",
           x2apic, (unsigned long long)ONE_COUNT_NS, (unsigned long long)sample,
           (unsigned long long)delivery, difference);
    destroy_graph(&graph);
}

int main(void)
{
    struct sigaction action = {.sa_handler = alarm_handler};
    checked(sigemptyset(&action.sa_mask), "signal mask");
    checked(sigaction(SIGALRM, &action, NULL), "alarm handler");
    int kvm = checked(open("/dev/kvm", O_RDWR | O_CLOEXEC), "open kvm");
    require_control(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_APIC_BUS_CYCLES_NS) > 0,
                    "KVM cannot configure the LAPIC bus cycle");
    zero_count_control(kvm, 0);
    zero_count_control(kvm, 1);
    checked(close(kvm), "close kvm");
    return 0;
}
