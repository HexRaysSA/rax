// Native KVM IRQ0 acknowledgment control using a real-mode guest.
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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
    const unsigned char vector[] = {0x00, 0x20, 0x00, 0x00};
    memcpy(graph.memory + 0x1000, main_code, sizeof(main_code));
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

static int marker(struct graph *graph)
{
    timed_out = 0;
    struct itimerval timer = {.it_value = {.tv_usec = 200000}};
    checked(setitimer(ITIMER_REAL, &timer, NULL), "arm timeout");
    int result = ioctl(graph->cpu, KVM_RUN, 0);
    int error = errno;
    struct itimerval disarm = {0};
    checked(setitimer(ITIMER_REAL, &disarm, NULL), "disarm timeout");
    if (result < 0 && error == EINTR && timed_out) {
        return -1;
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
    return *data;
}

static void destroy_graph(struct graph *graph)
{
    checked(munmap(graph->run, graph->run_size), "unmap run");
    checked(close(graph->cpu), "close cpu");
    checked(close(graph->vm), "close vm");
    checked(munmap(graph->memory, 2 * 1024 * 1024), "unmap guest");
}


static void pulse(int vm, uint32_t gsi)
{
    struct kvm_irq_level irq = {.irq = gsi, .level = 1};
    checked(ioctl(vm, KVM_IRQ_LINE, &irq), "assert GSI");
    irq.level = 0;
    checked(ioctl(vm, KVM_IRQ_LINE, &irq), "deassert GSI");
}

struct observer {
    int trigger_fd;
    int ack_fd;
    uint32_t gsi;
};

static struct observer attach_observer(int vm, uint32_t gsi)
{
    struct observer observer = {
        .trigger_fd = checked(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC), "create trigger fd"),
        .ack_fd = checked(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC), "create ack fd"),
        .gsi = gsi,
    };
    struct kvm_irqfd irqfd = {
        .fd = (uint32_t)observer.trigger_fd,
        .gsi = gsi,
        .flags = KVM_IRQFD_FLAG_RESAMPLE,
        .resamplefd = (uint32_t)observer.ack_fd,
    };
    checked(ioctl(vm, KVM_IRQFD, &irqfd), "attach resample observer");
    return observer;
}

static void detach_observer(int vm, struct observer observer)
{
    struct kvm_irqfd irqfd = {
        .fd = (uint32_t)observer.trigger_fd,
        .gsi = observer.gsi,
        .flags = KVM_IRQFD_FLAG_DEASSIGN,
    };
    checked(ioctl(vm, KVM_IRQFD, &irqfd), "detach resample observer");
    checked(close(observer.trigger_fd), "close trigger fd");
    checked(close(observer.ack_fd), "close ack fd");
}

static uint64_t observed_acks(struct observer observer)
{
    eventfd_t count = 0;
    if (eventfd_read(observer.ack_fd, &count) < 0 && errno != EAGAIN) {
        perror("read ack eventfd");
        exit(1);
    }
    return count;
}

enum route {
    PIC_EOI, PIC_AUTO_EOI, IOAPIC_EDGE, IOAPIC_LEVEL, MASKED, SHARED_VECTOR,
};

static void program_route(struct graph *graph, enum route route)
{
    const int pic_route = route == PIC_EOI || route == PIC_AUTO_EOI;
    struct kvm_lapic_state lapic = {0};
    checked(ioctl(graph->cpu, KVM_GET_LAPIC, &lapic), "read LAPIC");
    set_register(&lapic, 0xf0, 0x1ff);
    set_register(&lapic, 0x350, pic_route ? 7u << 8 : 1u << 16);
    checked(ioctl(graph->cpu, KVM_SET_LAPIC, &lapic), "enable LAPIC");

    struct kvm_irqchip pic = {.chip_id = KVM_IRQCHIP_PIC_MASTER};
    checked(ioctl(graph->vm, KVM_GET_IRQCHIP, &pic), "read PIC");
    pic.chip.pic.irq_base = 0x40;
    pic.chip.pic.imr = pic_route ? 0xfe : 0xff;
    pic.chip.pic.auto_eoi = route == PIC_AUTO_EOI;
    checked(ioctl(graph->vm, KVM_SET_IRQCHIP, &pic), "program PIC");
    memcpy(graph->memory + 0x40 * 4, graph->memory + 0x41 * 4, 4);

    struct kvm_irqchip ioapic = {.chip_id = KVM_IRQCHIP_IOAPIC};
    checked(ioctl(graph->vm, KVM_GET_IRQCHIP, &ioapic), "read I/O APIC");
    switch (route) {
    case IOAPIC_EDGE:
        ioapic.chip.ioapic.redirtbl[0].bits = 0x41;
        break;
    case IOAPIC_LEVEL:
        ioapic.chip.ioapic.redirtbl[0].bits = 0x41 | (1u << 15);
        break;
    case SHARED_VECTOR:
        ioapic.chip.ioapic.redirtbl[0].bits = 0x41 | (1u << 16);
        ioapic.chip.ioapic.redirtbl[5].bits = 0x41;
        break;
    default:
        break;
    }
    checked(ioctl(graph->vm, KVM_SET_IRQCHIP, &ioapic), "program I/O APIC");
    const unsigned char pic_handler[] = {
        0xb0, 0xa1, 0xe6, 0xe9, /* report handler entry */
        0xb0, 0x20, 0xe6, 0x20, /* PIC nonspecific EOI */
        0xb0, 0xa2, 0xe6, 0xe9, /* report after EOI */
        0xcf,
    };
    const unsigned char lapic_handler[] = {
        0xb0, 0xa1, 0xe6, 0xe9, /* report handler entry */
        0x67, 0x66, 0xc7, 0x05, 0xb0, 0x00, 0xe0, 0xfe, 0, 0, 0, 0, /* LAPIC EOI */
        0xb0, 0xa2, 0xe6, 0xe9, /* report after EOI */
        0xcf,
    };
    if (pic_route) {
        memcpy(graph->memory + 0x2000, pic_handler, sizeof(pic_handler));
    } else {
        memcpy(graph->memory + 0x2000, lapic_handler, sizeof(lapic_handler));
    }

}

static int run_case(int kvm, enum route route, const char *name)
{
    struct graph graph = create_graph(kvm);
    program_route(&graph, route);

    struct observer timer = attach_observer(graph.vm, 0);
    struct observer other = {0};
    int shared = route == SHARED_VECTOR;
    if (shared)
        other = attach_observer(graph.vm, 5);

    int idle_marker = marker(&graph);
    uint64_t idle_ack = observed_acks(timer);
    pulse(graph.vm, shared ? 5 : 0);
    uint64_t pulse_ack = observed_acks(timer);
    int entry_marker = marker(&graph);
    uint64_t entry_ack = observed_acks(timer);
    int eoi_marker = marker(&graph);
    uint64_t eoi_ack = observed_acks(timer);
    uint64_t other_ack = shared ? observed_acks(other) : 0;
    int extra_marker = marker(&graph);
    uint64_t extra_ack = observed_acks(timer);

    printf("{\"route\":\"%s\",\"markers\":[%d,%d,%d,%d],"
           "\"irq0_acks\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],"
           "\"irq5_acks\":%" PRIu64 "}\n",
           name, idle_marker, entry_marker, eoi_marker, extra_marker,
           idle_ack, pulse_ack, entry_ack, eoi_ack, extra_ack, other_ack);

    if (shared)
        detach_observer(graph.vm, other);
    detach_observer(graph.vm, timer);
    destroy_graph(&graph);

    if (idle_marker != -1 || idle_ack || pulse_ack || extra_marker != -1 || extra_ack)
        return 0;
    if (route == MASKED)
        return entry_marker == -1 && eoi_marker == -1 && entry_ack == 0 && eoi_ack == 0;
    if (entry_marker != 0xa1 || eoi_marker != 0xa2)
        return 0;
    if (route == PIC_AUTO_EOI)
        return entry_ack == 1 && eoi_ack == 0;
    return entry_ack == 0 && eoi_ack == 1 && other_ack == (uint64_t)shared;
}

enum cut { AFTER_PULSE, BEFORE_EOI, AFTER_EOI };

struct stopped_pc {
    unsigned char *memory;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_mp_state mp;
    struct kvm_vcpu_events events;
    struct kvm_lapic_state lapic;
    struct kvm_irqchip controllers[3];
};

static void settle_marker(struct graph *graph)
{
    /* The preceding PIO exit completed in userspace. Set immediate_exit so
     * KVM retires the emulated instruction without starting another one. */
    graph->run->immediate_exit = 1;
    int result = ioctl(graph->cpu, KVM_RUN, 0);
    int error = errno;
    graph->run->immediate_exit = 0;
    if (result != -1 || error != EINTR) {
        fprintf(stderr, "failed to settle marker, result %d errno %d\n", result, error);
        exit(1);
    }
}

static struct stopped_pc capture_pc(struct graph *graph)
{
    size_t size = 2 * 1024 * 1024;
    struct stopped_pc state = {
        .memory = malloc(size),
        .controllers = {
            {.chip_id = KVM_IRQCHIP_PIC_MASTER},
            {.chip_id = KVM_IRQCHIP_PIC_SLAVE},
            {.chip_id = KVM_IRQCHIP_IOAPIC},
        },
    };
    if (!state.memory) {
        perror("allocate stopped RAM");
        exit(1);
    }
    memcpy(state.memory, graph->memory, size);
    checked(ioctl(graph->cpu, KVM_GET_REGS, &state.regs), "capture regs");
    checked(ioctl(graph->cpu, KVM_GET_SREGS, &state.sregs), "capture special regs");
    checked(ioctl(graph->cpu, KVM_GET_MP_STATE, &state.mp), "capture MP state");
    checked(ioctl(graph->cpu, KVM_GET_VCPU_EVENTS, &state.events), "capture events");
    checked(ioctl(graph->cpu, KVM_GET_LAPIC, &state.lapic), "capture LAPIC");
    for (size_t i = 0; i < sizeof(state.controllers) / sizeof(state.controllers[0]); ++i)
        checked(ioctl(graph->vm, KVM_GET_IRQCHIP, &state.controllers[i]), "capture IRQ chip");
    return state;
}

static void restore_pc(struct graph *graph, const struct stopped_pc *state)
{
    memcpy(graph->memory, state->memory, 2 * 1024 * 1024);
    for (size_t i = 0; i < sizeof(state->controllers) / sizeof(state->controllers[0]); ++i)
        checked(ioctl(graph->vm, KVM_SET_IRQCHIP, &state->controllers[i]), "restore IRQ chip");
    checked(ioctl(graph->cpu, KVM_SET_SREGS, &state->sregs), "restore special regs");
    checked(ioctl(graph->cpu, KVM_SET_REGS, &state->regs), "restore regs");
    checked(ioctl(graph->cpu, KVM_SET_LAPIC, &state->lapic), "restore LAPIC");
    checked(ioctl(graph->cpu, KVM_SET_VCPU_EVENTS, &state->events), "restore events");
    checked(ioctl(graph->cpu, KVM_SET_MP_STATE, &state->mp), "restore MP state");
}

static void require(int condition, const char *meaning)
{
    if (!condition) {
        fprintf(stderr, "probe failed: %s\n", meaning);
        exit(1);
    }
}

static void run_continuation(int kvm, enum route route, const char *name, enum cut cut)
{
    struct graph original = create_graph(kvm);
    program_route(&original, route);
    struct observer source = attach_observer(original.vm, 0);
    require(marker(&original) == -1, "original halted before observer event");
    pulse(original.vm, 0);
    if (cut != AFTER_PULSE) {
        require(marker(&original) == 0xa1, "original entered interrupt handler");
        if (cut == AFTER_EOI)
            require(marker(&original) == 0xa2, "original wrote EOI");
        settle_marker(&original);
    }
    uint64_t source_acks = observed_acks(source);
    struct stopped_pc saved = capture_pc(&original);
    detach_observer(original.vm, source);
    destroy_graph(&original);

    struct graph replacement = create_graph(kvm);
    restore_pc(&replacement, &saved);
    free(saved.memory);
    struct observer target = attach_observer(replacement.vm, 0);
    uint64_t replacement_idle_acks = observed_acks(target);
    int first = marker(&replacement);
    int second = cut == AFTER_PULSE ? marker(&replacement) : -1;
    int extra = marker(&replacement);
    uint64_t replacement_acks = observed_acks(target);

    printf("{\"continuation\":\"%s\",\"cut\":%d,\"source_acks\":%" PRIu64
           ",\"replacement_idle_acks\":%" PRIu64 ",\"replacement_acks\":%" PRIu64
           ",\"replacement_markers\":[%d,%d,%d]}\n",
           name, cut, source_acks, replacement_idle_acks, replacement_acks,
           first, second, extra);
    detach_observer(replacement.vm, target);
    destroy_graph(&replacement);

    require(replacement_idle_acks == 0, "attaching observer must not invent an event");
    require(extra == -1, "continuation must not duplicate the interrupt");
    require(source_acks == (uint64_t)(cut == AFTER_EOI ||
            (cut == BEFORE_EOI && route == PIC_AUTO_EOI)), "expected source ack phase");
    require(source_acks + replacement_acks == 1, "exactly one ack across the cut");
    require(first == (cut == AFTER_PULSE ? 0xa1 : cut == BEFORE_EOI ? 0xa2 : -1),
            "first replacement marker matches the cut");
    require(second == (cut == AFTER_PULSE ? 0xa2 : -1), "replacement EOI marker");
}

static void run_dual_route(int kvm)
{
    struct graph graph = create_graph(kvm);
    program_route(&graph, PIC_EOI);
    struct kvm_irqchip ioapic = {.chip_id = KVM_IRQCHIP_IOAPIC};
    checked(ioctl(graph.vm, KVM_GET_IRQCHIP, &ioapic), "read I/O APIC for dual route");
    ioapic.chip.ioapic.redirtbl[0].bits = 0x41;
    checked(ioctl(graph.vm, KVM_SET_IRQCHIP, &ioapic), "program I/O APIC for dual route");
    const unsigned char second_vector[] = {0x00, 0x21, 0x00, 0x00};
    const unsigned char second_handler[] = {
        0xb0, 0xb1, 0xe6, 0xe9, /* report I/O APIC handler entry */
        0x67, 0x66, 0xc7, 0x05, 0xb0, 0, 0xe0, 0xfe, 0, 0, 0, 0,
        0xb0, 0xb2, 0xe6, 0xe9, /* report LAPIC EOI */
        0xcf,
    };
    memcpy(graph.memory + 0x41 * 4, second_vector, sizeof(second_vector));
    memcpy(graph.memory + 0x2100, second_handler, sizeof(second_handler));
    struct observer timer = attach_observer(graph.vm, 0);

    require(marker(&graph) == -1 && observed_acks(timer) == 0,
            "dual route idle before pulse");
    pulse(graph.vm, 0);
    int entry[2], eoi[2];
    uint64_t entry_acks[2], eoi_acks[2];
    for (size_t i = 0; i < 2; ++i) {
        entry[i] = marker(&graph);
        entry_acks[i] = observed_acks(timer);
        eoi[i] = marker(&graph);
        eoi_acks[i] = observed_acks(timer);
    }
    int extra = marker(&graph);
    uint64_t extra_acks = observed_acks(timer);
    printf("{\"dual_route\":true,\"entry_markers\":[%d,%d],\"eoi_markers\":[%d,%d],"
           "\"entry_acks\":[%" PRIu64 ",%" PRIu64 "],\"eoi_acks\":[%" PRIu64 ",%" PRIu64
           "],\"extra_marker\":%d,\"extra_acks\":%" PRIu64 "}\n",
           entry[0], entry[1], eoi[0], eoi[1],
           entry_acks[0], entry_acks[1], eoi_acks[0], eoi_acks[1], extra, extra_acks);
    detach_observer(graph.vm, timer);
    destroy_graph(&graph);

    require((entry[0] == 0xa1 && entry[1] == 0xb1) ||
            (entry[0] == 0xb1 && entry[1] == 0xa1), "one guest entry per enabled controller");
    for (size_t i = 0; i < 2; ++i) {
        require(eoi[i] == entry[i] + 1, "corresponding EOI marker");
        require(entry_acks[i] == 0 && eoi_acks[i] == 1, "one ack per EOI");
    }
    require(extra == -1 && extra_acks == 0, "no third delivery or acknowledgement");
}

int main(void)
{
    struct sigaction action = {.sa_handler = alarm_handler};
    checked(sigemptyset(&action.sa_mask), "signal mask");
    checked(sigaction(SIGALRM, &action, NULL), "alarm handler");
    int kvm = checked(open("/dev/kvm", O_RDWR | O_CLOEXEC), "open kvm");
    if (checked(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IRQFD_RESAMPLE), "resample capability") <= 0)
        return 2;
    const char *names[] = {"pic-eoi", "pic-auto-eoi", "ioapic-edge", "ioapic-level",
                           "masked", "ioapic-shared-vector"};
    for (int trial = 0; trial < 5; ++trial)
        run_dual_route(kvm);
    int valid = 1;
    for (int trial = 0; trial < 5; ++trial) {
        for (unsigned int route = 0; route < sizeof(names) / sizeof(*names); ++route)
            valid &= run_case(kvm, (enum route)route, names[route]);
    }
    if (checked(ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT), "immediate exit") <= 0)
        return 2;
    for (int trial = 0; trial < 5; ++trial) {
        for (int route = PIC_EOI; route <= IOAPIC_LEVEL; ++route) {
            for (int cut = AFTER_PULSE; cut <= AFTER_EOI; ++cut)
                run_continuation(kvm, (enum route)route, names[route], (enum cut)cut);
        }
    }
    checked(close(kvm), "close kvm");
    return !valid;
}
