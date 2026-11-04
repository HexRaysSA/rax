// Experimental x2APIC-only expired one-shot normalization control.
// The temporary raw NMI delivery mode is not a production restore contract.
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    const unsigned char handler[] = {
        0xb0, 0xa5, 0xe6, 0xe9,
        0x66, 0xb9, 0x0b, 0x08, 0x00, 0x00, // MOV ECX,IA32_X2APIC_EOI.
        0x66, 0x31, 0xc0, 0x66, 0x31, 0xd2, // EDX:EAX=0.
        0x0f, 0x30, // WRMSR.
        0xcf,
    };
    const unsigned char vector[] = {0x00, 0x20, 0x00, 0x00};
    memcpy(graph.memory + 0x1000, main_code, sizeof(main_code));
    memcpy(graph.memory + 0x2000, handler, sizeof(handler));
    memcpy(graph.memory + 0x41 * 4, vector, sizeof(vector));
    struct kvm_sregs special = {0};
    checked(ioctl(graph.cpu, KVM_GET_SREGS, &special), "get special");
    special.apic_base |= 1u << 10; // Keep x2APIC enabled on source and target.
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

// Keep the private notification blocked in userspace. KVM alone unmasks it,
// after acquiring its CPU mutex. The pending notification prevents guest entry
// but permits the architecture run loop to publish pending timer interrupts.
static void materialize_pending_timer(struct graph *graph)
{
    sigset_t blocked, previous;
    checked(sigfillset(&blocked), "fill blocked signals");
    int error = pthread_sigmask(SIG_SETMASK, &blocked, &previous);
    if (error) {
        errno = error;
        checked(-1, "block worker signals");
    }
    struct { uint32_t length; unsigned char signals[8]; } mask = {
        .length = 8,
        .signals = {255, 255, 255, 255, 255, 255, 255, 255},
    };
    int signal_number = SIGRTMAX;
    unsigned int bit = (unsigned int)signal_number - 1;
    mask.signals[bit / 8] &= (unsigned char)~(1u << (bit % 8));
    checked(ioctl(graph->cpu, KVM_SET_SIGNAL_MASK, &mask), "set entry-only signal mask");
    error = pthread_kill(pthread_self(), signal_number);
    if (error) {
        errno = error;
        checked(-1, "queue private signal");
    }
    graph->run->immediate_exit = 0;
    errno = 0;
    int result = ioctl(graph->cpu, KVM_RUN, 0);
    int run_error = errno;
    checked(ioctl(graph->cpu, KVM_SET_SIGNAL_MASK, NULL), "clear entry-only signal mask");
    sigset_t private_signal;
    checked(sigemptyset(&private_signal), "empty private signal set");
    checked(sigaddset(&private_signal, signal_number), "private signal set");
    struct timespec no_wait = {0};
    if (sigtimedwait(&private_signal, NULL, &no_wait) != signal_number) {
        fprintf(stderr, "private signal was not retained in userspace\n");
        exit(1);
    }
    error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
    if (error) {
        errno = error;
        checked(-1, "restore caller signal mask");
    }
    if (result != -1 || run_error != EINTR) {
        fprintf(stderr, "materialization returned %d/%d, exit %u\n", result,
                run_error, graph->run->exit_reason);
        exit(1);
    }
}

static void complete_output(struct graph *graph)
{
    graph->run->immediate_exit = 1;
    errno = 0;
    int result = ioctl(graph->cpu, KVM_RUN, 0);
    int error = errno;
    graph->run->immediate_exit = 0;
    if (result != -1 || error != EINTR) {
        fprintf(stderr, "output completion returned %d/%d\n", result, error);
        exit(1);
    }
}

static void normalize_expired(struct graph *target,
                              const struct kvm_lapic_state *saved,
                              const struct kvm_vcpu_events *events,
                              unsigned int *pending_nmi)
{
    struct kvm_lapic_state temporary = *saved;
    // Preserve the timer mode and its initial-count register. Only the raw
    // SET_LAPIC delivery mode is changed for this experiment.
    set_register(&temporary, 0x320,
                 (get_register(saved, 0x320) & ~0x700u) | 0x400u);
    checked(ioctl(target->cpu, KVM_SET_LAPIC, &temporary), "temporary NMI timer");
    struct kvm_mp_state original = {0};
    checked(ioctl(target->cpu, KVM_GET_MP_STATE, &original), "original MP state");
    struct kvm_mp_state halted = {.mp_state = KVM_MP_STATE_HALTED};
    checked(ioctl(target->cpu, KVM_SET_MP_STATE, &halted), "halt normalization");
    materialize_pending_timer(target);
    struct kvm_vcpu_events fake = {0};
    checked(ioctl(target->cpu, KVM_GET_VCPU_EVENTS, &fake), "materialized NMI events");
    *pending_nmi = fake.nmi.pending;
    checked(ioctl(target->cpu, KVM_SET_VCPU_EVENTS, events), "restore source events");
    // An x2APIC LVTT MSR write updates the LVT without reloading TMICT.
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entry;
    } msrs = {.header.nmsrs = 1,
              .entry = {.index = 0x832, .data = get_register(saved, 0x320)}};
    if (ioctl(target->cpu, KVM_SET_MSRS, &msrs) != 1) {
        fprintf(stderr, "LVTT MSR restore was incomplete\n");
        exit(1);
    }
    checked(ioctl(target->cpu, KVM_SET_MP_STATE, &original), "restore MP state");
}

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "pending") && strcmp(argv[1], "settled")) ||
        (strcmp(argv[2], "raw") && strcmp(argv[2], "normalize"))) {
        fprintf(stderr, "usage: %s pending|settled raw|normalize\n", argv[0]);
        return 1;
    }
    int pending = strcmp(argv[1], "pending") == 0;
    int normalize = strcmp(argv[2], "normalize") == 0;
    struct sigaction action = {.sa_handler = alarm_handler};
    checked(sigemptyset(&action.sa_mask), "signal mask");
    checked(sigaction(SIGALRM, &action, NULL), "alarm handler");
    int kvm = checked(open("/dev/kvm", O_RDWR | O_CLOEXEC), "open kvm");
    struct graph source = create_graph(kvm);
    struct kvm_lapic_state initial = {0}, saved = {0};
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &initial), "initial LAPIC");
    set_register(&initial, 0xf0, 0x1ff);
    set_register(&initial, 0x350, 1u << 16);
    set_register(&initial, 0x320, 0x41);
    set_register(&initial, 0x3e0, 0);
    set_register(&initial, 0x380, 1000000);
    set_register(&initial, 0x390, 1000000);
    checked(ioctl(source.cpu, KVM_SET_LAPIC, &initial), "arm source timer");
    struct timespec wait = {.tv_nsec = 100000000};
    checked(nanosleep(&wait, NULL), "allow source expiry");
    if (pending) {
        struct kvm_mp_state halted = {.mp_state = KVM_MP_STATE_HALTED};
        struct kvm_mp_state runnable = {.mp_state = KVM_MP_STATE_RUNNABLE};
        checked(ioctl(source.cpu, KVM_SET_MP_STATE, &halted), "halt source");
        materialize_pending_timer(&source);
        checked(ioctl(source.cpu, KVM_SET_MP_STATE, &runnable), "resume source");
    } else {
        if (observe_timer(&source) != 1) {
            fprintf(stderr, "source timer did not fire\n");
            return 1;
        }
        source.run->immediate_exit = 1;
        errno = 0;
        int result = ioctl(source.cpu, KVM_RUN, 0);
        int error = errno;
        source.run->immediate_exit = 0;
        if (result != -1 || error != EINTR || observe_timer(&source) != 0) {
            fprintf(stderr, "source one-shot did not settle\n");
            return 1;
        }
    }
    struct kvm_regs regs = {0};
    struct kvm_sregs special = {0};
    struct kvm_vcpu_events events = {0};
    struct kvm_mp_state mp = {0};
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &saved), "capture source LAPIC");
    checked(ioctl(source.cpu, KVM_GET_REGS, &regs), "capture source GPRs");
    checked(ioctl(source.cpu, KVM_GET_SREGS, &special), "capture source system registers");
    checked(ioctl(source.cpu, KVM_GET_VCPU_EVENTS, &events), "capture source events");
    checked(ioctl(source.cpu, KVM_GET_MP_STATE, &mp), "capture source MP state");
    unsigned char *memory = malloc(2 * 1024 * 1024);
    if (!memory) {
        perror("copy source RAM");
        return 1;
    }
    memcpy(memory, source.memory, 2 * 1024 * 1024);
    int source_delivery = pending ? observe_timer(&source) : 0;
    int source_extra = 0;
    if (source_delivery) {
        complete_output(&source);
        source_extra = observe_timer(&source);
    }
    destroy_graph(&source);
    struct graph target = create_graph(kvm);
    memcpy(target.memory, memory, 2 * 1024 * 1024);
    checked(ioctl(target.cpu, KVM_SET_SREGS, &special), "restore system registers");
    checked(ioctl(target.cpu, KVM_SET_REGS, &regs), "restore GPRs");
    checked(ioctl(target.cpu, KVM_SET_MP_STATE, &mp), "restore source MP state");
    checked(ioctl(target.cpu, KVM_SET_VCPU_EVENTS, &events), "restore source events");
    unsigned int pending_nmi = 0;
    if (normalize) {
        normalize_expired(&target, &saved, &events, &pending_nmi);
    } else {
        checked(ioctl(target.cpu, KVM_SET_LAPIC, &saved), "raw LAPIC restore");
    }
    struct kvm_regs after_regs = {0};
    struct kvm_sregs after_special = {0};
    struct kvm_vcpu_events after_events = {0};
    struct kvm_mp_state after_mp = {0};
    struct kvm_lapic_state after_lapic = {0};
    checked(ioctl(target.cpu, KVM_GET_REGS, &after_regs), "verify GPRs");
    checked(ioctl(target.cpu, KVM_GET_SREGS, &after_special), "verify system registers");
    checked(ioctl(target.cpu, KVM_GET_VCPU_EVENTS, &after_events), "verify events");
    checked(ioctl(target.cpu, KVM_GET_MP_STATE, &after_mp), "verify MP state");
    checked(ioctl(target.cpu, KVM_GET_LAPIC, &after_lapic), "verify LAPIC");
    int registers_equal = memcmp(&regs, &after_regs, sizeof(regs)) == 0;
    int special_equal = memcmp(&special, &after_special, sizeof(special)) == 0;
    int events_equal = memcmp(&events, &after_events, sizeof(events)) == 0;
    int mp_equal = mp.mp_state == after_mp.mp_state;
    int lapic_equal = memcmp(&saved, &after_lapic, sizeof(saved)) == 0;
    int memory_equal = memcmp(memory, target.memory, 2 * 1024 * 1024) == 0;
    free(memory);
    int target_delivery = observe_timer(&target);
    int target_extra = 0;
    if (target_delivery) {
        complete_output(&target);
        target_extra = observe_timer(&target);
    }
    printf("{\"pending_case\":%s,\"normalized\":%s,\"source_delivery\":%d,"
           "\"target_delivery\":%d,\"source_extra\":%d,\"target_extra\":%d,\"fake_nmi_pending\":%u,"
           "\"registers_equal\":%s,\"special_equal\":%s,\"events_equal\":%s,"
           "\"mp_equal\":%s,\"lapic_equal\":%s,\"memory_equal\":%s,"
           "\"saved_initial_count\":%u,\"restored_initial_count\":%u,"
           "\"saved_current_count\":%u,\"source_destroyed_before_restore\":true}\n",
           pending ? "true" : "false", normalize ? "true" : "false", source_delivery,
           target_delivery, source_extra, target_extra, pending_nmi, registers_equal ? "true" : "false",
           special_equal ? "true" : "false", events_equal ? "true" : "false",
           mp_equal ? "true" : "false", lapic_equal ? "true" : "false",
           memory_equal ? "true" : "false", get_register(&saved, 0x380),
           get_register(&after_lapic, 0x380), get_register(&saved, 0x390));
    destroy_graph(&target);
    checked(close(kvm), "close KVM");
    return 0;
}
