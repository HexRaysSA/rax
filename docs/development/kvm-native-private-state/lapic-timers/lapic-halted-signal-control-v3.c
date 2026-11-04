// Independent KVM control: materialize a pending LAPIC timer without guest execution.
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
    const unsigned char handler[] = {0xb0, 0xa5, 0xe6, 0xe9, 0xf4};
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

static void destroy_graph(struct graph *graph)
{
    checked(munmap(graph->run, graph->run_size), "unmap run");
    checked(close(graph->cpu), "close cpu");
    checked(close(graph->vm), "close vm");
    checked(munmap(graph->memory, 2 * 1024 * 1024), "unmap guest");
}

int main(int argc, char **argv)
{
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "if1") != 0)) {
        fprintf(stderr, "usage: %s [if1]\n", argv[0]);
        return 1;
    }
    int interrupts_enabled = argc == 2;
    struct sigaction action = {.sa_handler = alarm_handler};
    checked(sigemptyset(&action.sa_mask), "signal mask");
    checked(sigaction(SIGALRM, &action, NULL), "alarm handler");
    int kvm = checked(open("/dev/kvm", O_RDWR | O_CLOEXEC), "open kvm");
    struct graph source = create_graph(kvm);
    if (interrupts_enabled) {
        struct kvm_regs regs = {0};
        checked(ioctl(source.cpu, KVM_GET_REGS, &regs), "get initial flags");
        regs.rflags |= 1u << 9;
        checked(ioctl(source.cpu, KVM_SET_REGS, &regs), "enable guest interrupts");
    }
    struct kvm_lapic_state initial = {0}, saved = {0};
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &initial), "initial lapic");
    set_register(&initial, 0xf0, 0x1ff);
    set_register(&initial, 0x350, 1u << 16);
    set_register(&initial, 0x320, 0x41);
    set_register(&initial, 0x3e0, 0);
    set_register(&initial, 0x380, 1000000);
    set_register(&initial, 0x390, 1000000);
    checked(ioctl(source.cpu, KVM_SET_LAPIC, &initial), "arm one-shot");
    struct timespec wait = {.tv_nsec = 100000000};
    checked(nanosleep(&wait, NULL), "allow expiry");
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &saved), "capture expired lapic");
    uint32_t current = get_register(&saved, 0x390);
    uint32_t irr = get_register(&saved, 0x220) & (1u << 1);
    struct kvm_sregs special_before = {0}, special_after = {0};
    checked(ioctl(source.cpu, KVM_GET_SREGS, &special_before), "special registers before materialization");
    struct kvm_regs before = {0}, after = {0};
    checked(ioctl(source.cpu, KVM_GET_REGS, &before), "capture registers before materialization");
    unsigned char *ram_before = malloc(2 * 1024 * 1024);
    if (!ram_before) {
        perror("copy RAM");
        exit(1);
    }
    memcpy(ram_before, source.memory, 2 * 1024 * 1024);
    struct kvm_mp_state original_mp = {0};
    checked(ioctl(source.cpu, KVM_GET_MP_STATE, &original_mp), "capture original MP state");
    struct kvm_mp_state halted_mp = {.mp_state = KVM_MP_STATE_HALTED};
    checked(ioctl(source.cpu, KVM_SET_MP_STATE, &halted_mp), "temporary halted MP state");
    materialize_pending_timer(&source);
    checked(ioctl(source.cpu, KVM_SET_MP_STATE, &original_mp), "restore original MP state");
    checked(ioctl(source.cpu, KVM_GET_REGS, &after), "capture registers after materialization");
    checked(ioctl(source.cpu, KVM_GET_SREGS, &special_after), "special registers after materialization");
    struct kvm_mp_state final_mp = {0};
    checked(ioctl(source.cpu, KVM_GET_MP_STATE, &final_mp), "final MP state");
    int special_unchanged = memcmp(&special_before, &special_after, sizeof(special_before)) == 0;
    int mp_unchanged = original_mp.mp_state == final_mp.mp_state;
    int registers_unchanged = memcmp(&before, &after, sizeof(before)) == 0;
    int ram_unchanged = memcmp(ram_before, source.memory, 2 * 1024 * 1024) == 0;
    free(ram_before);
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &saved), "capture materialized timer");
    uint32_t materialized_irr = get_register(&saved, 0x220) & (1u << 1);
    if (!registers_unchanged || !ram_unchanged || !special_unchanged || !mp_unchanged ||
        materialized_irr != (1u << 1)) {
        fprintf(stderr, "materialization failed: regs=%d RAM=%d IRR=%u\n",
                registers_unchanged, ram_unchanged, materialized_irr);
        fprintf(stderr, "special=%d MP=%d\n", special_unchanged, mp_unchanged);
        exit(1);
    }
    int source_delivered = observe_timer(&source);
    destroy_graph(&source);
    struct graph target = create_graph(kvm);
    checked(ioctl(target.cpu, KVM_SET_LAPIC, &saved), "restore expired lapic");
    int restored_delivered = observe_timer(&target);
    printf("{\"saved_current_count\":%u,\"saved_vector_irr\":%u,"
           "\"source_delivered\":%d,\"restored_delivered\":%d,"
           "\"source_destroyed_before_restore\":true,"
           "\"materialized_irr\":%u,\"registers_unchanged\":%s,\"ram_unchanged\":%s,"
           "\"special_registers_unchanged\":%s,\"mp_state_unchanged\":%s,"
           "\"guest_if\":%d}\n",
           current, irr, source_delivered, restored_delivered, materialized_irr,
           registers_unchanged ? "true" : "false", ram_unchanged ? "true" : "false",
           special_unchanged ? "true" : "false", mp_unchanged ? "true" : "false",
           interrupts_enabled);
    destroy_graph(&target);
    checked(close(kvm), "close kvm");
    return 0;
}
