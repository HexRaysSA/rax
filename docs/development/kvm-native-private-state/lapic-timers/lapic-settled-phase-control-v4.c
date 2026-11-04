// Independent KVM UAPI control: acknowledged one-shot state versus GET/SET_LAPIC.
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

int main(void)
{
    struct sigaction action = {.sa_handler = alarm_handler};
    checked(sigemptyset(&action.sa_mask), "signal mask");
    checked(sigaction(SIGALRM, &action, NULL), "alarm handler");
    int kvm = checked(open("/dev/kvm", O_RDWR | O_CLOEXEC), "open kvm");
    struct graph source = create_graph(kvm);
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
    struct kvm_lapic_state pending = saved;
    int source_first = observe_timer(&source);
    source.run->immediate_exit = 1;
    errno = 0;
    int completion_result = ioctl(source.cpu, KVM_RUN, 0);
    int completion_error = errno;
    source.run->immediate_exit = 0;
    if (completion_result != -1 || completion_error != EINTR) {
        fprintf(stderr, "unexpected completion result %d errno %d exit %u\n",
                completion_result, completion_error, source.run->exit_reason);
        return 1;
    }
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &saved), "capture delivered lapic");
    struct kvm_regs regs = {0};
    struct kvm_sregs special = {0};
    checked(ioctl(source.cpu, KVM_GET_REGS, &regs), "capture delivered regs");
    checked(ioctl(source.cpu, KVM_GET_SREGS, &special), "capture delivered sregs");
    unsigned char *saved_memory = malloc(2 * 1024 * 1024);
    if (!saved_memory) {
        perror("saved memory");
        return 1;
    }
    memcpy(saved_memory, source.memory, 2 * 1024 * 1024);
    uint32_t current = get_register(&saved, 0x390);
    uint32_t irr = get_register(&saved, 0x220) & (1u << 1);
    uint32_t isr = get_register(&saved, 0x120) & (1u << 1);
    int source_extra = observe_timer(&source);
    struct kvm_lapic_state completed = {0};
    checked(ioctl(source.cpu, KVM_GET_LAPIC, &completed), "capture completed lapic");
    struct kvm_regs after_run = {0};
    checked(ioctl(source.cpu, KVM_GET_REGS, &after_run), "source final regs");
    unsigned int different_bytes = 0;
    for (size_t index = 0; index < sizeof(pending.regs); ++index) {
        different_bytes += pending.regs[index] != completed.regs[index];
    }
    destroy_graph(&source);
    struct graph target = create_graph(kvm);
    memcpy(target.memory, saved_memory, 2 * 1024 * 1024);
    free(saved_memory);
    checked(ioctl(target.cpu, KVM_SET_SREGS, &special), "restore delivered sregs");
    checked(ioctl(target.cpu, KVM_SET_REGS, &regs), "restore delivered regs");
    checked(ioctl(target.cpu, KVM_SET_LAPIC, &saved), "restore delivered lapic");
    int target_extra = observe_timer(&target);
    printf("{\"saved_current_count\":%u,\"saved_vector_irr\":%u,"
           "\"saved_vector_isr\":%u,\"source_first\":%d,"
           "\"source_extra\":%d,\"target_extra\":%d,"
           "\"source_destroyed_before_restore\":true,\"pending_irr\":%u,"
           "\"completed_irr\":%u,\"completed_isr\":%u,"
           "\"lapic_record_different_bytes\":%u,\"saved_rip\":%llu,"
           "\"source_final_rip\":%llu}\n",
           current, irr, isr, source_first, source_extra, target_extra,
           get_register(&pending, 0x220) & (1u << 1),
           get_register(&completed, 0x220) & (1u << 1),
           get_register(&completed, 0x120) & (1u << 1), different_bytes,
           (unsigned long long)regs.rip, (unsigned long long)after_run.rip);
    destroy_graph(&target);
    checked(close(kvm), "close kvm");
    return 0;
}
