#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

struct graph {
    int kvm;
    int vm;
    int cpus[4];
    unsigned count;
};

struct frame {
    struct kvm_clock_data clock;
    uint64_t anchor;
    uint64_t clock_before;
    uint64_t offsets[4];
    uint64_t observed_tsc[4];
    unsigned khz[4];
};

static uint64_t host_tsc(void)
{
    unsigned low, high;
    /* x86-64 guarantees SSE2/LFENCE and RDTSC. The serialized sample bounds
     * the synchronous ioctls; no optional guest/host vector instruction runs. */
    __asm__ volatile("lfence; rdtsc; lfence" : "=a"(low), "=d"(high) : : "memory");
    return ((uint64_t)high << 32) | low;
}

static uint64_t raw_ns(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC_RAW, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static struct graph create(unsigned count, int irqchip)
{
    struct graph g = {.count = count};
    g.kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    assert(g.kvm >= 0 && ioctl(g.kvm, KVM_GET_API_VERSION, 0) == 12);
    g.vm = ioctl(g.kvm, KVM_CREATE_VM, 0);
    assert(g.vm >= 0);
    if (irqchip)
        assert(ioctl(g.vm, KVM_CREATE_IRQCHIP, 0) == 0);
    for (unsigned i = 0; i < count; i++) {
        g.cpus[i] = ioctl(g.vm, KVM_CREATE_VCPU, i);
        assert(g.cpus[i] >= 0);
        struct kvm_device_attr attr = {
            .group = KVM_VCPU_TSC_CTRL, .attr = KVM_VCPU_TSC_OFFSET,
        };
        assert(ioctl(g.cpus[i], KVM_HAS_DEVICE_ATTR, &attr) == 0);
    }
    return g;
}

static void destroy(struct graph *g)
{
    for (unsigned i = 0; i < g->count; i++)
        assert(close(g->cpus[i]) == 0);
    assert(close(g->vm) == 0);
    assert(close(g->kvm) == 0);
}

static uint64_t get_offset(int cpu)
{
    uint64_t offset = 0;
    struct kvm_device_attr attr = {
        .group = KVM_VCPU_TSC_CTRL, .attr = KVM_VCPU_TSC_OFFSET,
        .addr = (uintptr_t)&offset,
    };
    assert(ioctl(cpu, KVM_GET_DEVICE_ATTR, &attr) == 0);
    return offset;
}

static void set_offset(int cpu, uint64_t offset)
{
    struct kvm_device_attr attr = {
        .group = KVM_VCPU_TSC_CTRL, .attr = KVM_VCPU_TSC_OFFSET,
        .addr = (uintptr_t)&offset,
    };
    assert(ioctl(cpu, KVM_SET_DEVICE_ATTR, &attr) == 0);
    assert(get_offset(cpu) == offset);
}

static uint64_t tsc_msr(int cpu, int write, uint64_t value)
{
    struct kvm_msrs *bank = calloc(1, sizeof(*bank) + sizeof(struct kvm_msr_entry));
    assert(bank);
    bank->nmsrs = 1;
    bank->entries[0].index = 0x10;
    bank->entries[0].data = value;
    assert(ioctl(cpu, write ? KVM_SET_MSRS : KVM_GET_MSRS, bank) == 1);
    value = bank->entries[0].data;
    free(bank);
    return value;
}

static void pause_one_ms(void)
{
    struct timespec delay = {.tv_nsec = 1000000};
    assert(nanosleep(&delay, NULL) == 0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int irqchip = 0; irqchip <= 1; irqchip++) {
        for (unsigned count = 1; count <= 4; count *= 2) {
            struct graph source = create(count, irqchip);
            struct frame f = {0};
            uint64_t start = host_tsc();
            for (unsigned i = 0; i < count; i++) {
                uint64_t phase = UINT64_C(0x123456789) + i * UINT64_C(0x400000000);
                set_offset(source.cpus[i], phase - start);
                int khz = ioctl(source.cpus[i], KVM_GET_TSC_KHZ, 0);
                assert(khz > 0);
                f.khz[i] = (unsigned)khz;
                assert(i == 0 || f.khz[i] == f.khz[0]);
                f.offsets[i] = get_offset(source.cpus[i]);
                f.observed_tsc[i] = tsc_msr(source.cpus[i], 0, 0);
            }
            struct kvm_clock_data seed = {.clock = UINT64_C(10000000000)};
            assert(ioctl(source.vm, KVM_SET_CLOCK, &seed) == 0);
            f.clock_before = host_tsc();
            assert(ioctl(source.vm, KVM_GET_CLOCK, &f.clock) == 0);
            f.anchor = host_tsc();
            assert(f.anchor >= f.clock_before);
            destroy(&source);

            /* Source native owners are gone before destination construction. */
            struct graph target = create(count, irqchip);
            unsigned naive_phase_losses = 0;
            for (unsigned i = 0; i < count; i++) {
                assert(ioctl(target.cpus[i], KVM_GET_TSC_KHZ, 0) == (int)f.khz[i]);
                tsc_msr(target.cpus[i], 1, f.observed_tsc[i]);
                pause_one_ms();
                if (i && get_offset(target.cpus[i]) - get_offset(target.cpus[0]) !=
                             f.offsets[i] - f.offsets[0])
                    naive_phase_losses++;
            }
            assert(count == 1 || naive_phase_losses == count - 1);

            uint64_t resume = host_tsc();
            uint64_t delta = f.anchor - resume;
            for (unsigned i = 0; i < count; i++)
                set_offset(target.cpus[i], f.offsets[i] + delta);
            unsigned exact_phases = 0;
            unsigned bounded_tsc_reads = 0;
            for (unsigned i = 0; i < count; i++) {
                assert(get_offset(target.cpus[i]) - get_offset(target.cpus[0]) ==
                       f.offsets[i] - f.offsets[0]);
                exact_phases++;
                uint64_t low = host_tsc();
                uint64_t actual = tsc_msr(target.cpus[i], 0, 0);
                uint64_t high = host_tsc();
                uint64_t expected_low = low + f.offsets[i] + delta;
                assert(high >= low && actual - expected_low <= high - low);
                bounded_tsc_reads++;
            }
            /* Clearing REALTIME excludes paused wall time from this restore.
             * The full producer must call this at its common resume gate. */
            struct kvm_clock_data restored = {.clock = f.clock.clock};
            uint64_t before_set = raw_ns();
            assert(ioctl(target.vm, KVM_SET_CLOCK, &restored) == 0);
            struct kvm_clock_data observed = {0};
            assert(ioctl(target.vm, KVM_GET_CLOCK, &observed) == 0);
            uint64_t after_get = raw_ns();
            assert(observed.clock >= f.clock.clock);
            printf("{\"cpu_count\":%u,\"irqchip\":%s,\"source_graph_destroyed\":true,"
                   "\"naive_phase_losses\":%u,\"exact_rebased_phases\":%u,"
                   "\"bracketed_unscaled_tsc_reads\":%u,\"clock_capture_interval_ticks\":%" PRIu64 ","
                   "\"tsc_khz\":%u,\"source_clock_flags\":%u,\"source_host_tsc\":%" PRIu64 ","
                   "\"source_clock_ns\":%" PRIu64 ",\"restored_clock_ns\":%" PRIu64 ","
                   "\"clock_set_get_interval_ns\":%" PRIu64 ",\"guest_entered\":false,"
                   "\"complete_checkpoint_producer\":false}\n",
                   count, irqchip ? "true" : "false", naive_phase_losses,
                   exact_phases, bounded_tsc_reads, f.anchor - f.clock_before,
                   f.khz[0], f.clock.flags, (uint64_t)f.clock.host_tsc,
                   (uint64_t)f.clock.clock, (uint64_t)observed.clock, after_get - before_set);
            destroy(&target);
        }
    }
    return 0;
}
