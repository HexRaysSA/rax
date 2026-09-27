// Deferred memory reclamation: the ring libmalloc allocates at start-up
// (arm64), and, in a process libmalloc gives none (named AegirPoster), a
// ring of its own: allocation, a second one refused, the accounting trap,
// entries reclaimed by flush (deallocated, freed, unaligned, cancelled,
// empty), resize, the kernel's errors, fork, and a deallocation over a hole.
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

// osfmk/mach/vm_reclaim_private.h (not in the SDK).
typedef uint64_t reclaim_id_t;
struct reclaim_entry {
    mach_vm_address_t address;
    uint32_t size;
    uint8_t behavior;
    uint8_t unused[3];
};
struct reclaim_ring {
    uint64_t va_in_buffer, last_accounting;
    uint32_t len, max_len;
    uint64_t indices[3];
    uint64_t sampling_period_abs, last_sample_abs, next_sample_deadline_abs;
    uint64_t reclaimable_bytes, reclaimable_bytes_min;
    uint64_t head, busy, tail;
    uint64_t unused[2];
    struct reclaim_entry entries[];
};
typedef struct reclaim_ring *ring_t;
struct ring_ref {
    mach_vm_address_t addr;
    mach_vm_size_t size;
};
#define FREE 1
#define DEALLOCATE 2

int mach_vm_reclaim_ring_allocate(ring_t *, uint32_t, uint32_t);
int mach_vm_reclaim_ring_flush(ring_t, uint32_t);
int mach_vm_reclaim_ring_resize(ring_t, uint32_t);
int mach_vm_reclaim_try_enter(ring_t, mach_vm_address_t, mach_vm_size_t, uint8_t, reclaim_id_t *, bool *);
int mach_vm_reclaim_try_cancel(ring_t, reclaim_id_t, mach_vm_address_t, mach_vm_size_t, uint8_t, uint32_t *, bool *);
int mach_vm_reclaim_query_state(ring_t, reclaim_id_t, uint8_t, uint32_t *);
int mach_vm_reclaim_get_rings_for_task(task_read_t, struct ring_ref *, uint32_t *);
uint32_t mach_vm_reclaim_round_capacity(uint32_t);
kern_return_t mach_vm_reclaim_update_kernel_accounting_trap(mach_port_name_t, uint64_t *, uint64_t *);
kern_return_t mach_vm_deferred_reclamation_buffer_allocate(task_t, mach_vm_address_t *, uint64_t *, uint32_t, uint32_t);
kern_return_t mach_vm_deferred_reclamation_buffer_flush(task_t, uint32_t, uint64_t *, uint64_t *);
kern_return_t mach_vm_deferred_reclamation_buffer_resize(task_t, uint32_t, uint64_t *, uint64_t *);
kern_return_t mach_vm_deferred_reclamation_buffer_query(task_read_t, mach_vm_address_t *, mach_vm_size_t *);

static uint64_t ten_seconds;

struct region {
    mach_vm_address_t addr;
    mach_vm_size_t size;
    int prot, max, inherit, tag;
};

// The region containing `addr` (or the next).
static struct region region_at(mach_vm_address_t addr) {
    struct region r = {addr, 0, -1, -1, -1, -1};
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 0;
    if (mach_vm_region_recurse(mach_task_self(), &r.addr, &r.size, &depth, (vm_region_recurse_info_t)&info, &cnt) ==
        KERN_SUCCESS) {
        r.prot = info.protection;
        r.max = info.max_protection;
        r.inherit = info.inheritance;
        r.tag = info.user_tag;
    }
    return r;
}

static bool mapped(mach_vm_address_t addr) {
    struct region r = region_at(addr);
    return r.prot >= 0 && r.addr <= addr && addr < r.addr + r.size;
}

// Regions tagged VM_MEMORY_VM_RECLAIM, and the protections of the last.
static int tagged(int *prot, int *max) {
    int n = 0;
    mach_vm_address_t a = 0;
    for (;;) {
        struct region r = region_at(a);
        if (r.prot < 0)
            break;
        if (r.tag == 22) {
            n++;
            *prot = r.prot;
            *max = r.max;
        }
        a = r.addr + r.size;
    }
    return n;
}

static void indices(const char *what, ring_t r) {
    printf("  %s: head %llu busy %llu tail %llu\n", what, r->head, r->busy, r->tail);
}

static mach_vm_address_t pages(int n) {
    mach_vm_address_t a = 0;
    mach_vm_allocate(mach_task_self(), &a, (mach_vm_size_t)n * vm_page_size, VM_FLAGS_ANYWHERE);
    memset((void *)a, 0xab, (size_t)n * vm_page_size);
    return a;
}

// Enters a new region into the ring: its ID (UINT64_MAX when full).
static reclaim_id_t enter(ring_t r, mach_vm_address_t addr, mach_vm_size_t size, uint8_t behavior) {
    reclaim_id_t id = UINT64_MAX;
    bool upd;
    int kr = mach_vm_reclaim_try_enter(r, addr, size, behavior, &id, &upd);
    if (kr != 0)
        printf("  try_enter %#x\n", kr);
    return id;
}

static const char *state(uint32_t s) {
    static const char *names[] = {"?", "UNRECLAIMED", "FREED", "DEALLOCATED", "BUSY"};
    return s < 5 ? names[s] : "?";
}

static void fresh(void) {
    uint64_t bytes = 7, deadline = 7;
    mach_vm_address_t qa = 1;
    mach_vm_size_t qs = 1;
    kern_return_t kr = mach_vm_deferred_reclamation_buffer_query(mach_task_self(), &qa, &qs);
    if (qa != 0) {
        printf("already has a ring\n");
        return;
    }
    printf("no ring: query %#x (%llu, %llu)", kr, qa, qs);
    printf(" trap %#x (%llu, %llu)", mach_vm_reclaim_update_kernel_accounting_trap(mach_task_self(), &bytes, &deadline),
           bytes, deadline);
    printf(" flush %#x", mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline));
    printf(" resize %#x\n", mach_vm_deferred_reclamation_buffer_resize(mach_task_self(), 1, &bytes, &deadline));
    mach_vm_address_t a;
    printf("allocate len 0 %#x, max below len %#x, too large %#x\n",
           mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(), &a, &deadline, 0, 8),
           mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(), &a, &deadline, 8, 4),
           mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(), &a, &deadline, 1, 8388601));
    printf("round capacity: 1 -> %u, 1017 -> %u\n", mach_vm_reclaim_round_capacity(1),
           mach_vm_reclaim_round_capacity(1017));

    ring_t R = NULL;
    uint64_t before = mach_absolute_time();
    kr = mach_vm_reclaim_ring_allocate(&R, 8, 1016);
    struct region rr = region_at((mach_vm_address_t)R);
    printf("allocate: %#x size %#llx prot %d/%d inherit %d tag %d len %u max %u\n", kr, rr.size, rr.prot, rr.max,
           rr.inherit, rr.tag, R->len, R->max_len);
    printf("  deadline in ten seconds %d\n", R->next_sample_deadline_abs - before >= ten_seconds &&
                                                 R->next_sample_deadline_abs - before < 2 * ten_seconds);
    indices("fresh", R);
    struct ring_ref ref;
    uint32_t count = 1;
    kr = mach_vm_reclaim_get_rings_for_task(mach_task_self(), &ref, &count);
    printf("  rings %#x %u same %d\n", kr, count, ref.addr == (mach_vm_address_t)R && ref.size == rr.size);
    int prot = -1, max = -1;
    int n0 = tagged(&prot, &max);
    kr = mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(), &a, &deadline, 8, 1016);
    int n1 = tagged(&prot, &max);
    printf("second allocate %#x: tagged regions %d -> %d, the new one %d/%d\n", kr, n0, n1, prot, max);

    uint64_t d0 = 0, d1 = 0;
    kr = mach_vm_reclaim_update_kernel_accounting_trap(mach_task_self(), &bytes, &d0);
    printf("trap %#x bytes %llu", kr, bytes);
    kr = mach_vm_reclaim_update_kernel_accounting_trap(mach_task_self(), &bytes, &d1);
    printf(", again %#x bytes %llu same deadline %d\n", kr, bytes, d0 == d1);
    printf("trap NULL %#x, null task %#x\n",
           mach_vm_reclaim_update_kernel_accounting_trap(mach_task_self(), NULL, &d0),
           mach_vm_reclaim_update_kernel_accounting_trap(MACH_PORT_NULL, &bytes, &d0));

    // A deallocated entry.
    bool upd;
    mach_vm_address_t x = pages(3);
    reclaim_id_t id = enter(R, x, 3 * vm_page_size, DEALLOCATE);
    uint32_t st = 0;
    mach_vm_reclaim_query_state(R, id, DEALLOCATE, &st);
    printf("enter id %llu %s\n", id, state(st));
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    printf("flush %#x pages %llu mapped %d\n", kr, bytes / vm_page_size, mapped(x));
    indices("after", R);
    mach_vm_reclaim_query_state(R, id, DEALLOCATE, &st);
    printf("  %s\n", state(st));

    // A freed entry keeps its mapping and contents.
    x = pages(4);
    id = enter(R, x, 4 * vm_page_size, FREE);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    mach_vm_reclaim_query_state(R, id, FREE, &st);
    printf("free: flush %#x pages %llu mapped %d byte %#x %s\n", kr, bytes / vm_page_size, mapped(x),
           *(unsigned char *)x, state(st));
    mach_vm_deallocate(mach_task_self(), x, 4 * vm_page_size);

    // An unaligned entry is widened to its pages.
    x = pages(3);
    enter(R, x + 100, vm_page_size, DEALLOCATE);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    printf("unaligned: flush %#x bytes %llu pages mapped %d %d %d\n", kr, bytes, mapped(x), mapped(x + vm_page_size),
           mapped(x + 2 * vm_page_size));
    mach_vm_deallocate(mach_task_self(), x + 2 * vm_page_size, vm_page_size);

    // A cancelled entry is skipped; cancelling one reclaimed says so.
    x = pages(1);
    id = enter(R, x, vm_page_size, DEALLOCATE);
    kr = mach_vm_reclaim_try_cancel(R, id, x, vm_page_size, DEALLOCATE, &st, &upd);
    printf("cancel %#x %s\n", kr, state(st));
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    printf("  flush %#x bytes %llu mapped %d\n", kr, bytes, mapped(x));
    mach_vm_reclaim_try_cancel(R, id, x, vm_page_size, DEALLOCATE, &st, &upd);
    printf("  cancel again: %s\n", state(st));
    mach_vm_deallocate(mach_task_self(), x, vm_page_size);

    // Flushing more than is pending, or nothing.
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 5, &bytes, &deadline);
    printf("flush empty %#x bytes %llu\n", kr, bytes);
    indices("empty", R);

    // Entries that wrap around the ring's eight slots, then a resize.
    mach_vm_address_t xs[10];
    for (int i = 0; i < 10; i++) {
        xs[i] = pages(1);
        if (enter(R, xs[i], vm_page_size, DEALLOCATE) == UINT64_MAX)
            printf("  entry %d: ring full\n", i);
    }
    indices("full", R);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 3, &bytes, &deadline);
    printf("flush 3: %#x pages %llu\n", kr, bytes / vm_page_size);
    kr = mach_vm_deferred_reclamation_buffer_resize(mach_task_self(), 1017, &bytes, &deadline);
    printf("resize past the mapping %#x\n", kr);
    kr = mach_vm_reclaim_ring_resize(R, 16);
    indices("resized", R);
    int still = 0;
    for (int i = 0; i < 10; i++)
        still += mapped(xs[i]);
    printf("resize %#x len %u, entry regions still mapped %d\n", kr, R->len, still);
    for (int i = 8; i < 10; i++)
        mach_vm_deallocate(mach_task_self(), xs[i], vm_page_size);

    // A child has its own copy of the ring.
    x = pages(1);
    enter(R, x, vm_page_size, DEALLOCATE);
    pid_t c = fork();
    if (c == 0) {
        mach_vm_address_t ca = 0;
        mach_vm_size_t cs = 0;
        mach_vm_deferred_reclamation_buffer_query(mach_task_self(), &ca, &cs);
        kr = mach_vm_deferred_reclamation_buffer_allocate(mach_task_self(), &a, &deadline, 8, 1016);
        uint64_t b = 0;
        kern_return_t fk = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &b, &deadline);
        printf("child: same ring %d, allocate %#x, flush %#x pages %llu mapped %d\n", ca == (mach_vm_address_t)R,
               kr, fk, b / vm_page_size, mapped(x));
        _exit(0);
    }
    waitpid(c, NULL, 0);
    printf("parent: mapped %d", mapped(x));
    indices("", R);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    printf("  flush %#x pages %llu\n", kr, bytes / vm_page_size);

    // A deallocation over a hole removes nothing, and the ring stays stuck.
    x = pages(3);
    mach_vm_deallocate(mach_task_self(), x + vm_page_size, vm_page_size);
    id = enter(R, x, 3 * vm_page_size, DEALLOCATE);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    printf("hole: flush %#x mapped %d %d\n", kr, mapped(x), mapped(x + 2 * vm_page_size));
    indices("stuck", R);
    kr = mach_vm_deferred_reclamation_buffer_flush(mach_task_self(), 1, &bytes, &deadline);
    mach_vm_reclaim_query_state(R, id, DEALLOCATE, &st);
    printf("  again %#x %s\n", kr, state(st));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    ten_seconds = 10000000000ull * tb.denom / tb.numer;
    if (argc > 1 && strcmp(argv[1], "fresh") == 0) {
        fresh();
        return 0;
    }
    struct ring_ref ref = {0, 0};
    uint32_t count = 1;
    int kr = mach_vm_reclaim_get_rings_for_task(mach_task_self(), &ref, &count);
    printf("rings at start: %#x %u\n", kr, count);
    if (count > 0) {
        ring_t r = (ring_t)ref.addr;
        struct region rr = region_at(ref.addr);
        printf("  size %#llx prot %d/%d inherit %d tag %d len %u max %u\n", ref.size, rr.prot, rr.max, rr.inherit,
               rr.tag, r->len, r->max_len);
    }
#if defined(__arm64__)
    // A process libmalloc gives no ring (by name) makes its own. (Rosetta's
    // pages and ring sizes are not an Intel Mac's.)
    char path[4096], dir[] = "/tmp/rax-reclaim.XXXXXX", link[4200];
    uint32_t size = sizeof path;
    _NSGetExecutablePath(path, &size);
    mkdtemp(dir);
    snprintf(link, sizeof link, "%s/AegirPoster", dir);
    symlink(path, link);
    pid_t c = fork();
    if (c == 0) {
        execl(link, "AegirPoster", "fresh", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(c, &status, 0);
    printf("fresh process: status %#x\n", status);
    unlink(link);
    rmdir(dir);
#endif
    return 0;
}
