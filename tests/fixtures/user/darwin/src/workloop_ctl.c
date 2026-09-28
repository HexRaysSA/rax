// kqueue_workloop_ctl: the size, copy-in, and version checks made before
// the command; KQ_WORKLOOP_CREATE's checks of the scheduling parameters
// and of the ID, a workloop made with parameters living until
// KQ_WORKLOOP_DESTROY (once, and only for such a workloop), and an unknown
// command; libpthread's _pthread_workloop_create SPI; and libdispatch
// workloops with a scheduler priority running work.
#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

// Private SPI (bsd/pthread/workqueue_syscalls.h, bsd/sys/event_private.h,
// libpthread's workqueue_private.h, libdispatch's workloop_private.h).
struct params {
    int version;
    int flags;
    uint64_t id;
    int sched_pri;
    int sched_pol;
    int cpu_percent;
    int cpu_refillms;
    unsigned int wi_port;
} __attribute__((packed));
extern int __kqueue_workloop_ctl(uintptr_t cmd, uint64_t options, void *addr, size_t sz);
extern int _pthread_workloop_create(uint64_t id, uint64_t options, pthread_attr_t *attr);
extern int _pthread_workloop_destroy(uint64_t id);
extern int pthread_attr_setcpupercent_np(pthread_attr_t *attr, int percent, unsigned long refillms);
extern void dispatch_workloop_set_scheduler_priority(dispatch_workloop_t wl, int priority, uint64_t flags);
struct kev_qos {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    int32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t data;
    uint64_t ext[4];
};
extern int kevent_id(uint64_t id, const void *changelist, int nchanges, void *eventlist, int nevents,
                     void *data_out, size_t *data_available, unsigned int flags);

#define CREATE 1
#define DESTROY 2
#define SCHED_PRI 0x1
#define SCHED_POL 0x2
#define CPU_PERCENT 0x4
#define WORK_INTERVAL 0x8
#define F_IMMEDIATE 0x1
#define F_ERROR_EVENTS 0x2
#define F_WORKLOOP 0x400

static int ctl(uintptr_t cmd, struct params *p, size_t sz) {
    errno = 0;
    int r = __kqueue_workloop_ctl(cmd, 0, p, sz);
    return r == 0 ? 0 : errno;
}

static struct params make(uint64_t id, int flags) {
    struct params p = {.version = sizeof(struct params), .flags = flags, .id = id};
    p.sched_pri = 31;
    p.sched_pol = 1;
    p.cpu_percent = 50;
    p.cpu_refillms = 100;
    return p;
}

// Registers (or deletes) EVFILT_USER knote 1 on workloop `id`: 0, or the
// error its event reports.
static int knote(uint64_t id, uint16_t flags) {
    // A workloop's knote needs a QoS (default, pthread_priority_t 0x10ff).
    struct kev_qos c = {.ident = 1, .filter = EVFILT_USER, .flags = flags, .qos = 0x10ff};
    struct kev_qos out;
    memset(&out, 0, sizeof out);
    int n = kevent_id(id, &c, 1, &out, 1, NULL, NULL, F_WORKLOOP | F_ERROR_EVENTS | F_IMMEDIATE);
    if (n < 0) return -errno;
    return n == 0 ? 0 : (int)out.data;
}

static void create(const char *what, struct params p) {
    printf("%s: %d\n", what, ctl(CREATE, &p, sizeof p));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint64_t base = 0x7a000000ull + (uint64_t)getpid() * 16;
    struct params p = make(base, SCHED_PRI);

    // Checked before the command: the size, the copy, the version.
    printf("size below the version: %d\n", ctl(CREATE, &p, 3));
    printf("no parameters: %d\n", ctl(CREATE, NULL, sizeof p));
    printf("version not the size: %d\n", ctl(CREATE, &p, sizeof p - 4));
    printf("unknown command: %d\n", ctl(7, &p, sizeof p));
    printf("unknown command, bad version: %d\n", ctl(7, &p, 8));
    // A shorter structure whose version is its size is taken, the rest
    // zero: its priority is then 0.
    struct params short_p = make(base, SCHED_PRI);
    short_p.version = 16;
    printf("short parameters: %d\n", ctl(CREATE, &short_p, 16));

    // KQ_WORKLOOP_CREATE's checks.
    create("no flags", make(base, 0));
    create("unknown flag only", make(base, 0x20));
    struct params q = make(base, SCHED_PRI);
    q.sched_pri = 0;
    create("priority 0", q);
    q.sched_pri = 64;
    create("priority 64", q);
    q = make(base, SCHED_POL);
    q.sched_pol = 3;
    create("policy 3", q);
    q = make(base, CPU_PERCENT);
    q.cpu_percent = 0;
    create("cpu percent 0", q);
    q.cpu_percent = 101;
    create("cpu percent 101", q);
    q.cpu_percent = 50;
    q.cpu_refillms = 0;
    create("refill 0", q);
    q.cpu_refillms = 0x1000000;
    create("refill 2^24", q);
    create("work interval without a port", make(base, WORK_INTERVAL | SCHED_PRI));
    create("id 0", make(0, SCHED_PRI));
    create("id -1", make(UINT64_MAX, SCHED_PRI));

    // A workloop with parameters lives until destroyed, once.
    create("create", make(base + 1, SCHED_PRI | SCHED_POL | CPU_PERCENT));
    create("create again", make(base + 1, SCHED_PRI));
    struct params d = make(base + 1, 0);
    printf("destroy: %d\n", ctl(DESTROY, &d, sizeof d));
    printf("destroy again: %d\n", ctl(DESTROY, &d, sizeof d));
    create("create after destroy", make(base + 1, SCHED_POL));
    // Still referenced by a knote, a destroyed workloop stays: another
    // destroy finds it released.
    printf("knote on it: %d\n", knote(base + 1, EV_ADD | EV_CLEAR));
    printf("destroy with a knote: %d\n", ctl(DESTROY, &d, sizeof d));
    printf("destroy released: %d\n", ctl(DESTROY, &d, sizeof d));
    create("create while it lives", make(base + 1, SCHED_PRI));
    printf("knote deleted: %d\n", knote(base + 1, EV_DELETE));
    printf("destroy after the knote: %d\n", ctl(DESTROY, &d, sizeof d));
    // A workloop kevent_id made has no parameters to release.
    int n = knote(base + 2, EV_ADD | EV_CLEAR);
    d.id = base + 2;
    printf("kevent_id's workloop: %d, destroy: %d\n", n, ctl(DESTROY, &d, sizeof d));
    printf("its knote deleted: %d\n", knote(base + 2, EV_DELETE));
    d.id = base + 3;
    printf("destroy nothing: %d\n", ctl(DESTROY, &d, sizeof d));

    // libpthread's SPI.
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    printf("spi without attributes: %d\n", _pthread_workloop_create(base + 4, 0, NULL));
    printf("spi with nothing set: %d\n", _pthread_workloop_create(base + 4, 0, &attr));
    struct sched_param sp = {.sched_priority = 37};
    pthread_attr_setschedparam(&attr, &sp);
    printf("spi with a priority: %d\n", _pthread_workloop_create(base + 4, 0, &attr));
    printf("spi bad option: %d\n", _pthread_workloop_create(base + 5, 2, &attr));
    printf("spi destroy: %d %d\n", _pthread_workloop_destroy(base + 4), _pthread_workloop_destroy(base + 4));
    pthread_attr_destroy(&attr);

    // libdispatch workloops with kernel attributes run work.
    for (int i = 0; i < 2; i++) {
        dispatch_workloop_t wl = dispatch_workloop_create_inactive("rax.fixture.workloop");
        dispatch_workloop_set_scheduler_priority(wl, 30 + 10 * i, 0);
        dispatch_activate(wl);
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block int ran = 0;
        for (int j = 0; j < 3; j++) {
            dispatch_async(wl, ^{
              ran++;
              if (ran == 3) dispatch_semaphore_signal(done);
            });
        }
        long waited = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        printf("dispatch workloop %d: waited=%ld ran=%d\n", i, waited, ran);
        dispatch_release(wl);
    }
    return 0;
}
