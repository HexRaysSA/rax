// Work queues and workloops through libpthread's workqueue SPI and the
// raw calls libdispatch makes (workq_kernreturn, kevent_qos with
// KEVENT_FLAG_WORKQ, kevent_id, bsdthread_ctl): argument checking,
// anonymous thread requests and what their threads see, overcommit and
// constrained concurrency, the workqueue kqueue (a QoS bucket and the
// event manager), workloop thread requests, synchronous waiters (woken,
// deleted, interrupted), and ownership deferring a servicer. Nothing
// printed depends on the CPU count or on scheduling order.
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/qos.h>
#include <unistd.h>

// Private SPI (bsd/sys/event_private.h, libpthread's workqueue_private.h
// and qos_private.h).
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
extern int kevent_qos(int kq, const void *changelist, int nchanges, void *eventlist, int nevents,
                      void *data_out, size_t *data_available, unsigned int flags);
extern int kevent_id(uint64_t id, const void *changelist, int nchanges, void *eventlist,
                     int nevents, void *data_out, size_t *data_available, unsigned int flags);
extern int __workq_kernreturn(int options, void *item, int affinity, int prio);
extern int __bsdthread_ctl(uintptr_t cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
typedef void (*wq_fn)(unsigned long pp);
typedef void (*kev_fn)(void **events, int *nevents);
typedef void (*wl_fn)(uint64_t *id, void **events, int *nevents);
extern int _pthread_workqueue_init_with_workloop(wq_fn, kev_fn, wl_fn, int offset, int flags);
extern int _pthread_workqueue_addthreads(int numthreads, unsigned long priority);
extern int _pthread_workqueue_allow_send_signals(int signum);

#define F_IMMEDIATE 0x1
#define F_ERROR_EVENTS 0x2
#define F_WORKQ 0x20
#define F_WORKLOOP 0x400
#define F_MUST_EXIST 0x20000
#define F_MUST_NOT_EXIST 0x40000
#define EVFILT_WORKLOOP_ (-17)
#define WL_THREAD_REQUEST 0x1
#define WL_SYNC_WAIT 0x4
#define WL_SYNC_WAKE 0x8
#define WL_END_OWNERSHIP 0x20
#define WL_DISCOVER_OWNER 0x80
#define WL_IGNORE_ESTALE 0x100
#define OVERCOMMIT 0x80000000u
#define MANAGER_FLAG 0x02000000u

static unsigned long pp(int qos, int relpri, unsigned long flags) {
    return flags | (1ul << (8 + qos - 1)) | (uint8_t)(relpri - 1);
}

static semaphore_t done, ready, go;
static void wait_sem(semaphore_t s) {
    while (semaphore_wait(s) != KERN_SUCCESS) {
    }
}

// Anonymous workers.
enum { W_PLAIN, W_RENDEZVOUS, W_CHECKS };
static atomic_int mode;
static atomic_int calls;
static unsigned long seen_pp[8];
static int seen_main[8], seen_qos[8], seen_kill[8], seen_narrow[8], seen_fixed[8];
static unsigned seen_mask[8];
static size_t seen_stack[8];

static void worker(unsigned long p) {
    int i = atomic_fetch_add(&calls, 1);
    if (i < 8) {
        seen_pp[i] = p;
        seen_main[i] = pthread_main_np();
        seen_qos[i] = qos_class_self();
        sigset_t m;
        pthread_sigmask(SIG_BLOCK, NULL, &m);
        seen_mask[i] = m;
        seen_stack[i] = pthread_get_stacksize_np(pthread_self());
    }
    if (atomic_load(&mode) == W_RENDEZVOUS) {
        semaphore_signal(ready);
        wait_sem(go);
    } else if (atomic_load(&mode) == W_CHECKS && i < 8) {
        seen_kill[i] = pthread_kill(pthread_self(), 0);
        int r = __workq_kernreturn(0x200, NULL, (int)pp(3, 0, 0), 0);
        seen_narrow[i] = r == -1 ? errno : 0;
        r = __bsdthread_ctl(0x100, 0, 0, 0x04);
        seen_fixed[i] = r == -1 ? errno : 0;
    }
    semaphore_signal(done);
}

// Workqueue kqueue events.
static struct kev_qos kev_seen[4];
static int kev_n, kev_qos_class;
static void kevent_worker(void **events, int *nevents) {
    struct kev_qos *ev = *events;
    kev_n = *nevents;
    if (*nevents > 0) {
        kev_seen[0] = ev[0];
    }
    kev_qos_class = qos_class_self();
    if (*nevents > 0 && ev[0].ident == 44) {
        // Hand back a change: delete the knote.
        struct kev_qos del = {.ident = 44, .filter = EVFILT_USER, .flags = EV_DELETE};
        ev[0] = del;
        *nevents = 1;
    } else {
        *nevents = 0;
    }
    semaphore_signal(done);
}

// Workloop servicers.
static uint64_t wl_id_seen;
static struct kev_qos wl_seen;
static int wl_n;
static atomic_int wl_served;
static void workloop_worker(uint64_t *id, void **events, int *nevents) {
    struct kev_qos *ev = *events;
    wl_id_seen = *id;
    wl_n = *nevents;
    if (*nevents > 0) {
        wl_seen = ev[0];
    }
    atomic_fetch_add(&wl_served, 1);
    // Consume the thread request: delete it on the way back.
    struct kev_qos del = {
        .ident = *id,
        .filter = EVFILT_WORKLOOP_,
        .flags = EV_ADD | EV_DELETE | EV_ENABLE,
        .fflags = WL_THREAD_REQUEST,
    };
    ev[0] = del;
    *nevents = 1;
    semaphore_signal(done);
}

static int rv(int r) { return r == -1 ? -errno : r; }

static void show_kev(const char *what, int n, const struct kev_qos *e) {
    printf("%s: n=%d", what, n);
    if (n > 0) {
        printf(" [id=%#llx f=%d fl=%#x ff=%#x q=%#x d=%lld u=%#llx]", (unsigned long long)e->ident,
               e->filter, e->flags, e->fflags, e->qos, (long long)e->data,
               (unsigned long long)e->udata);
    }
    printf("\n");
}

static int wl_change(uint64_t id, uint64_t ident, uint16_t flags, uint32_t fflags,
                     unsigned long q, uint64_t udata, uint64_t addr, uint64_t mask,
                     uint64_t value, struct kev_qos *out) {
    struct kev_qos c = {
        .ident = ident,
        .filter = EVFILT_WORKLOOP_,
        .flags = flags,
        .fflags = fflags,
        .qos = (int32_t)q,
        .udata = udata,
        .ext = {0, addr, mask, value},
    };
    memset(out, 0, sizeof *out);
    return kevent_id(id, &c, 1, out, 1, NULL, NULL, F_WORKLOOP | F_ERROR_EVENTS | F_IMMEDIATE);
}

// Synchronous waiters.
struct waiter {
    uint64_t wl, ident;
    int n;
    struct kev_qos out;
    atomic_int returned;
};
static void on_usr1(int sig) { (void)sig; }
static void *wait_thread(void *arg) {
    struct waiter *w = arg;
    struct kev_qos c = {
        .ident = w->ident,
        .filter = EVFILT_WORKLOOP_,
        .flags = EV_ADD | EV_DISABLE,
        .fflags = WL_SYNC_WAIT,
        .qos = (int32_t)pp(4, 0, 0),
    };
    w->n = kevent_id(w->wl, &c, 1, &w->out, 1, NULL, NULL, F_WORKLOOP | F_ERROR_EVENTS);
    atomic_store(&w->returned, 1);
    return NULL;
}

int main(void) {
    task_t t = mach_task_self();
    semaphore_create(t, &done, SYNC_POLICY_FIFO, 0);
    semaphore_create(t, &ready, SYNC_POLICY_FIFO, 0);
    semaphore_create(t, &go, SYNC_POLICY_FIFO, 0);

    // Before the work queue is opened.
    printf("bad op: %d\n", rv(__workq_kernreturn(0x999, NULL, 0, 0)));
    printf("reqthreads unopened: %d\n", rv(__workq_kernreturn(0x20, NULL, 1, (int)pp(4, 0, 0))));
    printf("thread return from main: %d\n", rv(__workq_kernreturn(0x4, NULL, 0, 0)));

    printf("init: %d\n",
           _pthread_workqueue_init_with_workloop(worker, kevent_worker, workloop_worker, 0, 0));
    printf("init again: %d\n",
           _pthread_workqueue_init_with_workloop(worker, kevent_worker, workloop_worker, 0, 0));

    // Argument checking.
    printf("reqthreads 0: %d\n", rv(__workq_kernreturn(0x20, NULL, 0, (int)pp(4, 0, 0))));
    printf("reqthreads no qos: %d\n", rv(__workq_kernreturn(0x20, NULL, 1, 0)));
    printf("reqthreads 70000: %d\n", rv(__workq_kernreturn(0x20, NULL, 70000, (int)pp(4, 0, 0))));
    printf("cooperative 2: %d\n", rv(__workq_kernreturn(0x30, NULL, 2, (int)pp(4, 0, 0))));
    printf("cooperative overcommit: %d\n",
           rv(__workq_kernreturn(0x30, NULL, 1, (int)pp(4, 0, OVERCOMMIT))));
    printf("should narrow from main: %d\n",
           rv(__workq_kernreturn(0x200, NULL, (int)pp(4, 0, 0), 0)));
    printf("manager priority relpri>0: %d\n",
           rv(__workq_kernreturn(0x80, NULL, (int)((1 << 11) | 5), 0)));
    printf("manager priority: %d\n", rv(__workq_kernreturn(0x80, NULL, (int)pp(5, 0, 0), 0)));
    uint32_t cfg[6] = {0, 0, 0, 0, 0, 0};
    printf("setup dispatch v0: %d\n", rv(__workq_kernreturn(0x400, cfg, 24, 0)));
    cfg[0] = 2;
    cfg[1] = 1;
    printf("setup dispatch flags: %d\n", rv(__workq_kernreturn(0x400, cfg, 24, 0)));
    printf("newspisupp: %d\n", rv(__workq_kernreturn(0x10, NULL, 0, 0)));

    // bsdthread_ctl.
    printf("parallelism qos 0: %d\n", rv(__bsdthread_ctl(0x800, 0, 1, 0)));
    printf("parallelism bad flags: %d\n", rv(__bsdthread_ctl(0x800, 4, 8, 0)));
    printf("parallelism arg3: %d\n", rv(__bsdthread_ctl(0x800, 4, 1, 1)));
    printf("parallelism: %s\n", __bsdthread_ctl(0x800, 4, 1, 0) > 0 ? "positive" : "?");
    printf("set qos (obsolete): %d\n", rv(__bsdthread_ctl(0x10, 0, 0, 0)));
    printf("unknown cmd: %d\n", rv(__bsdthread_ctl(0x3, 0, 0, 0)));
    printf("unbind from main: %d\n", rv(__bsdthread_ctl(0x100, 0, 0, 0x10)));
    printf("set self bad qos: %d\n", rv(__bsdthread_ctl(0x100, 0, 0, 0x01)));
    printf("set self bad voucher: %d\n", rv(__bsdthread_ctl(0x100, 0, 0x1234, 0x02)));
    printf("set self both bad: %d\n", rv(__bsdthread_ctl(0x100, 0, 0x1234, 0x03)));
    printf("set self qos: %d\n", rv(__bsdthread_ctl(0x100, pp(4, 0, 0), 0, 0x01)));
    mach_port_t me = mach_thread_self();
    printf("override start no qos: %d\n", rv(__bsdthread_ctl(0x40, me, 0, 0)));
    printf("override start bad port: %d\n", rv(__bsdthread_ctl(0x40, 0x1234, pp(5, 0, 0), 0)));
    printf("override start/end: %d %d\n", rv(__bsdthread_ctl(0x40, me, pp(5, 0, 0), 0x10)),
           rv(__bsdthread_ctl(0x80, me, 0x10, 0)));
    printf("dispatch override on main: %d\n", rv(__bsdthread_ctl(0x400, me, pp(5, 0, 0), 0)));
    printf("override reset on main: %d\n", rv(__bsdthread_ctl(0x200, 0, 0, 0)));
    printf("allow sigmask SIGSEGV: %d\n", rv(__bsdthread_ctl(0x4000, 1u << (SIGSEGV - 1), 0, 0)));

    // Anonymous requests: what a worker sees.
    atomic_store(&mode, W_PLAIN);
    printf("addthreads: %d\n", _pthread_workqueue_addthreads(3, pp(3, 0, 0)));
    for (int i = 0; i < 3; i++) {
        wait_sem(done);
    }
    int same = 1;
    for (int i = 1; i < 3; i++) {
        same &= seen_pp[i] == seen_pp[0] && seen_main[i] == seen_main[0] &&
                seen_qos[i] == seen_qos[0] && seen_mask[i] == seen_mask[0] &&
                seen_stack[i] == seen_stack[0];
    }
    printf("workers: calls=%d same=%d pp=%#lx main=%d qos=%#x mask=%#x\n", atomic_load(&calls),
           same, seen_pp[0], seen_main[0], seen_qos[0], seen_mask[0]);
#if defined(__arm64__)
    // The kernel places a workqueue thread's pthread_t PTHREAD_T_OFFSET
    // (12 KiB on an arm64 kernel, 0 on an x86_64 one) into the top of its
    // stack allocation; Rosetta's x86_64 processes run on an arm64 kernel.
    printf("worker stack: %zu\n", seen_stack[0]);
#endif

    // Two overcommit threads run at once, and two constrained ones when
    // one of them blocks.
    unsigned long kinds[2] = {pp(5, 0, OVERCOMMIT), pp(3, 0, 0)};
    for (int k = 0; k < 2; k++) {
        atomic_store(&calls, 0);
        atomic_store(&mode, W_RENDEZVOUS);
        _pthread_workqueue_addthreads(2, kinds[k]);
        wait_sem(ready);
        wait_sem(ready);
        semaphore_signal(go);
        semaphore_signal(go);
        wait_sem(done);
        wait_sem(done);
        printf("%s rendezvous: calls=%d pp=%#lx qos=%#x\n", k ? "constrained" : "overcommit",
               atomic_load(&calls), seen_pp[0], seen_qos[0]);
    }

    // Workers may not be signalled until the process allows it; workers
    // cannot narrow as overcommit threads or set a fixed priority.
    for (int k = 0; k < 2; k++) {
        atomic_store(&calls, 0);
        atomic_store(&mode, W_CHECKS);
        if (k == 1) {
            printf("allow send signals: %d\n", _pthread_workqueue_allow_send_signals(SIGUSR1));
        }
        _pthread_workqueue_addthreads(1, pp(5, 0, OVERCOMMIT));
        wait_sem(done);
        printf("worker checks: kill=%d narrow=%d fixedpri=%d\n", seen_kill[0], seen_narrow[0],
               seen_fixed[0]);
    }

    // The workqueue kqueue: a knote at a QoS, and the event manager's.
    struct kev_qos out[2];
    printf("kqwq requesting events: %d\n",
           rv(kevent_qos(-1, NULL, 0, out, 1, NULL, NULL, F_WORKQ)));
    struct kev_qos u = {.ident = 42,
                        .filter = EVFILT_USER,
                        .flags = EV_ADD | EV_CLEAR,
                        .qos = (int32_t)pp(3, 0, 0),
                        .udata = 0x42};
    printf("kqwq add: %d\n", rv(kevent_qos(-1, &u, 1, NULL, 0, NULL, NULL, F_WORKQ | F_IMMEDIATE)));
    u.flags = 0;
    u.fflags = NOTE_TRIGGER;
    kevent_qos(-1, &u, 1, NULL, 0, NULL, NULL, F_WORKQ | F_IMMEDIATE);
    wait_sem(done);
    show_kev("kqwq event", kev_n, &kev_seen[0]);
    printf("kqwq servicer qos: %#x\n", kev_qos_class);
    struct kev_qos m = {.ident = 43, .filter = EVFILT_USER, .flags = EV_ADD | EV_CLEAR, .udata = 0x43};
    kevent_qos(-1, &m, 1, NULL, 0, NULL, NULL, F_WORKQ | F_IMMEDIATE);
    m.flags = 0;
    m.fflags = NOTE_TRIGGER;
    kevent_qos(-1, &m, 1, NULL, 0, NULL, NULL, F_WORKQ | F_IMMEDIATE);
    wait_sem(done);
    show_kev("manager event", kev_n, &kev_seen[0]);
    printf("manager qos: %#x\n", kev_qos_class);
    // A change handed back by the servicer is applied when it returns.
    struct kev_qos d = {.ident = 44,
                        .filter = EVFILT_USER,
                        .flags = EV_ADD | EV_CLEAR,
                        .fflags = NOTE_TRIGGER,
                        .qos = (int32_t)pp(3, 0, 0)};
    kevent_qos(-1, &d, 1, NULL, 0, NULL, NULL, F_WORKQ | F_IMMEDIATE);
    wait_sem(done);
    d.flags = EV_DELETE;
    d.fflags = 0;
    int gone = 0;
    for (int i = 0; i < 200 && !gone; i++) {
        struct kev_qos probe = {.ident = 44, .filter = EVFILT_USER, .flags = EV_ENABLE};
        gone = kevent_qos(-1, &probe, 1, out, 1, NULL, NULL,
                          F_WORKQ | F_IMMEDIATE | F_ERROR_EVENTS) == 1 &&
               out[0].data == ENOENT;
        if (!gone) {
            usleep(5000);
        }
    }
    printf("returned change applied: %d\n", gone);

    // kevent_id arguments.
    printf("kevent_id id 0: %d\n", rv(kevent_id(0, NULL, 0, NULL, 0, NULL, NULL, F_WORKLOOP)));
    printf("kevent_id no workloop flag: %d\n",
           rv(kevent_id(0x1111, NULL, 0, NULL, 0, NULL, NULL, F_IMMEDIATE)));
    printf("kevent_id workq flag: %d\n",
           rv(kevent_id(0x1111, NULL, 0, NULL, 0, NULL, NULL, F_WORKLOOP | F_WORKQ)));
    printf("kevent_id must exist: %d\n",
           rv(kevent_id(0x1111, NULL, 0, NULL, 0, NULL, NULL, F_WORKLOOP | F_MUST_EXIST)));
    printf("kevent_id events from a non-servicer: %d\n",
           rv(kevent_id(0x1111, NULL, 0, out, 1, NULL, NULL, F_WORKLOOP | F_IMMEDIATE)));

    // Workloop registration errors come back as events.
    const uint64_t W = 0x5000;
    int n = wl_change(W, 0x999, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST, pp(4, 0, 0), 0, 0, 0, 0, out);
    printf("request ident mismatch: n=%d err=%lld\n", n, (long long)out[0].data);
    n = wl_change(W, W, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST, 0, 0, 0, 0, 0, out);
    printf("request without qos: n=%d err=%lld\n", n, (long long)out[0].data);
    n = wl_change(W, 0x51, EV_ADD, WL_SYNC_WAIT, pp(4, 0, 0), 0, 0, 0, 0, out);
    printf("sync wait enabled: n=%d err=%lld\n", n, (long long)out[0].data);
    n = wl_change(W, 0x51, EV_ADD | EV_DISABLE, 0, pp(4, 0, 0), 0, 0, 0, 0, out);
    printf("no command: n=%d err=%lld\n", n, (long long)out[0].data);
    uint64_t word = 5;
    n = wl_change(W, W, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST, pp(4, 0, 0), 0,
                  (uint64_t)(uintptr_t)&word, ~0ull, 6, out);
    printf("stale: n=%d err=%lld value=%llu\n", n, (long long)out[0].data,
           (unsigned long long)out[0].ext[3]);
    n = wl_change(W, W, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST | WL_IGNORE_ESTALE, pp(4, 0, 0), 0,
                  (uint64_t)(uintptr_t)&word, ~0ull, 6, out);
    printf("stale ignored: n=%d\n", n);
    word = 0x1234567;
    n = wl_change(W, W, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST | WL_DISCOVER_OWNER, pp(4, 0, 0), 0,
                  (uint64_t)(uintptr_t)&word, 0, 0, out);
    printf("dead owner: n=%d err=%lld\n", n, (long long)out[0].data);
    printf("soft delete: %d\n",
           wl_change(W, 0x52, EV_ADD | EV_DELETE | EV_ENABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out));

    // A thread request gets a servicer, which consumes it; the workloop
    // then goes away.
    n = wl_change(W, W, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST, pp(4, 0, OVERCOMMIT), 0x77, 0, 0, 0,
                  out);
    printf("thread request: n=%d\n", n);
    wait_sem(done);
    printf("servicer: id=%s ", wl_id_seen == W ? "ok" : "wrong");
    show_kev("events", wl_n, &wl_seen);
    gone = 0;
    for (int i = 0; i < 200 && !gone; i++) {
        gone = kevent_id(W, NULL, 0, NULL, 0, NULL, NULL, F_WORKLOOP | F_MUST_EXIST) == -1 &&
               errno == ENOENT;
        if (!gone) {
            usleep(5000);
        }
    }
    printf("workloop freed: %d\n", gone);

    // Synchronous waiters: woken by a wake, by the knote's deletion, and
    // interrupted by a signal.
    struct sigaction sa = {.sa_handler = on_usr1};
    sigaction(SIGUSR1, &sa, NULL);
    const uint64_t W2 = 0x6000;
    struct waiter w1 = {.wl = W2, .ident = 0x61};
    pthread_t th;
    pthread_create(&th, NULL, wait_thread, &w1);
    usleep(20000);
    n = wl_change(W2, 0x61, EV_ADD | EV_DISABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out);
    pthread_join(th, NULL);
    printf("sync wake: waker n=%d waiter n=%d\n", n, w1.n);
    printf("sync end: %d\n",
           wl_change(W2, 0x61, EV_DELETE | EV_ENABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out));

    struct waiter w2 = {.wl = W2, .ident = 0x62};
    pthread_create(&th, NULL, wait_thread, &w2);
    int deleted = 0;
    for (int i = 0; i < 400 && !deleted; i++) {
        n = wl_change(W2, 0x62, EV_DELETE | EV_ENABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out);
        deleted = n == 0;
        if (!deleted) {
            usleep(5000);
        }
    }
    pthread_join(th, NULL);
    printf("deleted waiter: deleted=%d waiter n=%d\n", deleted, w2.n);

    struct waiter w3 = {.wl = W2, .ident = 0x63};
    pthread_create(&th, NULL, wait_thread, &w3);
    for (int i = 0; i < 400 && !atomic_load(&w3.returned); i++) {
        usleep(10000);
        pthread_kill(th, SIGUSR1);
    }
    pthread_join(th, NULL);
    printf("interrupted waiter: n=%d fl=%#x err=%lld\n", w3.n, w3.out.flags,
           (long long)w3.out.data);
    wl_change(W2, 0x63, EV_DELETE | EV_ENABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out);

    // An owner defers the servicer until it gives up ownership.
    const uint64_t W3 = 0x7000;
    word = me;
    atomic_store(&wl_served, 0);
    n = wl_change(W3, W3, EV_ADD | EV_ENABLE, WL_THREAD_REQUEST | WL_DISCOVER_OWNER,
                  pp(4, 0, OVERCOMMIT), 0x78, (uint64_t)(uintptr_t)&word, 0, 0, out);
    usleep(50000);
    printf("owned: n=%d served=%d\n", n, atomic_load(&wl_served));
    wl_change(W3, 0x71, EV_ADD | EV_DISABLE, WL_SYNC_WAKE, 0, 0, 0, 0, 0, out);
    n = wl_change(W3, 0x71, EV_DELETE | EV_ENABLE, WL_SYNC_WAKE | WL_END_OWNERSHIP, 0, 0, 0, 0, 0,
                  out);
    wait_sem(done);
    printf("ownership ended: n=%d served=%d\n", n, atomic_load(&wl_served));
    return 0;
}
