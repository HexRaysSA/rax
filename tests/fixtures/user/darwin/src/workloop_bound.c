// Workloops with a permanently bound thread (KQ_WORKLOOP_CREATE_WITH_BOUND_THREAD)
// through libpthread's SPI and the raw calls: the thread made at creation,
// woken for the workloop's events and parking again, always the same one,
// ending when the workloop is destroyed; and the QoS a servicer of a
// workloop with a scheduler priority runs at. Then (in a spawned child,
// which starts a work queue of its own) libdispatch workloops with a bound
// thread and with a scheduler priority, whose work runs at the QoS its
// submitter's gives it: the main thread's, the QoS the process started
// with.
#include <dispatch/dispatch.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/qos.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// Private SPI (libpthread's workqueue_private.h, bsd/sys/event_private.h,
// libdispatch's workloop_private.h).
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
typedef void (*wq_fn)(unsigned long pp);
typedef void (*kev_fn)(void **events, int *nevents);
typedef void (*wl_fn)(uint64_t *id, void **events, int *nevents);
extern int _pthread_workqueue_init_with_workloop(wq_fn, kev_fn, wl_fn, int offset, int flags);
extern int _pthread_workloop_create(uint64_t id, uint64_t options, pthread_attr_t *attr);
extern int _pthread_workloop_destroy(uint64_t id);
extern int dispatch_workloop_set_uses_bound_thread(dispatch_workloop_t wl, uint64_t flags);
extern void dispatch_workloop_set_scheduler_priority(dispatch_workloop_t wl, int priority, uint64_t flags);

#define F_IMMEDIATE 0x1
#define F_ERROR_EVENTS 0x2
#define F_WORKLOOP 0x400
#define WITH_BOUND_THREAD 1
#define DEFAULT_QOS 0x10ff

static semaphore_t serviced;
static _Atomic(pthread_t) servicer;
static atomic_int nserviced, last_nevents, last_qos;
static _Atomic uint64_t last_ident, last_id;

static void on_workqueue(unsigned long pp) { (void)pp; }
static void on_kevent(void **events, int *nevents) {
    (void)events;
    *nevents = 0;
}
static void on_workloop(uint64_t *id, void **events, int *nevents) {
    struct kev_qos *ev = *events;
    atomic_store(&last_id, *id);
    atomic_store(&last_nevents, *nevents);
    atomic_store(&last_ident, *nevents > 0 ? ev[0].ident : 0);
    atomic_store(&last_qos, (int)qos_class_self());
    atomic_store(&servicer, pthread_self());
    atomic_fetch_add(&nserviced, 1);
    *nevents = 0;
    semaphore_signal(serviced);
}

static int thread_count(void) {
    thread_act_array_t list;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) return -1;
    for (mach_msg_type_number_t i = 0; i < n; i++) mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof list[0]);
    return (int)n;
}

// Registers, triggers, or deletes EVFILT_USER knote `ident` of workloop
// `id`: 0, or the error its event reports.
static int knote(uint64_t id, uint64_t ident, uint16_t flags, uint32_t fflags) {
    struct kev_qos c = {.ident = ident, .filter = EVFILT_USER, .flags = flags, .fflags = fflags, .qos = DEFAULT_QOS};
    struct kev_qos out;
    memset(&out, 0, sizeof out);
    int n = kevent_id(id, &c, 1, &out, 1, NULL, NULL, F_WORKLOOP | F_ERROR_EVENTS | F_IMMEDIATE);
    if (n < 0) return -errno;
    return n == 0 ? 0 : (int)out.data;
}

// Triggers knote `ident` and waits for the servicer: whether it ran.
static int fire(uint64_t id, uint64_t ident) {
    int before = atomic_load(&nserviced);
    int r = knote(id, ident, 0, NOTE_TRIGGER);
    mach_timespec_t t = {5, 0};
    while (atomic_load(&nserviced) == before) {
        if (semaphore_timedwait(serviced, t) != KERN_SUCCESS) break;
    }
    return r == 0 && atomic_load(&nserviced) > before;
}

// Waits up to 5 s for the thread count to fall to `n`.
static int threads_fall_to(int n) {
    for (int i = 0; i < 500; i++) {
        if (thread_count() <= n) return 1;
        usleep(10000);
    }
    return 0;
}

static void raw(void) {
    semaphore_create(mach_task_self(), &serviced, SYNC_POLICY_FIFO, 0);
    printf("init: %d\n", _pthread_workqueue_init_with_workloop(on_workqueue, on_kevent, on_workloop, 0, 0));
    uint64_t id = 0x7b000000ull + (uint64_t)getpid() * 16;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    // A bound thread is made with the workloop.
    int base = thread_count();
    printf("create bound: %d\n", _pthread_workloop_create(id, WITH_BOUND_THREAD, &attr));
    printf("a thread was made: %d\n", thread_count() == base + 1);
    printf("create bound again: %d\n", _pthread_workloop_create(id, WITH_BOUND_THREAD, &attr));
    printf("knote: %d\n", knote(id, 1, EV_ADD | EV_CLEAR, 0));
    int ran = fire(id, 1);
    pthread_t first = atomic_load(&servicer);
    printf("serviced: %d id_ok=%d nevents=%d ident=%llu main=%d\n", ran, atomic_load(&last_id) == id,
           atomic_load(&last_nevents), (unsigned long long)atomic_load(&last_ident),
           pthread_equal(first, pthread_self()));
    for (int i = 0; i < 3; i++) {
        ran = fire(id, 1);
        printf("again: %d same thread=%d\n", ran, pthread_equal(first, atomic_load(&servicer)));
    }
    printf("no thread was added: %d\n", thread_count() == base + 1);
    // Destroyed, the workloop lives on through its knote, but its thread
    // ends.
    printf("destroy: %d\n", _pthread_workloop_destroy(id));
    printf("its thread ended: %d\n", threads_fall_to(base));
    printf("destroy again: %d\n", _pthread_workloop_destroy(id));
    printf("knote deleted: %d\n", knote(id, 1, EV_DELETE, 0));

    // A bound workloop with a scheduler priority: its thread runs outside
    // the QoS classes.
    struct sched_param sp = {.sched_priority = 37};
    pthread_attr_setschedparam(&attr, &sp);
    printf("create bound with a priority: %d\n", _pthread_workloop_create(id + 1, WITH_BOUND_THREAD, &attr));
    printf("knote: %d\n", knote(id + 1, 2, EV_ADD | EV_CLEAR, 0));
    ran = fire(id + 1, 2);
    printf("serviced: %d qos=%#x main=%d\n", ran, atomic_load(&last_qos),
           pthread_equal(pthread_self(), atomic_load(&servicer)));
    printf("knote deleted: %d\n", knote(id + 1, 2, EV_DELETE, 0));
    printf("destroy: %d\n", _pthread_workloop_destroy(id + 1));
    printf("its thread ended: %d\n", threads_fall_to(base));

    // An unbound workloop with a scheduler priority: a pool thread
    // services it, outside the QoS classes too.
    printf("create with a priority: %d\n", _pthread_workloop_create(id + 2, 0, &attr));
    printf("knote: %d\n", knote(id + 2, 3, EV_ADD | EV_CLEAR, 0));
    ran = fire(id + 2, 3);
    printf("serviced: %d qos=%#x\n", ran, atomic_load(&last_qos));
    printf("knote deleted: %d\n", knote(id + 2, 3, EV_DELETE, 0));
    printf("destroy: %d\n", _pthread_workloop_destroy(id + 2));
    pthread_attr_destroy(&attr);
}

static void with_dispatch(void) {
    printf("child main thread qos: %#x %#x\n", qos_class_self(), qos_class_main());
    for (int bound = 1; bound >= 0; bound--) {
        dispatch_workloop_t wl = dispatch_workloop_create_inactive("rax.fixture.bound");
        if (bound) {
            printf("uses bound thread: %d\n", dispatch_workloop_set_uses_bound_thread(wl, 1));
        } else {
            dispatch_workloop_set_scheduler_priority(wl, 35, 0);
        }
        dispatch_activate(wl);
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block pthread_t firsts = NULL;
        __block int same = 1, main_thread = 0, ran = 0;
        __block qos_class_t qos = 0;
        pthread_t me = pthread_self();
        for (int j = 0; j < 4; j++) {
            dispatch_async(wl, ^{
              pthread_t t = pthread_self();
              if (!firsts) firsts = t;
              same &= pthread_equal(firsts, t);
              main_thread |= pthread_equal(me, t);
              qos = qos_class_self();
              if (++ran == 4) dispatch_semaphore_signal(done);
            });
        }
        long waited = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        printf("dispatch %s: waited=%ld ran=%d main=%d qos=%#x", bound ? "bound" : "priority", waited, ran,
               main_thread, qos);
        if (bound) printf(" same thread=%d", same);
        printf("\n");
        dispatch_release(wl);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) {
        with_dispatch();
        return 0;
    }
    // The main thread's QoS is the one the process was started with.
    printf("main thread qos: %#x %#x\n", qos_class_self(), qos_class_main());
    raw();
    char self[4096];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "dispatch", NULL};
    pid_t pid;
    int status = -1;
    if (posix_spawn(&pid, self, NULL, NULL, args, environ) == 0) waitpid(pid, &status, 0);
    printf("child: %d\n", status);
    return 0;
}
