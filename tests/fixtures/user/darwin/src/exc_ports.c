// Exception ports: task_, thread_, and host_{set,get,swap}_exception_ports
// and the _info variants: the valid masks, behaviors, and flavors and the
// order they are checked in, what may be a handler, the merged view `get`
// returns and its order, `swap`, the targets each routine accepts, and a
// thread's actions before its first `set`. Masks avoid EXC_RESOURCE and
// EXC_CORPSE_NOTIFY, which the launching environment may have set.
// Rosetta checks exception ports itself (and differently): what it does
// not share with XNU runs on arm64 only.
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

#define VALID 0x3ffe
#define QUIET (VALID & ~0x2800) // without EXC_RESOURCE, EXC_CORPSE_NOTIFY

#if defined(__arm64__)
#define THREAD_FLAVOR 6 // ARM_THREAD_STATE64
#else
#define THREAD_FLAVOR 4 // x86_THREAD_STATE64
#endif

static mach_port_t task, self, A, B;

static const char *label(mach_port_t p) {
    if (p == MACH_PORT_NULL) return "NULL";
    if (p == MACH_PORT_DEAD) return "DEAD";
    if (p == A) return "A";
    if (p == B) return "B";
    return "other";
}

static void show(const char *what, kern_return_t kr, mach_msg_type_number_t n, exception_mask_t *m,
                 mach_port_t *p, exception_behavior_t *b, thread_state_flavor_t *f) {
    printf("%s: kr=%d count=%u\n", what, kr, kr ? 0 : n);
    for (unsigned i = 0; kr == 0 && i < n; i++)
        printf("  [%u] mask=%#x port=%s behavior=%#x flavor=%d\n", i, m[i], label(p[i]), b[i], f[i]);
}

static void task_get(const char *what, mach_port_t t, exception_mask_t mask) {
    exception_mask_t m[32];
    mach_port_t p[32];
    exception_behavior_t b[32];
    thread_state_flavor_t f[32];
    mach_msg_type_number_t n = 32;
    kern_return_t kr = task_get_exception_ports(t, mask, m, &n, p, b, f);
    show(what, kr, n, m, p, b, f);
}

static void thread_get(const char *what, exception_mask_t mask) {
    exception_mask_t m[32];
    mach_port_t p[32];
    exception_behavior_t b[32];
    thread_state_flavor_t f[32];
    mach_msg_type_number_t n = 32;
    kern_return_t kr = thread_get_exception_ports(self, mask, m, &n, p, b, f);
    show(what, kr, n, m, p, b, f);
}

static kern_return_t tset(exception_mask_t mask, mach_port_t port, exception_behavior_t b,
                          thread_state_flavor_t f) {
    return thread_set_exception_ports(self, mask, port, b, f);
}

static mach_port_t handler_port(void) {
    mach_port_t p;
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    task = mach_task_self();
    self = mach_thread_self();
    A = handler_port();
    B = handler_port();

    thread_get("thread get before any set", QUIET);
    task_get("task get, mask 0", task, 0);

    // Masks.
    exception_mask_t masks[] = {0x1, 0x4000, 0x80000000, 0x3fff, VALID, 0};
    for (unsigned i = 0; i < sizeof masks / sizeof *masks; i++)
        printf("thread set mask %#x: %d\n", masks[i], tset(masks[i], A, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0));
    thread_get("thread get after set", QUIET);
    printf("thread set to NULL: %d\n", tset(VALID, MACH_PORT_NULL, 0, 0));
    thread_get("thread get after clearing", QUIET);
    task_get("task get, mask 0x1", task, 0x1);
    thread_get("thread get, mask 0x4000", 0x4000);

    // Behaviors, with a handler.
    exception_behavior_t behaviors[] = {0, 1, 2, 3, 4, 6, 7, 0x10000001, 0x20000001,
                                        (exception_behavior_t)0x80000002, (exception_behavior_t)0x80000003};
    for (unsigned i = 0; i < sizeof behaviors / sizeof *behaviors; i++)
        printf("behavior %#x: %d\n", behaviors[i], tset(0x2, A, behaviors[i], 0));
#if defined(__arm64__)
    exception_behavior_t more[] = {0x40000001, (exception_behavior_t)0x80000004,
                                   (exception_behavior_t)0x80000005, (exception_behavior_t)0xa0000001};
    for (unsigned i = 0; i < sizeof more / sizeof *more; i++)
        printf("behavior %#x: %d\n", more[i], tset(0x2, A, more[i], 0));
#endif
    // The order of the checks: behavior before the port, the port before
    // the flavor; the flavor and the codes requirement with no port too.
    printf("behavior 7, no port: %d\n", tset(0x2, MACH_PORT_NULL, 7, 0));
    printf("flavor 9999, no port: %d\n", tset(0x2, MACH_PORT_NULL, 1, 9999));
    printf("mask 0x1, behavior 7, flavor 9999: %d\n", tset(0x1, A, 7, 9999));
#if defined(__arm64__)
    printf("behavior 4, no port: %d\n", tset(0x2, MACH_PORT_NULL, 4, 0));
    printf("behavior 7, task port: %d\n", tset(0x2, task, 7, 0));
    printf("task port, flavor 9999: %d\n", tset(0x2, task, 1, 9999));
    printf("task port: %d\n", tset(0x2, task, 1, 0));
    printf("thread port: %d\n", tset(0x2, self, 1, 0));
    mach_port_t ro;
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &ro);
    printf("receive right only: %#x\n", tset(0x2, ro, 1, 0));
    mach_port_t dead;
    mach_port_allocate(task, MACH_PORT_RIGHT_DEAD_NAME, &dead);
    printf("dead name: %d\n", tset(0x2, dead, 1, 0));
    thread_get("thread get with a dead name", 0x2);
#endif

    // Flavors.
#if defined(__arm64__)
    for (int f = -1; f <= 52; f++) {
        kern_return_t kr = tset(0x2, A, EXCEPTION_STATE | MACH_EXCEPTION_CODES, f);
        if (kr == 0) printf("flavor %d ok\n", f);
        else printf("flavor %d: %d\n", f, kr);
    }
#else
    int flavors[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23, 26, 27, 40, 52};
    for (unsigned i = 0; i < sizeof flavors / sizeof *flavors; i++) {
        kern_return_t kr = tset(0x2, A, EXCEPTION_STATE | MACH_EXCEPTION_CODES, flavors[i]);
        if (kr == 0) printf("flavor %d ok\n", flavors[i]);
        else printf("flavor %d: %d\n", flavors[i], kr);
    }
#endif

    // A task's view merges equal actions, in exception order.
    exception_behavior_t def = EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES;
    printf("task set bad access and breakpoint: %d\n", task_set_exception_ports(task, 0x42, A, def, 0));
    printf("task set bad instruction: %d\n",
           task_set_exception_ports(task, 0x4, A, EXCEPTION_STATE | MACH_EXCEPTION_CODES, THREAD_FLAVOR));
    printf("task set arithmetic: %d\n", task_set_exception_ports(task, 0x8, B, def, 0));
    task_get("task get 0x4e", task, 0x4e);
    {
        exception_mask_t m[32];
        mach_port_t p[32];
        exception_behavior_t b[32];
        thread_state_flavor_t f[32];
        mach_msg_type_number_t n = 32;
        kern_return_t kr = task_swap_exception_ports(task, 0x1a, B,
                                                     EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                                     THREAD_FLAVOR, m, &n, p, b, f);
        show("task swap 0x1a", kr, n, m, p, b, f);
    }
    task_get("task get 0x7e", task, 0x7e);
    {
        exception_mask_t m[32];
        mach_port_t p[32];
        exception_behavior_t b[32];
        thread_state_flavor_t f[32];
        mach_msg_type_number_t n = 32;
        kern_return_t kr = task_swap_exception_ports(task, 0x2, A, 0x7fff, 0, m, &n, p, b, f);
        printf("task swap, bad behavior: %d\n", kr);
        n = 32;
        kr = thread_swap_exception_ports(self, 0x30, A, def, 0, m, &n, p, b, f);
        show("thread swap 0x30", kr, n, m, p, b, f);
    }

    // Targets.
    mach_port_t host = mach_host_self();
    {
        exception_mask_t m[32];
        mach_port_t p[32];
        exception_behavior_t b[32];
        thread_state_flavor_t f[32];
        mach_msg_type_number_t n = 32;
        printf("host get: %d\n", host_get_exception_ports(host, 0x2, m, &n, p, b, f));
        printf("host set: %d\n", host_set_exception_ports(host, 0x2, A, def, 0));
        printf("host set, bad everything: %d\n", host_set_exception_ports(host, 0x1, A, 7, 9999));
        n = 32;
        printf("host swap: %d\n", host_swap_exception_ports(host, 0x2, A, def, 0, m, &n, p, b, f));
        n = 32;
        printf("task set on the thread port: %d\n", task_set_exception_ports(self, 0x2, A, def, 0));
        printf("thread set on the task port: %d\n", thread_set_exception_ports(task, 0x2, A, def, 0));
    }
    mach_port_t readp = MACH_PORT_NULL;
    printf("task read port: %d\n", task_get_special_port(task, TASK_READ_PORT, &readp));
    task_get("task get on the read port", readp, 0x2);
    {
        exception_mask_t m[32];
        exception_handler_info_t info[32];
        exception_behavior_t b[32];
        thread_state_flavor_t f[32];
        mach_msg_type_number_t n = 32;
        kern_return_t kr = task_get_exception_ports_info(readp, 0x7e, m, &n, info, b, f);
        printf("task get info on the read port: kr=%d\n", kr);
#if defined(__arm64__)
        for (unsigned i = 0; kr == 0 && i < n; i++)
            printf("  [%u] mask=%#x port %s receiver %s behavior=%#x flavor=%d\n", i, m[i],
                   info[i].iip_port_object ? "set" : "none", info[i].iip_receiver_object ? "set" : "none",
                   b[i], f[i]);
        n = 32;
        kr = task_get_exception_ports_info(task, 0x1, m, &n, info, b, f);
        printf("task get info, mask 0x1: %d\n", kr);
        n = 32;
        kr = thread_get_exception_ports_info(self, 0x30, m, &n, info, b, f);
        printf("thread get info: kr=%d count=%u\n", kr, n);
        for (unsigned i = 0; kr == 0 && i < n; i++)
            printf("  [%u] mask=%#x port %s behavior=%#x\n", i, m[i], info[i].iip_port_object ? "set" : "none",
                   b[i]);
#endif
    }
    return 0;
}
