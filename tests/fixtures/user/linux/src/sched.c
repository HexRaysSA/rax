/* Scheduling attributes without privilege (kernel/sched/syscalls.c,
 * kernel/sys.c, block/ioprio.c): policies and their checks in order,
 * sched_setattr and sched_getattr (sizes, flags, the slice, keeping the
 * policy or the parameters, SCHED_IDLE's priority), nice values with
 * setpriority and getpriority (a thread, the group, the user, a partial
 * failure), SCHED_RESET_ON_FORK, inheritance by threads and children,
 * timer slack, the priority ranges, /proc/<pid>/stat's priority fields,
 * and I/O priorities. Root drops to nobody; the kernel's default slice and
 * time slices depend on the machine's CPUs and HZ and are not printed. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

#define BAD ((void *)16)
#define SCHED_NORMAL 0
#define SCHED_FIFO_ 1
#define SCHED_RR_ 2
#define SCHED_BATCH_ 3
#define SCHED_IDLE_ 5
#define SCHED_DEADLINE 6
#define RESET_ON_FORK 0x40000000
#define IOPRIO_BE (2 << 13)

struct attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t prio;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

static long setattr(struct attr a) {
    return syscall(SYS_sched_setattr, 0, &a, 0);
}

static struct attr getattr(pid_t pid) {
    struct attr a;
    memset(&a, 0xff, sizeof a);
    if (syscall(SYS_sched_getattr, pid, &a, sizeof a, 0) != 0) memset(&a, 0xee, sizeof a);
    return a;
}

static long setscheduler(pid_t pid, int policy, int prio) {
    return syscall(SYS_sched_setscheduler, pid, policy, &prio);
}

/* Fields 18, 19, 40, and 41 of /proc/self/task/<tid>/stat. */
static void stat_fields(pid_t tid, long f[4]) {
    char path[64], b[1024];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    FILE *fp = fopen(path, "r");
    b[0] = 0;
    if (fp) {
        fgets(b, sizeof b, fp);
        fclose(fp);
    }
    char *p = strrchr(b, ')');
    int field = 2;
    for (char *t = p ? strtok(p + 2, " ") : NULL; t; t = strtok(NULL, " ")) {
        field++;
        if (field == 18) f[0] = atol(t);
        if (field == 19) f[1] = atol(t);
        if (field == 40) f[2] = atol(t);
        if (field == 41) f[3] = atol(t);
    }
}

static int stat_is(pid_t tid, long prio, long nice, long rt, long policy) {
    long f[4] = {-999, -999, -999, -999};
    stat_fields(tid, f);
    return f[0] == prio && f[1] == nice && f[2] == rt && f[3] == policy;
}

static void policies(void) {
    int param = 0;
    CHECK("default-policy", syscall(SYS_sched_getscheduler, 0) == SCHED_NORMAL);
    CHECK("default-param", syscall(SYS_sched_getparam, 0, &param) == 0 && param == 0);
    struct attr a = getattr(0);
    CHECK("default-attr", a.size == 56 && a.policy == 0 && a.flags == 0 && a.nice == 0 && a.prio == 0 &&
                              a.deadline == 0 && a.period == 0);
    CHECK("default-stat", stat_is(gettid(), 20, 0, 0, 0));
    CHECK_ERR("getscheduler-pid", syscall(SYS_sched_getscheduler, -1), EINVAL);
    CHECK_ERR("getparam-null", syscall(SYS_sched_getparam, 0, NULL), EINVAL);
    CHECK_ERR("getparam-fault", syscall(SYS_sched_getparam, 0, BAD), EFAULT);
    CHECK_ERR("getparam-missing", syscall(SYS_sched_getparam, 4194303, &param), ESRCH);
    CHECK_ERR("setscheduler-policy", syscall(SYS_sched_setscheduler, 0, -1, BAD), EINVAL);
    CHECK_ERR("setscheduler-null", syscall(SYS_sched_setscheduler, 0, 0, NULL), EINVAL);
    CHECK_ERR("setscheduler-fault", syscall(SYS_sched_setscheduler, 0, 0, BAD), EFAULT);
    CHECK_ERR("setscheduler-missing", setscheduler(4194303, 4, 0), ESRCH);
    CHECK_ERR("setscheduler-unknown", setscheduler(0, 4, 0), EINVAL);
    CHECK_ERR("setscheduler-ext", setscheduler(0, 7, 0), EINVAL);
    CHECK_ERR("setscheduler-fifo-zero", setscheduler(0, SCHED_FIFO_, 0), EINVAL);
    CHECK_ERR("setscheduler-normal-prio", setscheduler(0, SCHED_NORMAL, 1), EINVAL);
    CHECK_ERR("setscheduler-rr-100", setscheduler(0, SCHED_RR_, 100), EINVAL);
    CHECK_ERR("setscheduler-fifo", setscheduler(0, SCHED_FIFO_, 1), EPERM);
    CHECK_ERR("setparam-zero", syscall(SYS_sched_setparam, 0, &(int){1}), EINVAL);
    int max[] = {0, 99, 99, 0, -1, 0, 0, 0, -1}, min[] = {0, 1, 1, 0, -1, 0, 0, 0, -1};
    for (int p = 0; p <= 8; p++) {
        char name[32];
        snprintf(name, sizeof name, "priority-range-%d", p);
        long hi = syscall(SYS_sched_get_priority_max, p), lo = syscall(SYS_sched_get_priority_min, p);
        CHECK(name, hi == max[p] && lo == min[p]);
    }
    CHECK("reset-on-fork-set", setscheduler(0, SCHED_BATCH_ | RESET_ON_FORK, 0) == 0 &&
                                   syscall(SYS_sched_getscheduler, 0) == (SCHED_BATCH_ | RESET_ON_FORK));
    CHECK_ERR("reset-on-fork-kept", setscheduler(0, SCHED_NORMAL, 0), EPERM);
    CHECK("reset-on-fork-attr", getattr(0).flags == 1);
    struct timespec ts;
    CHECK_ERR("rr-interval-pid", syscall(SYS_sched_rr_get_interval, -1, &ts), EINVAL);
    CHECK_ERR("rr-interval-fault", syscall(SYS_sched_rr_get_interval, 0, BAD), EFAULT);
    CHECK("rr-interval", syscall(SYS_sched_rr_get_interval, 0, &ts) == 0);
}

static void attributes(void) {
    struct attr a = {.size = 47};
    CHECK_ERR("setattr-null", syscall(SYS_sched_setattr, 0, NULL, 0), EINVAL);
    CHECK_ERR("setattr-flags-arg", syscall(SYS_sched_setattr, 0, &a, 1), EINVAL);
    CHECK_ERR("setattr-fault", syscall(SYS_sched_setattr, 0, BAD, 0), EFAULT);
    CHECK_ERR("setattr-small", syscall(SYS_sched_setattr, 0, &a, 0), E2BIG);
    CHECK("setattr-small-size", a.size == 56);
    unsigned char big[80] = {0};
    ((struct attr *)big)->size = 80;
    big[70] = 1;
    CHECK_ERR("setattr-tail", syscall(SYS_sched_setattr, 0, big, 0), E2BIG);
    big[70] = 0;
    ((struct attr *)big)->size = 80;
    ((struct attr *)big)->policy = SCHED_BATCH_;
    ((struct attr *)big)->flags = RESET_ON_FORK >> 30;
    CHECK("setattr-zero-tail", syscall(SYS_sched_setattr, 0, big, 0) == 0);
    CHECK("setattr-size-0", setattr((struct attr){.size = 0, .policy = SCHED_BATCH_, .flags = 1}) == 0);
    CHECK_ERR("setattr-uclamp", setattr((struct attr){.size = 56, .flags = 0x21}), EOPNOTSUPP);
    CHECK_ERR("setattr-uclamp-v0", setattr((struct attr){.size = 48, .flags = 0x21}), EINVAL);
    CHECK_ERR("setattr-unknown-flag", setattr((struct attr){.size = 56, .flags = 0x81}), EINVAL);
    CHECK_ERR("setattr-negative-policy", setattr((struct attr){.size = 56, .policy = -1, .flags = 1}), EINVAL);
    struct attr b = {.size = 56, .policy = SCHED_BATCH_, .flags = 1, .nice = 100};
    CHECK("setattr-nice-clamped", setattr(b) == 0 && getattr(0).nice == 19);
    b.nice = 10;
    CHECK_ERR("setattr-nice-lower", setattr(b), EPERM);
    b.nice = 19;
    b.runtime = 5000000;
    CHECK("setattr-slice", setattr(b) == 0 && getattr(0).runtime == 5000000);
    b.runtime = 1;
    CHECK("setattr-slice-min", setattr(b) == 0 && getattr(0).runtime == 100000);
    b.runtime = UINT64_MAX;
    CHECK("setattr-slice-max", setattr(b) == 0 && getattr(0).runtime == 100000000);
    b.runtime = 0;
    setattr(b);
    /* SCHED_FLAG_KEEP_PARAMS skips the parameters, the policy with them. */
    struct attr params = {.size = 56, .flags = 0x10 | 1, .policy = SCHED_NORMAL, .nice = -5};
    CHECK("keep-params", setattr(params) == 0 && getattr(0).policy == SCHED_BATCH_ && getattr(0).nice == 19);
    struct attr idle = {.size = 56, .policy = SCHED_IDLE_, .flags = 1};
    CHECK("idle", setattr(idle) == 0);
    struct attr g = getattr(0);
    CHECK("idle-keeps-nice", g.policy == SCHED_IDLE_ && g.nice == 19);
    CHECK("idle-stat", stat_is(gettid(), 20, 19, 0, 5));
    CHECK_ERR("idle-leave", setattr(b), EPERM);
    struct attr keep = {.size = 56, .flags = 0x08 | 1, .policy = SCHED_FIFO_, .nice = 5};
    CHECK("keep-policy", setattr(keep) == 0 && getattr(0).policy == SCHED_IDLE_ && getattr(0).nice == 19);
    CHECK_ERR("keep-params-idle", setattr(params), EPERM);
    struct attr dl = {.size = 56, .policy = SCHED_DEADLINE, .flags = 1, .runtime = 10000000,
                      .deadline = 30000000, .period = 100000000};
    CHECK_ERR("deadline", setattr(dl), EPERM);
    dl.runtime = 1023;
    CHECK_ERR("deadline-runtime", setattr(dl), EINVAL);
    struct attr out;
    CHECK_ERR("getattr-small", syscall(SYS_sched_getattr, 0, &out, 47, 0), EINVAL);
    CHECK_ERR("getattr-big", syscall(SYS_sched_getattr, 0, &out, 4097, 0), EINVAL);
    CHECK_ERR("getattr-flags", syscall(SYS_sched_getattr, 0, &out, 56, 1), EINVAL);
    CHECK_ERR("getattr-missing", syscall(SYS_sched_getattr, 4194303, &out, 56, 0), ESRCH);
    memset(&out, 0xff, sizeof out);
    CHECK("getattr-v0", syscall(SYS_sched_getattr, 0, &out, 48, 0) == 0 && out.size == 48 && out.util_min == 0xffffffff);
    unsigned char wide[72];
    memset(wide, 0xff, sizeof wide);
    CHECK("getattr-wide", syscall(SYS_sched_getattr, 0, wide, 72, 0) == 0 && ((struct attr *)wide)->size == 56 &&
                              wide[56] == 0 && wide[71] == 0);
}

static void *sleeper(void *arg) {
    pthread_barrier_t *b = arg;
    pthread_barrier_wait(b);
    pthread_barrier_wait(b);
    return NULL;
}

static void nice_values(void) {
    CHECK_ERR("getpriority-which", syscall(SYS_getpriority, 3, 0), EINVAL);
    CHECK_ERR("setpriority-which", syscall(SYS_setpriority, -1, 0, 0), EINVAL);
    CHECK_ERR("getpriority-missing", syscall(SYS_getpriority, PRIO_PROCESS, 4194303), ESRCH);
    CHECK_ERR("setpriority-missing", syscall(SYS_setpriority, PRIO_PROCESS, 4194303, 5), ESRCH);
    /* A process of its own, whose group is only itself. */
    pid_t c = fork();
    if (c == 0) {
        setpgid(0, 0);
        pthread_barrier_t b;
        pthread_barrier_init(&b, NULL, 2);
        pthread_t t;
        pthread_create(&t, NULL, sleeper, &b);
        pthread_barrier_wait(&b);
        pid_t tid = 0;
        /* The thread's ID: the other task in /proc/self/task. */
        for (pid_t id = gettid() + 1; id < gettid() + 64 && !tid; id++) {
            char path[64];
            snprintf(path, sizeof path, "/proc/self/task/%d", id);
            if (access(path, F_OK) == 0) tid = id;
        }
        int ok = 1;
        ok &= tid > 0;
        ok &= syscall(SYS_setpriority, PRIO_PROCESS, tid, 5) == 0;
        ok &= syscall(SYS_getpriority, PRIO_PROCESS, tid) == 15;
        ok &= syscall(SYS_getpriority, PRIO_PROCESS, 0) == 20;
        ok &= syscall(SYS_setpriority, PRIO_PROCESS, tid, 4) == -1 && errno == EACCES;
        ok &= syscall(SYS_setpriority, PRIO_PROCESS, tid, 100) == 0;
        ok &= syscall(SYS_getpriority, PRIO_PROCESS, tid) == 1;
        ok &= syscall(SYS_setpriority, PRIO_PROCESS, 0, -1) == -1 && errno == EACCES;
        ok &= syscall(SYS_getpriority, PRIO_PGRP, 0) == 20;
        ok &= syscall(SYS_setpriority, PRIO_PROCESS, 0, 7) == 0;
        ok &= syscall(SYS_getpriority, PRIO_PGRP, 0) == 13;
        /* A partial failure: the leader rises, the thread cannot fall. */
        ok &= syscall(SYS_setpriority, PRIO_PGRP, 0, 10) == -1 && errno == EACCES;
        ok &= syscall(SYS_getpriority, PRIO_PROCESS, 0) == 10;
        ok &= syscall(SYS_getpriority, PRIO_PROCESS, tid) == 1;
        ok &= stat_is(gettid(), 30, 10, 0, 3) && stat_is(tid, 39, 19, 0, 3);
        struct attr a = getattr(tid);
        ok &= a.nice == 19;
        pthread_barrier_wait(&b);
        pthread_join(t, NULL);
        _exit(ok ? 0 : 1);
    }
    int status;
    waitpid(c, &status, 0);
    CHECK("nice-values", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void *report(void *arg) {
    long *out = arg;
    struct attr a = getattr(0);
    out[0] = a.policy;
    out[1] = a.nice;
    out[2] = a.runtime;
    out[3] = a.flags;
    out[4] = prctl(PR_GET_TIMERSLACK);
    out[5] = syscall(SYS_ioprio_get, 1, 0);
    return NULL;
}

static void inheritance(void) {
    long out[6];
    pthread_t t;
    /* SCHED_RESET_ON_FORK keeps a SCHED_IDLE policy and a positive nice
     * value, and is not inherited itself. */
    prctl(PR_SET_TIMERSLACK, 7777);
    syscall(SYS_ioprio_set, 1, 0, IOPRIO_BE | 6);
    pthread_create(&t, NULL, report, out);
    pthread_join(t, NULL);
    CHECK("thread-inherits", out[0] == SCHED_IDLE_ && out[1] == 19 && out[3] == 0 && out[4] == 7777 &&
                                 out[5] == (IOPRIO_BE | 6));
    pid_t c = fork();
    if (c == 0) {
        struct attr a = getattr(0);
        _exit(a.policy == SCHED_IDLE_ && a.nice == 19 && a.flags == 0 && prctl(PR_GET_TIMERSLACK) == 7777 &&
                      syscall(SYS_ioprio_get, 1, 0) == (IOPRIO_BE | 6)
                  ? 0
                  : 1);
    }
    int status;
    waitpid(c, &status, 0);
    CHECK("child-inherits", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("parent-keeps-reset", getattr(0).flags == 1);
    CHECK("timer-slack-default", prctl(PR_SET_TIMERSLACK, 0) == 0 && prctl(PR_GET_TIMERSLACK) == 50000);
}

static void io_priorities(void) {
    CHECK_ERR("ioprio-get-which", syscall(SYS_ioprio_get, 4, 0), EINVAL);
    CHECK_ERR("ioprio-get-missing", syscall(SYS_ioprio_get, 1, 4194303), ESRCH);
    CHECK_ERR("ioprio-set-rt", syscall(SYS_ioprio_set, 4, 4194303, 1 << 13), EPERM);
    CHECK_ERR("ioprio-set-level", syscall(SYS_ioprio_set, 4, 4194303, 3), EINVAL);
    CHECK_ERR("ioprio-set-class", syscall(SYS_ioprio_set, 4, 4194303, 4 << 13), EINVAL);
    CHECK_ERR("ioprio-set-which", syscall(SYS_ioprio_set, 4, 0, IOPRIO_BE), EINVAL);
    CHECK_ERR("ioprio-set-missing", syscall(SYS_ioprio_set, 1, 4194303, IOPRIO_BE), ESRCH);
    pid_t c = fork();
    if (c == 0) {
        setpgid(0, 0);
        int ok = syscall(SYS_ioprio_get, 1, 0) == (IOPRIO_BE | 6);
        ok &= syscall(SYS_ioprio_set, 1, 0, 0) == 0;
        ok &= syscall(SYS_ioprio_get, 1, 0) == 0;
        /* Unset: the class and level of the nice value and policy. */
        ok &= syscall(SYS_ioprio_get, 2, 0) == ((3 << 13) | 7);
        ok &= syscall(SYS_ioprio_set, 2, 0, IOPRIO_BE | 2) == 0;
        ok &= syscall(SYS_ioprio_get, 2, 0) == (IOPRIO_BE | 2);
        /* User 0 is root, whose tasks another user may not change. */
        ok &= syscall(SYS_ioprio_set, 3, 0, IOPRIO_BE) == -1 && errno == EPERM;
        ok &= syscall(SYS_ioprio_set, 3, -1, IOPRIO_BE) == -1 && errno == ESRCH;
        ok &= syscall(SYS_ioprio_set, 3, getuid(), IOPRIO_BE | 1) == 0;
        ok &= syscall(SYS_ioprio_get, 1, 0) == (IOPRIO_BE | 1);
        _exit(ok ? 0 : 1);
    }
    int status;
    waitpid(c, &status, 0);
    CHECK("ioprio-group-and-user", WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (getuid() == 0 && (setgid(65534) != 0 || setuid(65534) != 0)) {
            printf("FAIL drop-privileges\n");
            exit(1);
        }
        policies();
        nice_values();
        attributes();
        inheritance();
        io_priorities();
        fflush(stdout);
        exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(c, &status, 0);
    failures = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    FINISH();
}
