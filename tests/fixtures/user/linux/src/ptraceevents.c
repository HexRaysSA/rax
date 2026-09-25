/* Events of a traced child (kernel/fork.c, kernel/exit.c, kernel/seccomp.c,
 * kernel/ptrace.c): PTRACE_EVENT_CLONE for a new thread (the maker's stop
 * with the thread's ID as its message, the thread traced from its first
 * instruction with SIGSTOP), PTRACE_EVENT_EXIT for that thread and for the
 * process (exit_group's code, then a fatal signal's number, as the message)
 * and the tracer reaping the thread that exited (after the group began to
 * exit: the group's code), and PTRACE_EVENT_SECCOMP
 * (SECCOMP_RET_TRACE's data as the message, PTRACE_GET_SYSCALL_INFO's
 * seccomp view, the call made once resumed or skipped when the tracer makes
 * its number -1, and ENOSYS once the tracer no longer asks). */
#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define EVENT(e) (SIGTRAP | ((e) << 8))
#ifndef PTRACE_SET_SYSCALL_INFO
#define PTRACE_SET_SYSCALL_INFO 0x4212
#endif

struct info {
    uint8_t op, reserved;
    uint16_t flags;
    uint32_t arch;
    uint64_t ip, sp;
    uint64_t nr, args[6];
    uint32_t ret_data, reserved2;
};

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static unsigned long event_msg(pid_t c) {
    unsigned long m = ~0ul;
    pt(PTRACE_GETEVENTMSG, c, 0, &m);
    return m;
}

/* The next stop of `c` (any thread with __WALL): its exit code, or -1. */
static int stop_of(pid_t c) {
    int st = 0;
    if (waitpid(c, &st, __WALL) != c || !WIFSTOPPED(st))
        return -1;
    return st >> 8;
}

static void *worker(void *arg) {
    (void)arg;
    return NULL;
}

/* A thread made and ended under PTRACE_O_TRACECLONE | TRACEEXIT, then the
 * process's exit_group(3). */
static void threads(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        pthread_join(t, NULL);
        exit(3);
    }
    stop_of(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT));
    pt(PTRACE_CONT, c, 0, 0);
    int clone = stop_of(c);
    pid_t tid = (pid_t)event_msg(c);
    CHECK("clone-event", clone == EVENT(PTRACE_EVENT_CLONE) && tid > 0 && tid != c);
    /* The new thread starts stopped, with SIGSTOP. */
    int st = 0;
    CHECK("clone-thread-stop", waitpid(tid, &st, __WALL) == tid && WIFSTOPPED(st) &&
                                   WSTOPSIG(st) == SIGSTOP);
    pt(PTRACE_CONT, tid, 0, 0);
    pt(PTRACE_CONT, c, 0, 0);
    /* The thread's exit stop, its exit code 0 as the message; then it is
     * the tracer's to reap. */
    CHECK("thread-exit-event", waitpid(tid, &st, __WALL) == tid && WIFSTOPPED(st) &&
                                   (st >> 8) == EVENT(PTRACE_EVENT_EXIT) && event_msg(tid) == 0);
    pt(PTRACE_CONT, tid, 0, 0);
    /* exit_group(3) once the thread is joined: the exit stop with 3 << 8.
     * The thread, reaped only now that the group is exiting, reports the
     * group's code (wait_task_zombie), not its own. */
    CHECK("exit-event", stop_of(c) == EVENT(PTRACE_EVENT_EXIT) && event_msg(c) == 0x300);
    CHECK("thread-reaped", waitpid(tid, &st, __WALL) == tid && WIFEXITED(st) &&
                               WEXITSTATUS(st) == 3);
    pt(PTRACE_CONT, c, 0, 0);
    CHECK("exited", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 3);
}

/* A fatal signal: its signal-delivery-stop, then the exit stop with the
 * signal as the message. */
static void fatal(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        raise(SIGTERM);
        _exit(0);
    }
    stop_of(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACEEXIT);
    pt(PTRACE_CONT, c, 0, 0);
    CHECK("fatal-signal-stop", stop_of(c) == SIGTERM);
    pt(PTRACE_CONT, c, 0, (void *)SIGTERM);
    CHECK("fatal-exit-event", stop_of(c) == EVENT(PTRACE_EVENT_EXIT) && event_msg(c) == SIGTERM);
    pt(PTRACE_CONT, c, 0, 0);
    int st = 0;
    CHECK("fatal-died", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
}

/* SECCOMP_RET_TRACE | 42 for getppid. */
static void filter(void) {
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | 42),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fp = {sizeof prog / sizeof prog[0], prog};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp);
}

static void seccomp_event(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pid_t parent = getppid();
        filter();
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        int ok = parent == syscall(SYS_getppid);
        errno = 0;
        ok &= syscall(SYS_getppid) == -1 && errno == ENOSYS;
        errno = 0;
        ok &= syscall(SYS_getppid) == -1 && errno == ENOSYS;
        _exit(ok ? 0 : 1);
    }
    stop_of(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACESECCOMP);
    pt(PTRACE_CONT, c, 0, 0);
    struct info i;
    memset(&i, 0, sizeof i);
    CHECK("seccomp-event", stop_of(c) == EVENT(PTRACE_EVENT_SECCOMP) && event_msg(c) == 42);
    long size = pt(PTRACE_GET_SYSCALL_INFO, c, (void *)sizeof i, &i);
    CHECK("seccomp-info", size == 84 && i.op == PTRACE_SYSCALL_INFO_SECCOMP &&
                              i.nr == SYS_getppid && i.ret_data == 42);
    /* Resumed: looked at again and made. */
    pt(PTRACE_CONT, c, 0, 0);
    /* The second call: skipped with -1. */
    CHECK("seccomp-again", stop_of(c) == EVENT(PTRACE_EVENT_SECCOMP));
    pt(PTRACE_GET_SYSCALL_INFO, c, (void *)sizeof i, &i);
    i.nr = (uint64_t)-1;
    CHECK("seccomp-skip", pt(PTRACE_SET_SYSCALL_INFO, c, (void *)sizeof i, &i) == 0);
    /* The third: no longer asked for, ENOSYS. */
    pt(PTRACE_SETOPTIONS, c, 0, 0);
    pt(PTRACE_CONT, c, 0, 0);
    int st = 0;
    CHECK("seccomp-results", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

int main(void) {
    threads();
    fatal();
    seccomp_event();
    FINISH();
}
