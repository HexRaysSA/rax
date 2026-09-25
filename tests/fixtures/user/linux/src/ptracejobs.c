/* Job control of a seized tracee (kernel/signal.c, kernel/ptrace.c)
 * between a parent and its child blocked in a pipe read: PTRACE_INTERRUPT
 * (a PTRACE_EVENT_STOP trap with SIGTRAP and its siginfo, the tracer's
 * SIGCHLD with CLD_STOPPED; another trap after the current one when
 * interrupted while stopped), PTRACE_LISTEN (refused at a
 * signal-delivery-stop; the listening tracee hidden from waitpid and from
 * other requests; PTRACE_INTERRUPT and SIGCONT trapping it again), a group
 * stop (SIGSTOP's signal-delivery-stop with CLD_TRAPPED, then the
 * PTRACE_EVENT_STOP trap with the signal and CLD_STOPPED), SIGCONT's own
 * stop after its trap, the interrupted read restarted, and an attached
 * tracee refusing PTRACE_INTERRUPT and PTRACE_LISTEN. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define EVENT(sig) ((sig) | (PTRACE_EVENT_STOP << 8))

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static int chld_code, chld_status;

/* The SIGCHLD a stop sent the tracer, which blocks it and takes one per
 * stop: ptrace_stop makes the stop visible to waitpid before it sends the
 * signal, so it may come a moment after. */
static void take_chld(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGCHLD);
    siginfo_t si;
    struct timespec second = {1, 0};
    chld_code = chld_status = 0;
    if (sigtimedwait(&s, &si, &second) == SIGCHLD) {
        chld_code = si.si_code;
        chld_status = si.si_status;
    }
}

/* The next stop's exit code (the wait status's high bits), or -1. */
static int wait_stop(pid_t c) {
    int st = 0;
    if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st))
        return -1;
    take_chld();
    return st >> 8;
}

/* The stop's siginfo: signal and code. */
static int siginfo_is(pid_t c, int signo, int code) {
    siginfo_t si;
    return pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_signo == signo && si.si_code == code;
}

static void seized(void) {
    int p[2];
    pipe(p);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        close(p[1]);
        char b = 0;
        long r = read(p[0], &b, 1);
        _exit(r == 1 && b == 'x' ? 0 : 1);
    }
    close(p[0]);
    CHECK("seize", pt(PTRACE_SEIZE, c, 0, 0) == 0);
    /* A trap without side effects. */
    CHECK("interrupt", pt(PTRACE_INTERRUPT, c, 0, 0) == 0 && wait_stop(c) == EVENT(SIGTRAP) &&
                           siginfo_is(c, SIGTRAP, EVENT(SIGTRAP)));
    CHECK("interrupt-sigchld", chld_code == CLD_STOPPED);
    /* Interrupted while stopped: another trap once resumed. */
    CHECK("interrupt-again", pt(PTRACE_INTERRUPT, c, 0, 0) == 0 && pt(PTRACE_CONT, c, 0, 0) == 0 &&
                                 wait_stop(c) == EVENT(SIGTRAP));
    /* Listening: stopped, but out of sight until trapped again. */
    int st = 0;
    CHECK("listen", pt(PTRACE_LISTEN, c, 0, 0) == 0);
    CHECK("listen-hidden", waitpid(c, &st, WNOHANG) == 0);
    CHECK_ERR("listen-no-requests", pt(PTRACE_GETSIGINFO, c, 0, &st), ESRCH);
    CHECK("listen-interrupt", pt(PTRACE_INTERRUPT, c, 0, 0) == 0 && wait_stop(c) == EVENT(SIGTRAP));
    /* A group stop: SIGSTOP's signal-delivery-stop, then its trap. */
    pt(PTRACE_CONT, c, 0, 0);
    kill(c, SIGSTOP);
    CHECK("stop-signal", wait_stop(c) == SIGSTOP && chld_code == CLD_TRAPPED &&
                             chld_status == SIGSTOP);
    CHECK_ERR("listen-signal-stop", pt(PTRACE_LISTEN, c, 0, 0), EIO);
    pt(PTRACE_CONT, c, 0, (void *)SIGSTOP);
    CHECK("group-stop", wait_stop(c) == EVENT(SIGSTOP) && siginfo_is(c, SIGSTOP, EVENT(SIGSTOP)));
    CHECK("group-stop-sigchld", chld_code == CLD_STOPPED && chld_status == SIGSTOP);
    /* Listening through the group stop; SIGCONT traps it with SIGTRAP,
     * then SIGCONT has its own stop. (Continuing also tells the parent,
     * CLD_CONTINUED, whenever the tracee gets to it: not checked.) */
    CHECK("listen-stopped", pt(PTRACE_LISTEN, c, 0, 0) == 0 && waitpid(c, &st, WNOHANG) == 0);
    kill(c, SIGCONT);
    CHECK("continued-trap", wait_stop(c) == EVENT(SIGTRAP));
    pt(PTRACE_CONT, c, 0, 0);
    CHECK("continue-signal", wait_stop(c) == SIGCONT && siginfo_is(c, SIGCONT, SI_USER));
    pt(PTRACE_CONT, c, 0, 0);
    /* The read, interrupted by each trap, goes on. */
    write(p[1], "x", 1);
    CHECK("read-restarted", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(p[1]);
}

static void attached(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        _exit(0);
    }
    wait_stop(c);
    CHECK_ERR("attached-interrupt", pt(PTRACE_INTERRUPT, c, 0, 0), EIO);
    CHECK_ERR("attached-listen", pt(PTRACE_LISTEN, c, 0, 0), EIO);
    pt(PTRACE_CONT, c, 0, 0);
    int st = 0;
    CHECK("attached-exit", waitpid(c, &st, 0) == c && WIFEXITED(st));
}

int main(void) {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    seized();
    attached();
    FINISH();
}
