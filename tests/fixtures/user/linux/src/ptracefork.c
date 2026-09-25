/* A traced child's children (kernel/fork.c, kernel/exit.c, kernel/ptrace.c):
 * with PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK and PTRACE_O_TRACEVFORKDONE,
 * and PTRACE_O_TRACECLONE, the child stops for PTRACE_EVENT_FORK,
 * PTRACE_EVENT_VFORK (then PTRACE_EVENT_VFORK_DONE once the vfork child is
 * gone), and PTRACE_EVENT_CLONE (a process clone with no exit signal), the
 * new process's ID as the message; the grandchild is traced by the tracer
 * from its first instruction (SIGSTOP), its memory within the tracer's
 * reach, and the tracer reaps it (its exit status); then its parent, told
 * with its exit signal (the traced parent's signal-delivery-stop for
 * SIGCHLD with CLD_EXITED; none for a clone without one), reaps it too. */
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

#define EVENT(e) (SIGTRAP | ((e) << 8))

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static unsigned long event_msg(pid_t c) {
    unsigned long m = ~0ul;
    pt(PTRACE_GETEVENTMSG, c, 0, &m);
    return m;
}

static int stop_of(pid_t c) {
    int st = 0;
    if (waitpid(c, &st, __WALL) != c || !WIFSTOPPED(st))
        return -1;
    return st >> 8;
}

static volatile long marker = 0x5eed;

enum kind { FORK, VFORK, CLONE };

/* The child: traced, it makes a grandchild of this kind that exits with
 * `code`; it reaps the grandchild only once the tracer has (a byte on
 * `go`), and reports whether it saw that status too. */
static int child(enum kind k, int code, int go) {
    pt(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    pid_t g;
    if (k == VFORK)
        g = vfork();
    else if (k == FORK)
        g = fork();
    else
        g = syscall(SYS_clone, 0, 0, 0, 0, 0);
    if (g == 0)
        _exit(code);
    char b;
    read(go, &b, 1);
    int st = 0;
    return waitpid(g, &st, __WALL) == g && WIFEXITED(st) && WEXITSTATUS(st) == code ? 0 : 1;
}

static void events(enum kind k, const char *name, long options, int event, int code) {
    char check[64];
    int go[2];
    pipe(go);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0)
        _exit(child(k, code, go[0]));
    stop_of(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)options);
    pt(PTRACE_CONT, c, 0, 0);
    int s = stop_of(c);
    pid_t g = (pid_t)event_msg(c);
    snprintf(check, sizeof check, "%s-event", name);
    CHECK(check, s == EVENT(event) && g > 0 && g != c);
    /* The grandchild starts stopped, and is the tracer's. */
    long word = 0;
    snprintf(check, sizeof check, "%s-traced", name);
    CHECK(check, stop_of(g) == SIGSTOP && pt(PTRACE_PEEKDATA, g, (void *)&marker, &word) == 0 &&
                     word == 0x5eed);
    pt(PTRACE_CONT, g, 0, 0);
    pt(PTRACE_CONT, c, 0, 0);
    if (k == VFORK) {
        /* The vfork child is gone: the child's second event. */
        snprintf(check, sizeof check, "%s-done", name);
        CHECK(check, stop_of(c) == EVENT(PTRACE_EVENT_VFORK_DONE) && event_msg(c) == (unsigned long)g);
        pt(PTRACE_CONT, c, 0, 0);
    }
    /* The tracer reaps the grandchild, then its parent may. */
    int st = 0;
    snprintf(check, sizeof check, "%s-reaped", name);
    CHECK(check, waitpid(g, &st, __WALL) == g && WIFEXITED(st) && WEXITSTATUS(st) == code);
    if (k != CLONE) {
        siginfo_t si;
        memset(&si, 0, sizeof si);
        snprintf(check, sizeof check, "%s-parent-told", name);
        CHECK(check, stop_of(c) == SIGCHLD && pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 &&
                         si.si_code == CLD_EXITED && si.si_pid == g && si.si_status == code);
        pt(PTRACE_CONT, c, 0, 0);
    }
    write(go[1], "x", 1);
    snprintf(check, sizeof check, "%s-parent", name);
    CHECK(check, waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(go[0]);
    close(go[1]);
}

int main(void) {
    events(FORK, "fork", PTRACE_O_TRACEFORK, PTRACE_EVENT_FORK, 7);
    events(VFORK, "vfork", PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE, PTRACE_EVENT_VFORK, 5);
    events(CLONE, "clone", PTRACE_O_TRACECLONE, PTRACE_EVENT_CLONE, 9);
    FINISH();
}
