/* ptrace (kernel/ptrace.c) between a parent and its child: the checks in
 * order (a missing task, the caller's own process, a task not traced or not
 * stopped, PTRACE_SEIZE's address and options, a resumption's signal,
 * register sets, signal masks, options); PTRACE_TRACEME (once), a
 * signal-delivery-stop reported by waitpid without WUNTRACED and by SIGCHLD
 * with CLD_TRAPPED, PTRACE_GETSIGINFO, PEEKDATA and POKEDATA (also into
 * read-only text), the general registers, the signal mask, PTRACE_CONT
 * cancelling the signal or changing it; PTRACE_ATTACH's SIGSTOP and
 * PTRACE_DETACH; execve's SIGTRAP and, with PTRACE_O_TRACEEXEC, its event
 * stop and message; TracerPid; and a child attaching to its parent while
 * the parent waits for it. Every value that differs between architectures
 * is checked here, not printed. */
#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#if defined(__x86_64__)
#define REGS_SIZE 216
#define PC_OF(r) ((r)[16])
#elif defined(__aarch64__)
#define REGS_SIZE 272
#define PC_OF(r) ((r)[32])
#elif defined(__riscv)
#define REGS_SIZE 256
#define PC_OF(r) ((r)[0])
#endif

#define BAD ((void *)16)

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static volatile long secret = 0x1122334455667788;
static const long constant = 0x0102030405060708;
static volatile int handled;
static volatile int chld_code;
static void on_usr1(int s) { (void)s; handled++; }
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s;
    (void)u;
    chld_code = si->si_code;
}

static long tracer_pid(void) {
    static char b[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    long n = read(fd, b, sizeof b - 1);
    close(fd);
    b[n > 0 ? n : 0] = 0;
    char *l = strstr(b, "TracerPid:");
    return l ? strtol(l + 10, NULL, 10) : -1;
}

/* The checks that need no tracee. */
static void checks(void) {
    CHECK_ERR("no-task", pt(PTRACE_PEEKDATA, 0x7ffffff, BAD, BAD), ESRCH);
    CHECK_ERR("zero-pid", pt(PTRACE_PEEKDATA, 0, BAD, BAD), ESRCH);
    CHECK_ERR("own-process", pt(PTRACE_ATTACH, getpid(), 0, 0), EPERM);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pause();
        _exit(0);
    }
    CHECK_ERR("not-traced", pt(PTRACE_PEEKDATA, c, (void *)&secret, BAD), ESRCH);
    CHECK_ERR("seize-addr", pt(PTRACE_SEIZE, c, (void *)1, 0), EIO);
    CHECK_ERR("seize-options", pt(PTRACE_SEIZE, c, 0, (void *)0x400000), EIO);
    CHECK("seize", pt(PTRACE_SEIZE, c, 0, (void *)PTRACE_O_EXITKILL) == 0);
    CHECK_ERR("seize-again", pt(PTRACE_SEIZE, c, 0, 0), EPERM);
    CHECK_ERR("running", pt(PTRACE_PEEKDATA, c, (void *)&secret, BAD), ESRCH);
    CHECK("kill-running", pt(PTRACE_KILL, c, 0, 0) == 0);
    int st = 0;
    CHECK("killed", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
}

/* PTRACE_TRACEME and a signal-delivery-stop. */
static void traceme(void) {
    struct sigaction sa = {.sa_sigaction = on_chld, .sa_flags = SA_SIGINFO};
    sigaction(SIGCHLD, &sa, NULL);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        signal(SIGUSR1, on_usr1);
        int ok = pt(PTRACE_TRACEME, 0, 0, 0) == 0;
        ok &= pt(PTRACE_TRACEME, 0, 0, 0) == -1 && errno == EPERM;
        ok &= tracer_pid() == getppid();
        raise(SIGUSR1);
        /* The tracer cancelled SIGUSR1 and changed the words. */
        ok &= handled == 0 && secret == 0x55 && constant == 0x0102030405060708;
        raise(SIGUSR1);
        ok &= handled == 1;
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    CHECK("stop-reported", waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGUSR1);
    CHECK("sigchld-trapped", chld_code == CLD_TRAPPED);
    siginfo_t si;
    CHECK("getsiginfo", pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_signo == SIGUSR1 &&
                            si.si_code == SI_TKILL && si.si_pid == c);
    CHECK_ERR("getsiginfo-fault", pt(PTRACE_GETSIGINFO, c, 0, BAD), EFAULT);
    long word = 0;
    CHECK("peekdata", pt(PTRACE_PEEKDATA, c, (void *)&secret, &word) == 0 && word == 0x1122334455667788);
    CHECK_ERR("peekdata-unmapped", pt(PTRACE_PEEKDATA, c, BAD, &word), EIO);
    CHECK_ERR("peekdata-fault", pt(PTRACE_PEEKDATA, c, (void *)&secret, BAD), EFAULT);
    CHECK("pokedata", pt(PTRACE_POKEDATA, c, (void *)&secret, (void *)0x55) == 0);
    /* POKETEXT writes where the tracee cannot (FOLL_FORCE), and back. */
    CHECK("poketext-readonly", pt(PTRACE_POKETEXT, c, (void *)&constant, (void *)0x77) == 0 &&
                                   pt(PTRACE_PEEKTEXT, c, (void *)&constant, &word) == 0 && word == 0x77 &&
                                   pt(PTRACE_POKETEXT, c, (void *)&constant, (void *)constant) == 0);
    uint64_t regs[64];
    struct iovec iov = {regs, sizeof regs};
    CHECK("getregset", pt(PTRACE_GETREGSET, c, (void *)NT_PRSTATUS, &iov) == 0 && iov.iov_len == REGS_SIZE &&
                           PC_OF(regs) != 0);
    iov.iov_len = 12;
    CHECK_ERR("getregset-length", pt(PTRACE_GETREGSET, c, (void *)NT_PRSTATUS, &iov), EINVAL);
    iov.iov_len = sizeof regs;
    CHECK_ERR("getregset-type", pt(PTRACE_GETREGSET, c, (void *)0x999, &iov), EINVAL);
    iov.iov_len = REGS_SIZE;
    CHECK("setregset", pt(PTRACE_SETREGSET, c, (void *)NT_PRSTATUS, &iov) == 0 && iov.iov_len == REGS_SIZE);
    uint64_t mask = 0;
    CHECK("getsigmask", pt(PTRACE_GETSIGMASK, c, (void *)8, &mask) == 0 && mask == 0);
    CHECK_ERR("getsigmask-size", pt(PTRACE_GETSIGMASK, c, (void *)4, &mask), EINVAL);
    CHECK_ERR("setoptions-unknown", pt(PTRACE_SETOPTIONS, c, 0, (void *)0x400000), EINVAL);
    CHECK_ERR("cont-signal", pt(PTRACE_CONT, c, 0, (void *)65), EIO);
    CHECK("cont-cancelled", pt(PTRACE_CONT, c, 0, 0) == 0);
    CHECK("second-stop", waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGUSR1);
    CHECK("cont-delivered", pt(PTRACE_CONT, c, 0, (void *)SIGUSR1) == 0);
    CHECK("tracee-exit", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    signal(SIGCHLD, SIG_DFL);
}

/* A fatal signal to a traced process stops it first: the tracer cancels
 * it (the process lives on) or lets it through (the process dies of it). */
static void fatal(void) {
    for (int deliver = 0; deliver < 2; deliver++) {
        fflush(stdout);
        pid_t c = fork();
        if (c == 0) {
            pt(PTRACE_TRACEME, 0, 0, 0);
            raise(SIGUSR2);
            _exit(7);
        }
        int st = 0;
        CHECK(deliver ? "fatal-stops-again" : "fatal-stops",
              waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGUSR2);
        pt(PTRACE_CONT, c, 0, deliver ? (void *)SIGUSR2 : 0);
        if (deliver)
            CHECK("fatal-delivered", waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGUSR2);
        else
            CHECK("fatal-cancelled", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 7);
    }
}

/* PTRACE_ATTACH stops with SIGSTOP; PTRACE_DETACH lets it go. */
static void attach(void) {
    int go[2];
    pipe(go);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        char b;
        read(go[0], &b, 1);
        _exit(secret == 0x66 ? 0 : 1);
    }
    int st = 0;
    CHECK("attach", pt(PTRACE_ATTACH, c, 0, 0) == 0);
    CHECK("attach-stop", waitpid(c, &st, 0) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
    CHECK("attach-poke", pt(PTRACE_POKEDATA, c, (void *)&secret, (void *)0x66) == 0);
    CHECK("detach", pt(PTRACE_DETACH, c, 0, 0) == 0);
    CHECK_ERR("detached", pt(PTRACE_PEEKDATA, c, (void *)&secret, BAD), ESRCH);
    write(go[1], "x", 1);
    CHECK("attached-exit", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* execve: SIGTRAP, or the PTRACE_EVENT_EXEC stop. */
static void exec_stops(const char *self) {
    for (int event = 0; event < 2; event++) {
        fflush(stdout);
        pid_t c = fork();
        if (c == 0) {
            pt(PTRACE_TRACEME, 0, 0, 0);
            raise(SIGSTOP);
            execl(self, self, "exit", (char *)NULL);
            _exit(99);
        }
        int st = 0;
        waitpid(c, &st, 0);
        if (event) pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACEEXEC);
        pt(PTRACE_CONT, c, 0, 0);
        int stopped = waitpid(c, &st, 0) == c && WIFSTOPPED(st);
        if (event) {
            unsigned long msg = 0;
            CHECK("exec-event", stopped && (st >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)) &&
                                    pt(PTRACE_GETEVENTMSG, c, 0, &msg) == 0 && (pid_t)msg == c);
        } else {
            CHECK("exec-sigtrap", stopped && WSTOPSIG(st) == SIGTRAP && (st >> 16) == 0);
        }
        pt(PTRACE_CONT, c, 0, 0);
        CHECK(event ? "exec-event-exit" : "exec-sigtrap-exit",
              waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 42);
    }
}

/* A child attaches to its parent, which waits for it. */
static void reverse(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pid_t parent = getppid();
        int ok = pt(PTRACE_ATTACH, parent, 0, 0) == 0;
        int st = 0;
        ok &= waitpid(parent, &st, __WALL) == parent && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP;
        long word = 0;
        ok &= pt(PTRACE_PEEKDATA, parent, (void *)&secret, &word) == 0 && word == 0x1122334455667788;
        ok &= pt(PTRACE_POKEDATA, parent, (void *)&secret, (void *)0x99) == 0;
        ok &= pt(PTRACE_DETACH, parent, 0, 0) == 0;
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    CHECK("parent-traced", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0 &&
                               secret == 0x99);
    secret = 0x1122334455667788;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "exit") == 0) return 42;
    checks();
    traceme();
    fatal();
    attach();
    exec_stops(argv[0]);
    reverse();
    FINISH();
}
