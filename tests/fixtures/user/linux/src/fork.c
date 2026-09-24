/* New processes: fork, vfork, posix_spawn, clone with an exit signal, and
 * fork in a second thread; waitpid/waitid statuses for exits, signals,
 * stops, and continuations; SIGCHLD and its siginfo, SA_NOCLDSTOP, and
 * automatic reaping when SIGCHLD is ignored; pipes between processes;
 * process groups and kill(0); signals sent to a child as it is created.
 * Children report through exit codes and pipes; only the parent prints.
 * The program first makes itself a process-group leader, so signals to
 * its group reach only its own processes. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

extern char **environ;

static volatile sig_atomic_t chld_count, usr1_count;
static volatile int chld_code, chld_pid, chld_status;

static void on_chld(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    chld_count++;
    chld_code = si->si_code;
    chld_pid = si->si_pid;
    chld_status = si->si_status;
}

static void on_usr1(int sig) {
    (void)sig;
    usr1_count++;
}

static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&t, &t) != 0) {
    }
}

/* Forks in a second thread: the child's only thread is the one that
 * forked, and it has the process's ID. */
static void *fork_in_thread(void *arg) {
    pid_t p = fork();
    if (p == 0) {
        DIR *d = opendir("/proc/self/task");
        struct dirent *e;
        int n = 0;
        while (d && (e = readdir(d))) n += e->d_name[0] != '.';
        _exit(syscall(SYS_gettid) == getpid() && n == 1 ? 30 : 31);
    }
    *(pid_t *)arg = p;
    return 0;
}

/* Waits (with SIGCHLD delivered meanwhile) until the handler ran n times. */
static void await_chld(int n) {
    for (int i = 0; i < 5000 && chld_count < n; i++) sleep_ms(1);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1) {
        /* Programs the parent runs: "exit N" and "sleep-exit N". */
        if (!strcmp(argv[1], "exit")) return atoi(argv[2]);
        if (!strcmp(argv[1], "sleep-exit")) {
            sleep_ms(500);
            return atoi(argv[2]);
        }
        return 99;
    }
    CHECK("own-process-group", setpgid(0, 0) == 0 && getpgrp() == getpid());
    struct sigaction sa = {0};
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, 0);

    /* fork: the child sees a new PID and this process as its parent. */
    int fds[2];
    pipe(fds);
    pid_t parent = getpid();
    pid_t p = fork();
    if (p == 0) {
        close(fds[0]);
        char ok = getpid() != parent && getppid() == parent && getpgrp() == parent;
        write(fds[1], &ok, 1);
        _exit(7);
    }
    close(fds[1]);
    char ok = 0;
    CHECK("fork-child-identity", read(fds[0], &ok, 1) == 1 && ok);
    CHECK("pipe-eof-after-exit", read(fds[0], &ok, 1) == 0);
    close(fds[0]);
    int st;
    CHECK("waitpid-exit", waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 7);
    await_chld(1);
    CHECK("sigchld-exited", chld_count == 1 && chld_code == CLD_EXITED && chld_pid == p &&
                                chld_status == 7);
    CHECK_ERR("no-children", waitpid(-1, &st, WNOHANG), ECHILD);

    /* A running child: WNOHANG finds nothing; then SIGTERM kills it. */
    p = fork();
    if (p == 0) {
        for (;;) pause();
    }
    CHECK("wnohang-running", waitpid(p, &st, WNOHANG) == 0);
    kill(p, SIGTERM);
    CHECK("waitpid-killed", waitpid(p, &st, 0) == p && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    await_chld(2);
    CHECK("sigchld-killed", chld_code == CLD_KILLED && chld_status == SIGTERM);

    /* A fault: no core file (RLIMIT_CORE 0), so no core-dump flag. */
    p = fork();
    if (p == 0) {
        struct rlimit none = {0, 0};
        setrlimit(RLIMIT_CORE, &none);
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK("waitpid-segv", waitpid(p, &st, 0) == p && WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV &&
                              !WCOREDUMP(st));

    /* Stop and continue, reported once each; SIGCHLD reports them too. */
    chld_count = 0;
    p = fork();
    if (p == 0) {
        raise(SIGSTOP);
        _exit(3);
    }
    CHECK("waitpid-stopped", waitpid(p, &st, WUNTRACED) == p && WIFSTOPPED(st) &&
                                 WSTOPSIG(st) == SIGSTOP);
    await_chld(1);
    CHECK("sigchld-stopped", chld_code == CLD_STOPPED && chld_status == SIGSTOP);
    CHECK("stop-reported-once", waitpid(p, &st, WUNTRACED | WNOHANG) == 0);
    kill(p, SIGCONT);
    CHECK("waitpid-continued", waitpid(p, &st, WCONTINUED) == p && WIFCONTINUED(st));
    CHECK("waitpid-after-continue", waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 3);

    /* waitid with WNOWAIT leaves the child to reap. */
    p = fork();
    if (p == 0) _exit(5);
    siginfo_t si = {0};
    CHECK("waitid-nowait", waitid(P_PID, p, &si, WEXITED | WNOWAIT) == 0 &&
                               si.si_signo == SIGCHLD && si.si_code == CLD_EXITED &&
                               si.si_pid == p && si.si_status == 5);
    CHECK("waitid-reap", waitid(P_PID, p, &si, WEXITED) == 0 && si.si_pid == p);
    CHECK_ERR("waitid-gone", waitid(P_PID, p, &si, WEXITED | WNOHANG), ECHILD);
    CHECK_ERR("waitid-no-events", waitid(P_ALL, 0, &si, WNOHANG), EINVAL);

    /* vfork: the parent runs again when the child calls execve. */
    char *args[] = {argv[0], "sleep-exit", "11", 0};
    p = vfork();
    if (p == 0) {
        execve("/proc/self/exe", args, environ);
        _exit(127);
    }
    CHECK("vfork-returns-at-exec", waitpid(p, &st, WNOHANG) == 0);
    CHECK("vfork-child-exit", waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 11);

    /* posix_spawn: musl's CLONE_VM | CLONE_VFORK child. */
    char *sargs[] = {argv[0], "exit", "12", 0};
    CHECK("posix-spawn", posix_spawn(&p, "/proc/self/exe", 0, 0, sargs, environ) == 0 &&
                             waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 12);
    char *bad[] = {"/nonexistent", 0};
    CHECK("posix-spawn-enoent", posix_spawn(&p, "/nonexistent", 0, 0, bad, environ) == ENOENT);

    /* An exit signal other than SIGCHLD: only __WCLONE/__WALL wait. */
    signal(SIGUSR2, SIG_IGN);
    p = syscall(SYS_clone, SIGUSR2, 0, 0, 0, 0);
    if (p == 0) _exit(9);
    CHECK_ERR("clone-child-plain-wait", waitpid(p, &st, 0), ECHILD);
    CHECK("clone-child-wclone", waitpid(p, &st, __WCLONE) == p && WEXITSTATUS(st) == 9);

    /* kill(0) reaches every process of the group, this one included. */
    signal(SIGUSR1, on_usr1);
    pipe(fds);
    p = fork();
    if (p == 0) {
        close(fds[0]);
        usr1_count = 0;
        write(fds[1], "r", 1);
        while (!usr1_count) pause();
        _exit(20);
    }
    close(fds[1]);
    read(fds[0], &ok, 1);
    close(fds[0]);
    kill(0, SIGUSR1);
    for (int i = 0; i < 5000 && !usr1_count; i++) sleep_ms(1);
    CHECK("kill-group", usr1_count == 1 && waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 20);

    /* SA_NOCLDSTOP: stops do not raise SIGCHLD. */
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, 0);
    chld_count = 0;
    p = fork();
    if (p == 0) {
        raise(SIGSTOP);
        _exit(0);
    }
    waitpid(p, &st, WUNTRACED);
    sleep_ms(50);
    CHECK("nocldstop", chld_count == 0);
    kill(p, SIGCONT);
    waitpid(p, &st, 0);

    /* fork in a second thread. Once that thread has exited, its child is
     * the main thread's own (__WNOTHREAD); the thread's TID word is cleared
     * before its children pass on, so ECHILD may come first. */
    pthread_t thr;
    pid_t tp = 0;
    pthread_create(&thr, 0, fork_in_thread, &tp);
    pthread_join(thr, 0);
    int r = -1;
    for (int i = 0; i < 5000 && r != tp; i++) {
        r = waitpid(tp, &st, __WNOTHREAD);
        if (r < 0 && errno == ECHILD) sleep_ms(1);
    }
    CHECK("fork-in-thread", tp > 0 && r == tp && WIFEXITED(st) && WEXITSTATUS(st) == 30);

    /* A signal sent to a child the moment it exists reaches it: each of
     * 100 children is killed right after fork. */
    int died = 0;
    for (int i = 0; i < 100; i++) {
        p = fork();
        if (p == 0) {
            for (;;) pause();
        }
        kill(p, SIGTERM);
        int w = 0;
        for (int t = 0; t < 5000 && (w = waitpid(p, &st, WNOHANG)) == 0; t++) sleep_ms(1);
        if (w == 0) {
            kill(p, SIGKILL);
            waitpid(p, &st, 0);
        } else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM) {
            died++;
        }
    }
    CHECK("kill-at-fork", died == 100);

    /* SIGCHLD ignored: children are reaped as they exit. */
    signal(SIGCHLD, SIG_IGN);
    p = fork();
    if (p == 0) _exit(0);
    CHECK_ERR("autoreap", waitpid(p, &st, 0), ECHILD);

    struct rusage ru;
    CHECK("children-rusage", getrusage(RUSAGE_CHILDREN, &ru) == 0);
    FINISH();
}
