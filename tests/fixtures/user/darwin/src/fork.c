// fork, wait4, and SIGCHLD: what a child inherits (descriptors with their
// offsets, shared and private memory, VM_INHERIT_NONE regions, the signal
// mask and actions) and what it does not (other threads, kqueues, pending
// signals, interval timers, the alternate signal stack); its port names;
// exit, signal, stop, and continue statuses; SIGCHLD's siginfo; WNOHANG;
// and children reaped at once when SIGCHLD is ignored.
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t chld_code, chld_status, chld_pid, usr1_seen;
static void on_chld(int s, siginfo_t *si, void *u) {
    (void)s;
    (void)u;
    chld_code = si->si_code;
    chld_status = si->si_status;
    chld_pid = si->si_pid;
}
static void on_usr1(int s) {
    (void)s;
    usr1_seen = 1;
}
static int atfork_child_ran;
static void atfork_child(void) { atfork_child_ran = 1; }

static void *sleeper(void *arg) {
    (void)arg;
    for (;;) {
        pause();
    }
    return NULL;
}

static int wait_for(pid_t pid, int options) {
    int st = -1;
    pid_t w;
    do {
        w = waitpid(pid, &st, options);
    } while (w == -1 && errno == EINTR);
    return w == pid ? st : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGUSR1, on_usr1);
    pthread_atfork(NULL, NULL, atfork_child);

    // State the child should or should not see.
    int kq = kqueue();
    int pipefd[2];
    pipe(pipefd);
    char tmpl[] = "/tmp/rax-fork-XXXXXX";
    int fd = mkstemp(tmpl);
    unlink(tmpl);
    write(fd, "0123456789", 10);
    lseek(fd, 2, SEEK_SET);
    volatile int *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    volatile int *private = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    char *none = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    minherit(none, 4096, VM_INHERIT_NONE);
    *shared = 1;
    *private = 1;
    pthread_t th;
    pthread_create(&th, NULL, sleeper, NULL);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block, NULL);
    raise(SIGUSR1); // pending, blocked
    struct itimerval it = {{10, 0}, {10, 0}};
    setitimer(ITIMER_REAL, &it, NULL);
    char altstack[16384];
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    printf("parent: task=%#x thread=%#x\n", mach_task_self(), mach_thread_self());

    pid_t c = fork();
    if (c == 0) {
        mach_msg_type_number_t n = 0;
        thread_act_array_t list;
        task_threads(mach_task_self(), &list, &n);
        sigset_t mask, pend;
        sigprocmask(SIG_BLOCK, NULL, &mask);
        sigpending(&pend);
        struct itimerval cur;
        getitimer(ITIMER_REAL, &cur);
        stack_t cs;
        sigaltstack(NULL, &cs);
        struct kevent ev;
        int kr = kevent(kq, NULL, 0, &ev, 1, &(struct timespec){0, 0});
        int kerr = errno;
        char buf[4] = {0};
        read(fd, buf, 3);
        printf("child: ppid=%d task=%#x thread=%#x atfork=%d\n", getppid() == getpid() ? -1 : 1,
               mach_task_self(), mach_thread_self(), atfork_child_ran);
#if defined(__arm64__)
        // Only the caller's thread (Rosetta adds a thread of its own to an
        // x86_64 child).
        printf("child: threads=%u\n", n);
#else
        (void)n;
#endif
        printf("child: usr1 blocked=%d pending=%d timer=%ld altstack disabled=%d\n",
               sigismember(&mask, SIGUSR1), sigismember(&pend, SIGUSR1), (long)cur.it_value.tv_sec,
               (cs.ss_flags & SS_DISABLE) != 0);
        printf("child: kevent=%d errno=%d read=%s\n", kr, kerr, buf);
        *shared = 2;
        *private = 2;
        write(pipefd[1], "k", 1);
        _exit(7);
    }
    char b;
    read(pipefd[0], &b, 1);
    int st = wait_for(c, 0);
    printf("parent: exited=%d code=%d offset=%lld shared=%d private=%d\n", WIFEXITED(st),
           WEXITSTATUS(st), (long long)lseek(fd, 0, SEEK_CUR), *shared, *private);
    for (int i = 0; i < 200 && chld_pid != c; i++) {
        usleep(1000);
    }
    printf("sigchld: code=%d status=%d pid_ok=%d\n", chld_code, chld_status, chld_pid == c);
    printf("no more children: %d errno=%d\n", waitpid(-1, &st, WNOHANG), errno);

    // The VM_INHERIT_NONE region is gone in the child: the region found at
    // its address starts above it.
    c = fork();
    if (c == 0) {
        vm_address_t a = (vm_address_t)none;
        vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object;
        kern_return_t kr = vm_region_64(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &object);
        _exit(kr != KERN_SUCCESS ? 3 : a == (vm_address_t)none ? 1 : 2);
    }
    st = wait_for(c, 0);
    printf("inherit none: child reports %d\n", WEXITSTATUS(st));

    // Statuses: WNOHANG, a signal death, a stop, a continue.
    c = fork();
    if (c == 0) {
        for (;;) {
            pause();
        }
    }
    printf("wnohang: %d\n", waitpid(c, &st, WNOHANG));
    kill(c, SIGSTOP);
    st = wait_for(c, WUNTRACED);
    printf("stopped: %d sig=%d raw=%#x\n", WIFSTOPPED(st), WSTOPSIG(st), st);
    kill(c, SIGCONT);
    st = wait_for(c, WCONTINUED);
    printf("continued: %d raw=%#x\n", WIFCONTINUED(st), st);
    kill(c, SIGTERM);
    st = wait_for(c, 0);
    printf("terminated: %d sig=%d\n", WIFSIGNALED(st), WTERMSIG(st));
    struct rusage ru;
    c = fork();
    if (c == 0) {
        _exit(0);
    }
    pid_t w;
    do {
        w = wait4(c, &st, 0, &ru);
    } while (w == -1 && errno == EINTR);
    printf("wait4 rusage: pid_ok=%d sane=%d\n", w == c, ru.ru_utime.tv_sec >= 0 && ru.ru_maxrss >= 0);

    // SIGCHLD ignored: no zombie is left to wait for.
    signal(SIGCHLD, SIG_IGN);
    c = fork();
    if (c == 0) {
        _exit(0);
    }
    usleep(200000);
    errno = 0;
    printf("ignored: %d errno=%d\n", waitpid(c, &st, WNOHANG), errno);
    printf("invalid pid: %d errno=%d\n", wait4(-2147483647 - 1, &st, 0, NULL), errno);
    return 0;
}
