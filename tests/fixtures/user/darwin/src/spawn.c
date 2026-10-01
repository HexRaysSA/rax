// posix_spawn and waitid: a child that is a fork and an exec in one (its
// descriptors after file actions, working directory, signal mask and
// defaults, process group and session, special and exception ports),
// errors that create no child at all (and no SIGCHLD), binary
// preferences, POSIX_SPAWN_SETEXEC, POSIX_SPAWN_START_SUSPENDED, and
// waitid's view of exits, stops, continues, and signal deaths.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// csrctl(CSR_SYSCALL_CHECK, CSR_ALLOW_KERNEL_DEBUGGER).
#define SYS_csrctl 483
#define CSR_ALLOW_KERNEL_DEBUGGER (1u << 3)

// Whether this host lets a task set its own kernel port in a child: the
// task's control port must be movable (the MAC policy hands it out) and
// SIP must allow the kernel debugger (task_set_special_port, "for
// Mach-on-Mach emulation"). The child then runs with its parent's task as
// its own and crashes, so the case is spawned only where it is refused.
static int kernel_port_settable(void) {
    mach_port_t p = MACH_PORT_NULL;
    int movable = task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &p) == KERN_SUCCESS;
    if (movable) mach_port_deallocate(mach_task_self(), p);
    uint32_t mask = CSR_ALLOW_KERNEL_DEBUGGER;
    return movable && syscall(SYS_csrctl, 0, &mask, sizeof mask) == 0;
}

static char self[PATH_MAX];
static char dir[PATH_MAX];
static volatile sig_atomic_t chld;

static void on_chld(int s) {
    (void)s;
    chld++;
}

// The child's report: which of descriptors 0-31 are open, and how.
static void report(const char *tag) {
    printf("%s: fds", tag);
    for (int fd = 0; fd < 32; fd++) {
        int f = fcntl(fd, F_GETFD);
        if (f >= 0) {
            printf(" %d%s", fd, (f & FD_CLOEXEC) ? "c" : "");
        }
    }
    printf("\n");
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof cwd);
    const char *want = getenv("SPAWN_CWD");
    char real[PATH_MAX] = "";
    if (want) {
        realpath(want, real);
    }
    sigset_t mask;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    struct sigaction sa;
    sigaction(SIGUSR2, NULL, &sa);
    const char *ppid = getenv("SPAWN_PPID");
    printf("%s: ppid ok=%d cwd ok=%d usr1 blocked=%d usr2 %s pgrp leader=%d session leader=%d\n", tag,
           ppid && getppid() == atoi(ppid), want ? strcmp(cwd, real) == 0 : -1,
           sigismember(&mask, SIGUSR1), sa.sa_handler == SIG_IGN ? "ign" : "dfl",
           getpgrp() == getpid(), getsid(0) == getpid());
    mach_port_t bootstrap = MACH_PORT_NULL;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap);
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    exception_handler_t handlers[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    task_get_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS, masks, &count, handlers, behaviors,
                             flavors);
    // The bootstrap port is inherited: valid in the child as in the parent.
    const char *parent_bootstrap = getenv("SPAWN_BOOTSTRAP");
    printf("%s: task=%#x thread=%#x bootstrap inherited=%d bad access handler=%d behavior=%#x\n", tag,
           mach_task_self(), mach_thread_self(),
           parent_bootstrap && MACH_PORT_VALID(bootstrap) == atoi(parent_bootstrap),
           count > 0 && MACH_PORT_VALID(handlers[0]), count > 0 ? behaviors[0] : 0);
    const char *out = getenv("SPAWN_WRITE_FD");
    if (out) {
        write(atoi(out), "hi", 2);
    }
}

// Whether this process has a bootstrap port, as an environment string.
static char *bootstrap_env(void) {
    static char env[32];
    mach_port_t bootstrap = MACH_PORT_NULL;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap);
    snprintf(env, sizeof env, "SPAWN_BOOTSTRAP=%d", MACH_PORT_VALID(bootstrap));
    return env;
}

static int spawn(const char *tag, const char *path, posix_spawn_file_actions_t *fa, posix_spawnattr_t *attr,
                 pid_t *pid) {
    char cwd[PATH_MAX + 16], ppid[32];
    snprintf(cwd, sizeof cwd, "SPAWN_CWD=%s", dir);
    snprintf(ppid, sizeof ppid, "SPAWN_PPID=%d", getpid());
    char out[32] = "SPAWN_NONE=";
    if (getenv("SPAWN_WRITE_FD")) {
        snprintf(out, sizeof out, "SPAWN_WRITE_FD=%s", getenv("SPAWN_WRITE_FD"));
    }
    char *argv[] = {"spawned", "child", (char *)tag, NULL};
    char *envp[] = {cwd, ppid, out, bootstrap_env(), NULL};
    return posix_spawn(pid, path, fa, attr, argv, envp);
}

static void spawn_wait(const char *tag, const char *path, posix_spawn_file_actions_t *fa,
                       posix_spawnattr_t *attr) {
    pid_t pid = -12345;
    int r = spawn(tag, path, fa, attr, &pid);
    if (r != 0) {
        printf("%s: error=%d pid untouched=%d\n", tag, r, pid == -12345);
        return;
    }
    int st;
    waitpid(pid, &st, 0);
    printf("%s: exit=%d\n", tag, WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
}

static void file_actions(void) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/out", dir);
    int keep = open("/dev/null", O_RDONLY);
    dup2(keep, 10);
    int ce = open("/dev/null", O_RDONLY | O_CLOEXEC);
    dup2(ce, 11);
    fcntl(11, F_SETFD, FD_CLOEXEC);
    int kq = kqueue();
    dup2(kq, 12);
    close(keep);
    close(ce);
    close(kq);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 20, p, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    posix_spawn_file_actions_adddup2(&fa, 11, 21);
    posix_spawn_file_actions_addclose(&fa, 10);
    posix_spawn_file_actions_addopen(&fa, 22, "/dev/null", O_RDONLY | O_CLOEXEC, 0);
    posix_spawn_file_actions_adddup2(&fa, 20, 23);
    setenv("SPAWN_WRITE_FD", "23", 1);
    spawn_wait("actions", self, &fa, NULL);
    unsetenv("SPAWN_WRITE_FD");
    posix_spawn_file_actions_destroy(&fa);
    struct stat st;
    stat(p, &st);
    printf("actions: out size=%lld mode=%o\n", (long long)st.st_size, st.st_mode & 0777);

    // Default close-on-exec: only what is inherited explicitly.
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addinherit_np(&fa, 1);
    posix_spawn_file_actions_addinherit_np(&fa, 11);
    posix_spawn_file_actions_adddup2(&fa, 1, 25);
    posix_spawn_file_actions_addopen(&fa, 26, "/dev/null", O_RDONLY, 0);
    spawn_wait("cloexec default", self, &fa, &attr);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    close(10);
    close(11);
    close(12);
}

static void failures(void) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addclose(&fa, 55);
    spawn_wait("close unopened", self, &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 5, "/nonexistent/file", O_RDONLY, 0);
    spawn_wait("open missing", self, &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, 1, 300);
    spawn_wait("dup2 past limit", self, &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addchdir_np(&fa, "/nonexistent");
    spawn_wait("chdir missing", self, &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    // fchdir to what is not a directory: a file, or no vnode at all.
    int file = open("/etc/hosts", O_RDONLY);
    int pfd[2];
    pipe(pfd);
    int kq = kqueue();
    int targets[] = {file, pfd[0], kq};
    const char *names[] = {"fchdir file", "fchdir pipe", "fchdir kqueue"};
    for (int i = 0; i < 3; i++) {
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addfchdir_np(&fa, targets[i]);
        spawn_wait(names[i], self, &fa, NULL);
        posix_spawn_file_actions_destroy(&fa);
    }
    errno = 0;
    printf("fchdir kqueue call: %d errno=%d\n", fchdir(kq), errno);
    close(file);
    close(pfd[0]);
    close(pfd[1]);
    close(kq);
    spawn_wait("missing", "/nonexistent/program", NULL, NULL);
    spawn_wait("directory", "/tmp", NULL, NULL);
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/garbage", dir);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(fd, "garbage\n", 8);
    close(fd);
    spawn_wait("garbage", p, NULL, NULL);
    unlink(p);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    cpu_type_t none[] = {CPU_TYPE_POWERPC};
    posix_spawnattr_setbinpref_np(&attr, 1, none, NULL);
    spawn_wait("binpref ppc", self, NULL, &attr);
    cpu_type_t four[] = {CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64, CPU_TYPE_SPARC, CPU_TYPE_I860};
    posix_spawnattr_setbinpref_np(&attr, 4, four, NULL);
    spawn_wait("binpref four", self, NULL, &attr);
    cpu_type_t any[] = {CPU_TYPE_POWERPC, CPU_TYPE_ANY};
    posix_spawnattr_setbinpref_np(&attr, 2, any, NULL);
    spawn_wait("binpref any", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);

    // A new group leader cannot start a session.
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSID);
    posix_spawnattr_setpgroup(&attr, 0);
    spawn_wait("pgroup and session", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);

    posix_spawnattr_init(&attr);
    posix_spawnattr_setspecialport_np(&attr, mach_task_self(), TASK_KERNEL_PORT);
    if (kernel_port_settable())
        printf("kernel port: settable here, not spawned\n");
    else
        spawn_wait("kernel port", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);
    posix_spawnattr_init(&attr);
    posix_spawnattr_setspecialport_np(&attr, 0x12345678, TASK_BOOTSTRAP_PORT);
    spawn_wait("bad port name", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);

    // The kernel reaps a failed spawn's child on its own time.
    usleep(300000);
    int st;
    errno = 0;
    printf("failures: no child=%d errno=%d sigchld=%d\n", waitpid(-1, &st, WNOHANG), errno, (int)chld);
}

static void attributes(void) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    posix_spawnattr_setsigmask(&attr, &set);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    posix_spawnattr_setsigdefault(&attr, &set);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSID);
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    posix_spawnattr_setexceptionports_np(&attr, EXC_MASK_BAD_ACCESS, port, EXCEPTION_DEFAULT, 0);
    spawn_wait("attributes", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);

    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attr, 0);
    spawn_wait("own group", self, NULL, &attr);
    posix_spawnattr_destroy(&attr);

    // Relative to the working directory the actions chose.
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addchdir_np(&fa, dir);
    char link[PATH_MAX];
    snprintf(link, sizeof link, "%s/prog", dir);
    symlink(self, link);
    spawn_wait("chdir", "./prog", &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addfchdir_np(&fa, dfd);
    spawn_wait("fchdir", "./prog", &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    close(dfd);
    unlink(link);
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof cwd);
    printf("chdir: caller moved=%d\n", strstr(cwd, "rax-spawn-") != NULL);
}

static void suspended(void) {
    int pfd[2];
    pipe(pfd);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pfd[1], 1);
    posix_spawn_file_actions_addclose(&fa, pfd[0]);
    pid_t pid;
    int r = spawn("suspended", self, &fa, &attr, &pid);
    close(pfd[1]);
    fcntl(pfd[0], F_SETFL, O_NONBLOCK);
    usleep(300000);
    char buf[16];
    errno = 0;
    ssize_t n = read(pfd[0], buf, 1);
    printf("suspended: spawn=%d read before=%zd errno=%d\n", r, n, errno);
    kill(pid, SIGCONT);
    fcntl(pfd[0], F_SETFL, 0);
    n = read(pfd[0], buf, 1);
    printf("suspended: read after=%zd\n", n);
    int st;
    waitpid(pid, &st, 0);
    printf("suspended: exit=%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    close(pfd[0]);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
}

static void print_si(const char *what, int r, const siginfo_t *si) {
    printf("%s: %d errno=%d signo=%d code=%d status=%d uid=%d\n", what, r, r ? errno : 0, si->si_signo,
           si->si_code, si->si_status, (int)si->si_uid);
}

static void waitid_views(void) {
    siginfo_t si;
    errno = 0;
    printf("waitid options 0: %d errno=%d\n", waitid(P_ALL, 0, &si, 0), errno);
    errno = 0;
    printf("waitid bad options: %d errno=%d\n", waitid(P_ALL, 0, &si, WEXITED | 0x100), errno);
    errno = 0;
    printf("waitid negative pid: %d errno=%d\n", waitid(P_PID, (id_t)-5, &si, WEXITED), errno);
    errno = 0;
    printf("waitid no children: %d errno=%d\n", waitid(P_ALL, 0, &si, WEXITED | WNOHANG), errno);

    pid_t c = fork();
    if (c == 0) {
        for (;;) {
            pause();
        }
    }
    memset(&si, 0x5a, sizeof si);
    int r = waitid(P_PID, c, &si, WEXITED | WNOHANG);
    printf("waitid nothing yet: %d si_signo untouched=%d\n", r, si.si_signo == 0x5a5a5a5a);
    kill(c, SIGSTOP);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, c, &si, WSTOPPED);
    print_si("waitid stopped", r, &si);
    kill(c, SIGCONT);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, c, &si, WCONTINUED);
    print_si("waitid continued", r, &si);
    printf("waitid continued pid ok=%d\n", si.si_pid == c);
    kill(c, SIGTERM);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, c, &si, WEXITED | WNOWAIT);
    print_si("waitid killed (nowait)", r, &si);
    memset(&si, 0, sizeof si);
    r = waitid(P_ALL, 0, &si, WEXITED);
    print_si("waitid killed", r, &si);
    printf("waitid pid ok=%d\n", si.si_pid == c);

    c = fork();
    if (c == 0) {
        _exit(42);
    }
    memset(&si, 0, sizeof si);
    r = waitid(P_PGID, getpgrp(), &si, WEXITED);
    print_si("waitid exited", r, &si);
    errno = 0;
    printf("waitid reaped: %d errno=%d\n", waitpid(c, NULL, WNOHANG), errno);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t size = sizeof self;
    _NSGetExecutablePath(self, &size);
    if (argc > 2 && strcmp(argv[1], "child") == 0) {
        report(argv[2]);
        return 3;
    }
    // The descriptor limit file actions are checked against.
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = 256;
    setrlimit(RLIMIT_NOFILE, &rl);
    snprintf(dir, sizeof dir, "/tmp/rax-spawn-XXXXXX");
    mkdtemp(dir);
    struct sigaction sa = {0};
    sa.sa_handler = on_chld;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGUSR2, SIG_IGN);

    if (argc > 1 && strcmp(argv[1], "bridge-smoke") == 0) {
        spawn_wait("bridge-smoke", self, NULL, NULL);
        rmdir(dir);
        return 0;
    }

    spawn_wait("plain", self, NULL, NULL);
    file_actions();
    failures();
    attributes();
    signal(SIGCHLD, SIG_DFL);
    suspended();
    waitid_views();

    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/out", dir);
    unlink(p);
    rmdir(dir);

    // SETEXEC: an error returns, success becomes the child.
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
    pid_t pid = -1;
    char *argv_missing[] = {"x", NULL};
    int r = posix_spawn(&pid, "/nonexistent/program", NULL, &attr, argv_missing, environ);
    printf("setexec missing: %d pid=%d\n", r, pid);
    char ppid[32];
    snprintf(ppid, sizeof ppid, "SPAWN_PPID=%d", getppid());
    char *argv_self[] = {self, "child", "setexec", NULL};
    char *envp[] = {ppid, bootstrap_env(), NULL};
    r = posix_spawn(&pid, self, NULL, &attr, argv_self, envp);
    printf("setexec returned: %d\n", r);
    return 1;
}
