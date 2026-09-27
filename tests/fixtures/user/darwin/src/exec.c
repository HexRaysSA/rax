// execve: what the kernel refuses before the point of no return (each
// errno), what kills the caller after it, `#!` scripts, the argument
// vectors, and what a new image keeps of the process: pid and parent,
// descriptors (close-on-exec ones and kqueues closed, offsets kept), the
// signal mask and pending signals, ignored signals (caught ones back to
// their defaults), interval timers, the file-creation mask, the working
// directory, resource limits, one thread, no alternate signal stack.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static char self[PATH_MAX];
static char dir[PATH_MAX];

static void on_sig(int s) { (void)s; }

// The files execve refuses, in the order tried.
static const char *refused[] = {"noexec",  "empty",   "garbage",     "nointerp",     "blankinterp",
                                "longline", "unterminated", "badinterp", "nested",
                                "interp_noexec", "dylib", "ppc64",     "cigam",        "i386",
                                "fat_overlap", "fat_ppc", "fat_past_end"};
// Everything else the fixture writes into its directory.
static const char *others[] = {"okscript", "truncated", "data", "script", "script2"};

static void put(const char *name, const void *data, size_t len, mode_t mode) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    write(fd, data, len);
    close(fd);
    chmod(p, mode);
}

static void try_exec(const char *what, const char *path, char *const argv[], char *const envp[]) {
    errno = 0;
    int r = execve(path, argv, envp);
    printf("%s: %d errno=%d\n", what, r, errno);
}

static void try_file(const char *name) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    char *argv[] = {p, NULL};
    try_exec(name, p, argv, environ);
}

// A Mach-O header of this process's CPU type.
static struct mach_header_64 own_header(uint32_t filetype) {
    const struct mach_header *h = _dyld_get_image_header(0);
    struct mach_header_64 mh = {0};
    mh.magic = MH_MAGIC_64;
    mh.cputype = h->cputype;
    mh.cpusubtype = h->cpusubtype;
    mh.filetype = filetype;
    return mh;
}

static void refusals(void) {
    char *argv[] = {"x", NULL};
    try_exec("enoent", "/nonexistent/program", argv, environ);
    try_exec("enotdir", "/etc/hosts/x", argv, environ);
    try_exec("directory", "/tmp", argv, environ);
    try_exec("empty path", "", argv, environ);
    char longpath[1100];
    memset(longpath, 'a', sizeof longpath - 1);
    longpath[0] = '/';
    longpath[sizeof longpath - 1] = 0;
    try_exec("long path", longpath, argv, environ);
    try_exec("bad path", (const char *)8, argv, environ);
    try_exec("bad argv", self, (char *const *)8, environ);
    char *bad_env[] = {"A=1", (char *)8, NULL};
    try_exec("bad envp string", self, argv, bad_env);
    // An argument larger than ARG_MAX.
    size_t big = 1 << 20;
    char *huge = malloc(big + 1);
    memset(huge, 'x', big);
    huge[big] = 0;
    char *big_argv[] = {"x", huge, NULL};
    try_exec("e2big", self, big_argv, environ);
    free(huge);

    put("noexec", "#!/bin/sh\n", 10, 0644);
    put("empty", "", 0, 0755);
    put("garbage", "hello\n", 6, 0755);
    put("nointerp", "#!\n", 3, 0755);
    put("blankinterp", "#!   # comment\n", 15, 0755);
    char longline[700] = "#!/bin/sh ";
    memset(longline + 10, 'x', sizeof longline - 10);
    put("longline", longline, sizeof longline, 0755);
    put("unterminated", "#!/bin/sh", 9, 0755);
    put("badinterp", "#!/nonexistent/interp\n", 22, 0755);
    put("okscript", "#!/bin/sh\n", 10, 0755);
    char nested[PATH_MAX + 8];
    int n = snprintf(nested, sizeof nested, "#!%s/okscript\n", dir);
    put("nested", nested, n, 0755);
    n = snprintf(nested, sizeof nested, "#!%s/noexec\n", dir);
    put("interp_noexec", nested, n, 0755);

    struct mach_header_64 mh = own_header(MH_DYLIB);
    put("dylib", &mh, sizeof mh, 0755);
    mh = own_header(MH_EXECUTE);
    mh.cputype = CPU_TYPE_POWERPC64;
    put("ppc64", &mh, sizeof mh, 0755);
    mh = own_header(MH_EXECUTE);
    mh.magic = MH_CIGAM_64;
    put("cigam", &mh, sizeof mh, 0755);
    mh = own_header(MH_EXECUTE);
    mh.cputype = CPU_TYPE_I386;
    mh.magic = MH_MAGIC;
    put("i386", &mh, sizeof mh, 0755);

    // Fat files: a slice over the header, a table of only PowerPC.
    unsigned char fat[0x5000] = {0};
    struct fat_header *fh = (struct fat_header *)fat;
    struct fat_arch *fa = (struct fat_arch *)(fat + sizeof *fh);
    fh->magic = OSSwapHostToBigInt32(FAT_MAGIC);
    fh->nfat_arch = OSSwapHostToBigInt32(1);
    fa->cputype = OSSwapHostToBigInt32(CPU_TYPE_POWERPC);
    fa->offset = OSSwapHostToBigInt32(8);
    fa->size = OSSwapHostToBigInt32(0x100);
    put("fat_overlap", fat, sizeof fat, 0755);
    fa->offset = OSSwapHostToBigInt32(0x4000);
    put("fat_ppc", fat, sizeof fat, 0755);
    fa->size = OSSwapHostToBigInt32(0x10000);
    put("fat_past_end", fat, sizeof fat, 0755);

    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        try_file(refused[i]);
    }
}

// Past the point of no return: a header the kernel accepts over load
// commands it does not.
static void killed_after_commit(void) {
    struct mach_header_64 mh = own_header(MH_EXECUTE);
    mh.ncmds = 1;
    mh.sizeofcmds = 0x1000;
    put("truncated", &mh, sizeof mh, 0755);
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/truncated", dir);
    pid_t c = fork();
    if (c == 0) {
        char *argv[] = {p, NULL};
        execve(p, argv, environ);
        printf("truncated: returned errno=%d\n", errno);
        _exit(1);
    }
    int st;
    waitpid(c, &st, 0);
    printf("truncated: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static void *sleeper(void *arg) {
    (void)arg;
    for (;;) {
        pause();
    }
    return NULL;
}

static void run_and_wait(const char *what, void (*child)(void)) {
    pid_t c = fork();
    if (c == 0) {
        child();
        _exit(99);
    }
    int st;
    waitpid(c, &st, 0);
    printf("%s: exit=%d\n", what, WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
}

static void exec_with_state(void) {
    // Descriptors: one kept (with its offset), one close-on-exec, a kqueue.
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/data", dir);
    int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0600);
    write(fd, "0123456789", 10);
    lseek(fd, 3, SEEK_SET);
    dup2(fd, 20);
    int ce = open(p, O_RDONLY | O_CLOEXEC);
    dup2(ce, 21);
    fcntl(21, F_SETFD, FD_CLOEXEC);
    // A kqueue is close-on-exec; its duplicate is not, but no kqueue
    // survives an exec.
    int kq = kqueue();
    printf("before: kqueue cloexec=%d\n", fcntl(kq, F_GETFD) & FD_CLOEXEC);
    dup2(kq, 22);

    // Signals.
    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_flags = 0;
    sigaction(SIGURG, &sa, NULL);
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGUSR2, SIG_IGN);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGURG);
    sigprocmask(SIG_BLOCK, &block, NULL);
    raise(SIGHUP);
    raise(SIGURG);
    char altstack[16384];
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    struct itimerval it = {{0, 0}, {100, 0}};
    setitimer(ITIMER_REAL, &it, NULL);

    // Process state.
    umask(027);
    chdir(dir);
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = 200;
    setrlimit(RLIMIT_NOFILE, &rl);
    pthread_t th;
    pthread_create(&th, NULL, sleeper, NULL);

    char pid[32], ppid[32], cwd[PATH_MAX + 8];
    snprintf(pid, sizeof pid, "EXEC_PID=%d", getpid());
    snprintf(ppid, sizeof ppid, "EXEC_PPID=%d", getppid());
    snprintf(cwd, sizeof cwd, "EXEC_CWD=%s", dir);
    char *argv[] = {self, "after", "", "two words", NULL};
    char *envp[] = {pid, ppid, cwd, "EMPTY=", NULL};
    execve(self, argv, envp);
    printf("exec failed: %d\n", errno);
}

static int after(int argc, char **argv) {
    printf("after: argc=%d", argc);
    for (int i = 2; i < argc; i++) {
        printf(" [%s]", argv[i]);
    }
    printf(" self=%d\n", strcmp(argv[0], self) == 0);
    int envc = 0;
    for (char **e = environ; *e; e++) {
        envc++;
    }
    printf("after: envc=%d EMPTY=[%s]\n", envc, getenv("EMPTY"));
    printf("after: pid same=%d ppid same=%d\n", getpid() == atoi(getenv("EXEC_PID")),
           getppid() == atoi(getenv("EXEC_PPID")));
    char buf[4] = {0};
    int r = (int)read(20, buf, 3);
    printf("after: fd20 read=%d [%s] fd21=%d fd22=%d errno=%d\n", r, buf, fcntl(21, F_GETFD),
           fcntl(22, F_GETFD), errno);
    struct sigaction sa;
    sigaction(SIGUSR1, NULL, &sa);
    printf("after: usr1 dfl=%d flags=%#x\n", sa.sa_handler == SIG_DFL, sa.sa_flags);
    sigaction(SIGUSR2, NULL, &sa);
    printf("after: usr2 ign=%d\n", sa.sa_handler == SIG_IGN);
    sigaction(SIGURG, NULL, &sa);
    printf("after: urg dfl=%d\n", sa.sa_handler == SIG_DFL);
    sigaction(SIGCHLD, NULL, &sa);
    printf("after: chld dfl=%d nocldstop=%d\n", sa.sa_handler == SIG_DFL,
           (sa.sa_flags & SA_NOCLDSTOP) != 0);
    sigset_t mask, pend;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    sigpending(&pend);
    printf("after: hup blocked=%d pending=%d urg blocked=%d pending=%d\n", sigismember(&mask, SIGHUP),
           sigismember(&pend, SIGHUP), sigismember(&mask, SIGURG), sigismember(&pend, SIGURG));
    stack_t ss;
    sigaltstack(NULL, &ss);
    printf("after: altstack disabled=%d\n", (ss.ss_flags & SS_DISABLE) != 0);
    struct itimerval it;
    getitimer(ITIMER_REAL, &it);
    printf("after: itimer running=%d\n", it.it_value.tv_sec > 50 && it.it_value.tv_sec <= 100);
    mode_t m = umask(0);
    printf("after: umask=%03o\n", m);
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof cwd);
    char real[PATH_MAX];
    realpath(getenv("EXEC_CWD"), real);
    printf("after: cwd same=%d\n", strcmp(cwd, real) == 0);
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    printf("after: nofile=%llu\n", (unsigned long long)rl.rlim_cur);
    mach_msg_type_number_t n = 0;
    thread_act_array_t list;
    task_threads(mach_task_self(), &list, &n);
#if defined(__arm64__)
    printf("after: threads=%u\n", n);
#endif
    printf("after: task=%#x thread=%#x\n", mach_task_self(), mach_thread_self());
    return 7;
}

static int script(int argc, char **argv) {
    printf("script: argc=%d", argc);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strstr(a, "/script")) {
            a = strrchr(a, '/') + 1;
        }
        printf(" [%s]", a);
    }
    char exe[PATH_MAX];
    uint32_t size = sizeof exe;
    _NSGetExecutablePath(exe, &size);
    printf(" argv0 self=%d exe self=%d\n", strcmp(argv[0], self) == 0, strcmp(exe, self) == 0);
    return 0;
}

static void exec_script(void) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/script", dir);
    char *argv[] = {"ignored", "x", NULL};
    execve(p, argv, environ);
    printf("script exec failed: %d\n", errno);
}

static void exec_script_relative(void) {
    chdir(dir);
    char *argv[] = {"ignored", NULL};
    execve("./script2", argv, environ);
    printf("script exec failed: %d\n", errno);
}

static void exec_script_null_argv(void) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/script2", dir);
    execve(p, NULL, environ);
    printf("script exec failed: %d\n", errno);
}

// Which image runs: its architecture and CPU subtype.
static int who(void) {
    const struct mach_header *h = _dyld_get_image_header(0);
#if defined(__x86_64__)
    printf("who: x86_64 subtype=%#x\n", h->cpusubtype);
#else
    printf("who: arm64 subtype=%#x\n", h->cpusubtype);
#endif
    return 0;
}

// An x86_64 image (the x86_64 build of this fixture) exec'd from arm64:
// thin, and in fat files with x86_64h slices, which translation does not
// run.
static int translate(const char *x86) {
    int fd = open(x86, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    size_t n = (size_t)st.st_size;
    unsigned char *img = malloc(n);
    read(fd, img, n);
    close(fd);
    snprintf(dir, sizeof dir, "/tmp/rax-exec-XXXXXX");
    mkdtemp(dir);
    put("thin", img, n, 0755);
    // The same image as x86_64h.
    unsigned char *h = malloc(n);
    memcpy(h, img, n);
    ((struct mach_header_64 *)h)->cpusubtype = CPU_SUBTYPE_X86_64_H;
    put("thin_h", h, n, 0755);
    // Fat files: {x86_64h, x86_64} and {x86_64h}.
    size_t page = 0x4000, off1 = page, off2 = (off1 + n + page - 1) & ~(page - 1);
    size_t total = off2 + n;
    unsigned char *fat = calloc(1, total);
    struct fat_header *fh = (struct fat_header *)fat;
    struct fat_arch *fa = (struct fat_arch *)(fat + sizeof *fh);
    fh->magic = OSSwapHostToBigInt32(FAT_MAGIC);
    fh->nfat_arch = OSSwapHostToBigInt32(2);
    fa[0].cputype = OSSwapHostToBigInt32(CPU_TYPE_X86_64);
    fa[0].cpusubtype = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_64_H);
    fa[0].offset = OSSwapHostToBigInt32((uint32_t)off1);
    fa[0].size = OSSwapHostToBigInt32((uint32_t)n);
    fa[0].align = OSSwapHostToBigInt32(14);
    fa[1].cputype = OSSwapHostToBigInt32(CPU_TYPE_X86_64);
    fa[1].cpusubtype = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_64_ALL);
    fa[1].offset = OSSwapHostToBigInt32((uint32_t)off2);
    fa[1].size = OSSwapHostToBigInt32((uint32_t)n);
    fa[1].align = OSSwapHostToBigInt32(14);
    memcpy(fat + off1, h, n);
    memcpy(fat + off2, img, n);
    put("fat", fat, total, 0755);
    fh->nfat_arch = OSSwapHostToBigInt32(1);
    put("fat_h", fat, off1 + n, 0755);

    const char *files[] = {"thin", "thin_h", "fat", "fat_h"};
    for (int i = 0; i < 4; i++) {
        char p[PATH_MAX];
        snprintf(p, sizeof p, "%s/%s", dir, files[i]);
        pid_t c = fork();
        if (c == 0) {
            char *argv[] = {p, "who", NULL};
            execve(p, argv, environ);
            printf("%s: errno=%d\n", files[i], errno);
            _exit(1);
        }
        int status;
        waitpid(c, &status, 0);
        unlink(p);
    }
    rmdir(dir);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint32_t size = sizeof self;
    _NSGetExecutablePath(self, &size);
    if (argc > 1 && strcmp(argv[1], "after") == 0) {
        return after(argc, argv);
    }
    if (argc > 1 && strcmp(argv[1], "who") == 0) {
        return who();
    }
    if (argc > 2 && strcmp(argv[1], "translate") == 0) {
        return translate(argv[2]);
    }
    if (argc > 1 && strcmp(argv[1], "script") == 0) {
        return script(argc, argv);
    }
    snprintf(dir, sizeof dir, "/tmp/rax-exec-XXXXXX");
    mkdtemp(dir);

    refusals();
    killed_after_commit();
    run_and_wait("state", exec_with_state);

    char text[PATH_MAX + 64];
    int n = snprintf(text, sizeof text, "#!  %s script  one\ttwo  # comment\n", self);
    put("script", text, n, 0755);
    n = snprintf(text, sizeof text, "#!%s script\n", self);
    put("script2", text, n, 0755);
    run_and_wait("script", exec_script);
    run_and_wait("relative script", exec_script_relative);
    run_and_wait("script without argv", exec_script_null_argv);

    char p[PATH_MAX];
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, refused[i]);
        unlink(p);
    }
    for (size_t i = 0; i < sizeof others / sizeof *others; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, others[i]);
        unlink(p);
    }
    printf("cleanup: %d\n", rmdir(dir));
    return 0;
}
