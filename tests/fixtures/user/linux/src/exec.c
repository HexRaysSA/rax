/* execve and execveat, as a chain of stages that each run the program
 * again (argv[1] names the stage):
 *   (none)   sets up state and executes /proc/self/exe "check";
 *   check    verifies what execve keeps and resets, the errors, and runs a
 *            #! script whose interpreter is this program;
 *   script   verifies the interpreter's arguments, then runs the program
 *            through a descriptor (execveat with AT_EMPTY_PATH);
 *   fdexec   verifies the descriptor's name, then executes from a second
 *            thread;
 *   thread   verifies that the executing thread took over the process.
 * Temporary files go to /tmp and are removed. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include "check.h"

extern char **environ;

static char tmp[4][96];

static void handler(int sig) { (void)sig; }

static void write_file(const char *path, const char *content, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    write(fd, content, strlen(content));
    close(fd);
    chmod(path, mode);
}

static int count_tasks(void) {
    DIR *d = opendir("/proc/self/task");
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)))
        if (e->d_name[0] != '.') n++;
    if (d) closedir(d);
    return n;
}

static void comm_is(const char *name, const char *want) {
    char comm[16] = {0};
    prctl(PR_GET_NAME, comm);
    CHECK(name, strcmp(comm, want) == 0);
}

static int first(void) {
    int keep = open("/dev/null", O_RDONLY);
    int gone = open("/dev/null", O_RDONLY | O_CLOEXEC);
    signal(SIGUSR1, handler);
    signal(SIGUSR2, SIG_IGN);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGHUP);
    sigprocmask(SIG_BLOCK, &s, 0);
    raise(SIGHUP);
    static char alt[65536];
    stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt};
    sigaltstack(&ss, 0);
    struct itimerval it = {{0, 0}, {100, 0}};
    setitimer(ITIMER_REAL, &it, 0);
    prctl(PR_SET_NAME, "before-exec");
    char k[16], g[16];
    snprintf(k, sizeof k, "%d", keep);
    snprintf(g, sizeof g, "%d", gone);
    char *argv[] = {"exec-arg0", "check", k, g, 0};
    char *envp[] = {"EXEC_STAGE=1", 0};
    printf("stage first\n");
    execve("/proc/self/exe", argv, envp);
    printf("FAIL execve: errno %d\n", errno);
    return 1;
}

static int check(int argc, char **argv) {
    printf("stage check\n");
    CHECK("argv", argc == 4 && strcmp(argv[0], "exec-arg0") == 0);
    CHECK("envp", environ[0] && strcmp(environ[0], "EXEC_STAGE=1") == 0 && !environ[1]);
    CHECK("execfn", strcmp((char *)getauxval(AT_EXECFN), "/proc/self/exe") == 0);
    comm_is("comm-from-name", "exe");
    char link[256] = {0};
    readlink("/proc/self/exe", link, sizeof link - 1);
    size_t n = strlen(link);
    CHECK("exe-link", n > 5 && strcmp(link + n - 5, "/exec") == 0);
    int keep = atoi(argv[2]), gone = atoi(argv[3]);
    CHECK("fd-kept", fcntl(keep, F_GETFD) == 0);
    CHECK_ERR("fd-cloexec-closed", fcntl(gone, F_GETFD), EBADF);
    struct sigaction sa;
    sigaction(SIGUSR1, 0, &sa);
    CHECK("handler-reset", sa.sa_handler == SIG_DFL);
    sigaction(SIGUSR2, 0, &sa);
    CHECK("ignored-kept", sa.sa_handler == SIG_IGN);
    sigset_t s;
    sigprocmask(SIG_SETMASK, 0, &s);
    CHECK("mask-kept", sigismember(&s, SIGHUP));
    sigpending(&s);
    CHECK("pending-kept", sigismember(&s, SIGHUP));
    stack_t ss;
    sigaltstack(0, &ss);
    CHECK("altstack-cleared", ss.ss_flags & SS_DISABLE);
    struct itimerval it;
    getitimer(ITIMER_REAL, &it);
    CHECK("itimer-kept", it.it_value.tv_sec > 50);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, 0);

    /* Errors, in the kernel's order. */
    char *args[] = {"x", 0};
    int pid = getpid();
    for (int i = 0; i < 4; i++) snprintf(tmp[i], sizeof tmp[i], "/tmp/rax-exec-%d-%d", pid, i);
    CHECK_ERR("enoent", execve("/nonexistent/program", args, environ), ENOENT);
    CHECK_ERR("directory", execve("/", args, environ), EACCES);
    write_file(tmp[0], "#!/bin/sh\n", 0644);
    CHECK_ERR("no-exec-permission", execve(tmp[0], args, environ), EACCES);
    write_file(tmp[0], "not a program\n", 0755);
    CHECK_ERR("unknown-format", execve(tmp[0], args, environ), ENOEXEC);
    write_file(tmp[0], "#!\n", 0755);
    CHECK_ERR("script-without-interpreter", execve(tmp[0], args, environ), ENOEXEC);
    write_file(tmp[0], "#!/nonexistent/interpreter -x\n", 0755);
    CHECK_ERR("script-interpreter-missing", execve(tmp[0], args, environ), ENOENT);
    char line[128];
    snprintf(line, sizeof line, "#!%s\n", tmp[1]);
    write_file(tmp[0], line, 0755);
    snprintf(line, sizeof line, "#!%s\n", tmp[0]);
    write_file(tmp[1], line, 0755);
    CHECK_ERR("script-loop", execve(tmp[0], args, environ), ELOOP);
    CHECK_ERR("bad-argv", execve("/proc/self/exe", (char **)8, environ), EFAULT);
    char *huge = malloc(200000);
    memset(huge, 'a', 199999);
    huge[199999] = 0;
    char *big[] = {"x", huge, 0};
    CHECK_ERR("argument-too-long", execve("/proc/self/exe", big, environ), E2BIG);
    free(huge);
    CHECK_ERR("execveat-bad-flags", syscall(SYS_execveat, AT_FDCWD, "/proc/self/exe", args, environ, 1),
              EINVAL);
    CHECK_ERR("execveat-empty-path", syscall(SYS_execveat, AT_FDCWD, "", args, environ, 0), ENOENT);
    unlink(tmp[1]);

    /* A script: the interpreter gets its argument and the script's name. */
    write_file(tmp[0], "#!/proc/self/exe  script-arg  \n", 0755);
    setenv("SCRIPT_PATH", tmp[0], 1);
    char *sargv[] = {"ignored", "last", 0};
    fflush(stdout);
    execve(tmp[0], sargv, environ);
    printf("FAIL script: errno %d\n", errno);
    return 1;
}

static int script(int argc, char **argv) {
    printf("stage script\n");
    const char *path = getenv("SCRIPT_PATH");
    CHECK("script-argv", argc == 4 && strcmp(argv[0], "/proc/self/exe") == 0 &&
                             strcmp(argv[1], "script-arg") == 0 &&
                             strcmp(argv[2], path) == 0 && strcmp(argv[3], "last") == 0);
    CHECK("script-execfn", strcmp((char *)getauxval(AT_EXECFN), path) == 0);
    char want[16] = {0};
    strncpy(want, strrchr(path, '/') + 1, 15);
    comm_is("script-comm", want);
    unlink(path);

    /* Through a descriptor: the name is /dev/fd/N, comm the file's name. */
    int fd = open("/proc/self/exe", O_RDONLY);
    char *fargv[] = {"exec", "fdexec", 0};
    fflush(stdout);
    syscall(SYS_execveat, fd, "", fargv, environ, AT_EMPTY_PATH);
    printf("FAIL execveat: errno %d\n", errno);
    return 1;
}

static void *exec_from_thread(void *arg) {
    char *targv[] = {"exec", "thread", arg, 0};
    fflush(stdout);
    execve("/proc/self/exe", targv, environ);
    printf("FAIL thread execve: errno %d\n", errno);
    exit(1);
}

static int fdexec(int argc, char **argv) {
    (void)argc, (void)argv;
    printf("stage fdexec\n");
    const char *execfn = (char *)getauxval(AT_EXECFN);
    CHECK("fd-execfn", strncmp(execfn, "/dev/fd/", 8) == 0);
    comm_is("fd-comm", "exec");
    static char pid[16];
    snprintf(pid, sizeof pid, "%d", getpid());
    pthread_t t;
    pthread_create(&t, 0, exec_from_thread, pid);
    for (;;) pause();
}

static int thread(int argc, char **argv) {
    printf("stage thread\n");
    CHECK("thread-took-pid", argc == 3 && atoi(argv[2]) == getpid() &&
                                 syscall(SYS_gettid) == getpid());
    CHECK("other-threads-gone", count_tasks() == 1);
    FINISH();
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) return first();
    if (!strcmp(argv[1], "check")) return check(argc, argv);
    if (!strcmp(argv[1], "script-arg")) return script(argc, argv);
    if (!strcmp(argv[1], "fdexec")) return fdexec(argc, argv);
    if (!strcmp(argv[1], "thread")) return thread(argc, argv);
    printf("FAIL unknown stage %s\n", argv[1]);
    return 1;
}
