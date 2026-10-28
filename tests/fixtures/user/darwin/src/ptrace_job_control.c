/* A connected child's job stop and continue remain visible to waiters. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t stop_signals;
static void child_changed(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)context;
    if (info->si_pid == tracee && info->si_code == CLD_STOPPED) stop_signals++;
}
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(124);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int self_stop = argc > 1 && strcmp(argv[1], "self") == 0;
    int external_continue = argc > 1 && strcmp(argv[1], "external") == 0;
    int double_stop = argc > 1 && strcmp(argv[1], "double") == 0;
    int host_stop_unwaited = argc > 1 && strcmp(argv[1], "hoststop_unwaited") == 0;
    int host_stop = host_stop_unwaited || (argc > 1 && strcmp(argv[1], "hoststop") == 0);
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        char byte;
        if (write(ready[1], "r", 1) != 1) _exit(90);
        if (self_stop) raise(SIGSTOP);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    tracee = child;
    if (double_stop) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_sigaction = child_changed;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGCHLD, &action, NULL) != 0) goto fail;
    }
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(gate[0]);
    char byte;
    siginfo_t info;
    int status;
    if (read(ready[0], &byte, 1) != 1) goto fail;
    if (host_stop) {
        pid_t helper = fork();
        if (helper < 0) goto fail;
        if (helper == 0) _exit(kill(child, SIGSTOP) != 0);
        int helper_status;
        if (waitpid(helper, &helper_status, 0) != helper || !WIFEXITED(helper_status) ||
            WEXITSTATUS(helper_status) != 0) goto fail;
        if (host_stop_unwaited && kill(child, SIGSTOP)) goto fail;
    } else if (!self_stop && kill(child, SIGSTOP)) goto fail;
    memset(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)child, &info, WSTOPPED | WNOWAIT) || info.si_pid != child) goto fail;
    printf("peek-stop=%d signal=%d\n", info.si_code, info.si_status);
    pid_t none = waitpid(child, &status, WNOHANG);
    if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status)) goto fail;
    printf("without-untraced=%d stop=%d\n", (int)none, WSTOPSIG(status));
    if (double_stop) {
        pid_t helper = fork();
        if (helper < 0) goto fail;
        if (helper == 0) _exit(kill(child, SIGSTOP) != 0);
        int helper_status;
        if (waitpid(helper, &helper_status, 0) != helper || !WIFEXITED(helper_status) ||
            WEXITSTATUS(helper_status) != 0) goto fail;
        int duplicate = 0;
        for (int i = 0; i < 20; i++) {
            pid_t observed = waitpid(child, &status, WUNTRACED | WNOHANG);
            if (observed == child) { duplicate = 1; break; }
            if (observed < 0) goto fail;
            usleep(1000);
        }
        printf("duplicate-stop=%d\n", duplicate);
        printf("stop-signals=%d\n", (int)stop_signals);
        if (duplicate || stop_signals != 1) goto fail;
    }
    if (host_stop && !host_stop_unwaited && kill(child, SIGSTOP)) goto fail;
    if (external_continue) {
        pid_t helper = fork();
        if (helper < 0) goto fail;
        if (helper == 0) _exit(kill(child, SIGCONT) != 0);
        int helper_status;
        if (waitpid(helper, &helper_status, 0) != helper || !WIFEXITED(helper_status) ||
            WEXITSTATUS(helper_status) != 0) goto fail;
    } else if (kill(child, SIGCONT)) goto fail;
    memset(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)child, &info, WCONTINUED | WNOWAIT) || info.si_pid != child) goto fail;
    printf("peek-continue=%d signal=%d\n", info.si_code, info.si_status);
    if (waitpid(child, &status, WCONTINUED) != child || !WIFCONTINUED(status)) goto fail;
    printf("continued=%d\n", WIFCONTINUED(status) != 0);
    if (write(gate[1], "x", 1) != 1 || waitpid(child, &status, 0) != child) goto fail;
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    puts("failed");
    return 1;
}
