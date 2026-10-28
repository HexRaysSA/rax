/* Native probe for the signal carried across PT_DETACH and PT_CONTINUE.
 * Compile with: clang -O1 -Wall -Wno-deprecated-declarations
 *   tools/darwin/ptrace_detach_probe.c -o /tmp/ptrace-detach-probe
 * Run as: /tmp/ptrace-detach-probe detach|continue 0|usr1|usr2 [trap|usr1]
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static volatile sig_atomic_t received;

static void signal_handler(int signal_number) {
    (void)signal_number;
    received++;
}

static void timed_out(int signal_number) {
    (void)signal_number;
    if (tracee > 0) {
        kill((pid_t)tracee, SIGKILL);
    }
    _exit(2);
}

int main(int argc, char **argv) {
    if ((argc != 3 && argc != 4) ||
        (strcmp(argv[1], "detach") && strcmp(argv[1], "continue")) ||
        (strcmp(argv[2], "0") && strcmp(argv[2], "usr1") && strcmp(argv[2], "usr2")) ||
        (argc == 4 && strcmp(argv[3], "trap") && strcmp(argv[3], "usr1"))) {
        return 2;
    }
    int detach = strcmp(argv[1], "detach") == 0;
    int signal_number = strcmp(argv[2], "usr1") == 0 ? SIGUSR1 :
        strcmp(argv[2], "usr2") == 0 ? SIGUSR2 : 0;
    int stop_signal = argc == 4 && strcmp(argv[3], "usr1") == 0 ? SIGUSR1 : SIGTRAP;
    setbuf(stdout, NULL);
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        signal(SIGUSR1, signal_handler);
        if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
            _exit(90);
        }
        raise(stop_signal);
        printf("received_usr1=%d\n", (int)received);
        _exit(0);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    int status = 0;
    pid_t stopped = waitpid(child, &status, 0);
    if (stopped != child || !WIFSTOPPED(status)) {
        if (stopped != child && (stopped >= 0 || errno != ECHILD)) {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        tracee = 0;
        printf("trace_stop=failed\n");
        return 1;
    }
    printf("trace_stop=%d\n", WSTOPSIG(status));
    errno = 0;
    int result = ptrace(detach ? PT_DETACH : PT_CONTINUE, child, (caddr_t)1, signal_number);
    printf("request=%d errno=%d\n", result, errno);
    if (result != 0) {
        kill(child, SIGKILL);
    }
    pid_t waited = waitpid(child, &status, 0);
    tracee = 0;
    alarm(0);
    printf("exit=%d signal=%d\n",
           waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1,
           waited == child && WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return waited != child || result != 0;
}
