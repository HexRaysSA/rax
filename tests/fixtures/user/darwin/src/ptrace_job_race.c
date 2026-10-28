/* A continue sent immediately after a connected child's stop is not lost. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(124);
}

int main(void) {
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        char byte;
        if (write(ready[1], "r", 1) != 1) _exit(90);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(gate[0]);
    char byte;
    int status;
    if (read(ready[0], &byte, 1) != 1 || kill(child, SIGSTOP) || kill(child, SIGCONT) ||
        write(gate[1], "x", 1) != 1 || waitpid(child, &status, 0) != child) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        tracee = 0;
        alarm(0);
        return 1;
    }
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}
