/* Signals sent from outside: the user_linux CLI tests send this program
 * host signals and follow its progress through the lines it prints. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t got;
static volatile int code, pid;

static void on_signal(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got = sig;
    code = si->si_code;
    pid = si->si_pid;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    printf("ready\n");
    while (!got) pause();
    printf("%d si_code=%d from-parent=%d\n", got, code, pid == getppid());

    /* A blocking read of standard input ends with EINTR (no SA_RESTART). */
    got = 0;
    printf("reading\n");
    char c;
    errno = 0;
    ssize_t n = read(0, &c, 1);
    printf("read=%zd eintr=%d signal=%d\n", n, errno == EINTR, got);

    /* SIGTERM keeps its default action. */
    printf("waiting\n");
    for (;;) pause();
}
