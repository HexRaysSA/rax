// SIGCONT's action as the kernel sees it. `default` or `catch`: take the
// default action or install a handler, print "ready", and sleep until
// killed. `query PID`: print 1 if process PID catches SIGCONT, else 0
// (kinfo_proc's p_sigcatch).
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static void on_cont(int s) { (void)s; }

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "query") == 0) {
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, atoi(argv[2])};
        struct kinfo_proc kp;
        size_t len = sizeof kp;
        if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return 1;
        printf("%d\n", (kp.kp_proc.p_sigcatch & sigmask(SIGCONT)) != 0);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "catch") == 0) signal(SIGCONT, on_cont);
    printf("ready\n");
    fflush(stdout);
    for (;;) sleep(60);
}
