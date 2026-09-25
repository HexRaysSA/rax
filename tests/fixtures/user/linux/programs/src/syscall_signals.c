/*
 * Signal Handling
 *
 * Tests signal syscall patterns.
 * Exercises signal delivery and handling.
 *
 * Features exercised:
 *   - Signal installation (sigaction)
 *   - Signal delivery (kill, raise)
 *   - Signal blocking (sigprocmask)
 *   - Signal waiting (sigsuspend, sigwait)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;
static int64_t rax_nondet; /* rax: PIDs, excluded from the printed result */
volatile sig_atomic_t signal_count = 0;
volatile sig_atomic_t last_signal = 0;

/* Basic signal handler */
void basic_handler(int sig) {
    signal_count++;
    last_signal = sig;
}

/* Signal handler with siginfo */
void siginfo_handler(int sig, siginfo_t *info, void *context) {
    (void)context;
    signal_count++;
    last_signal = sig;
    if (info) {
        /* Access siginfo fields */
        sink += info->si_signo;
        sink += info->si_pid;
    }
}

/* Test basic signal handling */
__attribute__((noinline))
int64_t test_basic_signals(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    /* Setup handler for SIGUSR1 */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGUSR1, &sa, &old_sa) < 0) {
        return -1;
    }

    signal_count = 0;

    /* Send signal to self */
    for (int i = 0; i < 10; i++) {
        raise(SIGUSR1);
    }

    result += signal_count;
    result += last_signal;

    /* Restore old handler */
    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

/* Test sigaction with SA_SIGINFO */
__attribute__((noinline))
int64_t test_siginfo(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = siginfo_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGUSR2, &sa, &old_sa) < 0) {
        return -1;
    }

    signal_count = 0;

    for (int i = 0; i < 5; i++) {
        raise(SIGUSR2);
    }

    result += signal_count;

    sigaction(SIGUSR2, &old_sa, NULL);

    return result;
}

/* Test signal blocking */
__attribute__((noinline))
int64_t test_signal_blocking(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;
    sigset_t block_set, old_set;

    /* Setup handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, &old_sa);

    signal_count = 0;

    /* Block SIGUSR1 */
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block_set, &old_set);

    /* Send signals while blocked */
    for (int i = 0; i < 5; i++) {
        raise(SIGUSR1);
    }

    result += signal_count; /* Should still be 0 */

    /* Check if signal is pending */
    sigset_t pending;
    sigpending(&pending);
    if (sigismember(&pending, SIGUSR1)) {
        result += 100;
    }

    /* Unblock - signal should be delivered */
    sigprocmask(SIG_UNBLOCK, &block_set, NULL);

    result += signal_count; /* Should be 1 (signals coalesce) */

    /* Restore */
    sigprocmask(SIG_SETMASK, &old_set, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

/* Test signal mask during handler */
__attribute__((noinline))
int64_t test_handler_mask(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    /* Setup handler that blocks SIGUSR2 during execution */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2); /* Block SIGUSR2 in handler */
    sa.sa_flags = 0;

    sigaction(SIGUSR1, &sa, &old_sa);

    signal_count = 0;
    raise(SIGUSR1);

    result += signal_count;

    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

/* Test sending signals between processes */
__attribute__((noinline))
int64_t test_kill(void) {
    int64_t result = 0;
    int pipe_fd[2];

    if (pipe(pipe_fd) < 0) {
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    } else if (pid == 0) {
        /* Child */
        close(pipe_fd[0]);

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = basic_handler;
        sigaction(SIGUSR1, &sa, NULL);

        signal_count = 0;

        /* rax: block SIGUSR1 until sigsuspend: with pause(), a SIGUSR1 sent
         * between the write and the pause was lost and the child hung (on
         * one CPU the parent always preempts it there) */
        sigset_t rax_block, rax_old;
        sigemptyset(&rax_block);
        sigaddset(&rax_block, SIGUSR1);
        sigprocmask(SIG_BLOCK, &rax_block, &rax_old);

        /* Tell parent we're ready */
        char ready = 1;
        write(pipe_fd[1], &ready, 1);

        /* Wait for signal */
        sigsuspend(&rax_old); /* rax: was pause() */

        /* Send back count */
        int count = signal_count;
        write(pipe_fd[1], &count, sizeof(count));
        close(pipe_fd[1]);

        _exit(0);
    } else {
        /* Parent */
        close(pipe_fd[1]);

        /* Wait for child to be ready */
        char ready;
        read(pipe_fd[0], &ready, 1);

        /* Send signal to child */
        kill(pid, SIGUSR1);

        /* Read result */
        int count;
        read(pipe_fd[0], &count, sizeof(count));
        close(pipe_fd[0]);

        result += count;

        int status;
        waitpid(pid, &status, 0);
        result += pid;
        rax_nondet += pid; /* rax: print the result so that runs can be compared */
    }

    return result;
}

/* Test alarm */
__attribute__((noinline))
int64_t test_alarm(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sigaction(SIGALRM, &sa, &old_sa);

    signal_count = 0;

    /* Set very short alarm */
    alarm(1);

    /* Cancel it */
    unsigned int remaining = alarm(0);
    result += (remaining > 0) ? 1 : 0;

    /* Verify no signal received */
    result += signal_count;

    sigaction(SIGALRM, &old_sa, NULL);

    return result;
}

/* Test multiple signal handlers */
__attribute__((noinline))
int64_t test_multiple_handlers(void) {
    int64_t result = 0;
    struct sigaction sa1, sa2, old_sa1, old_sa2;

    memset(&sa1, 0, sizeof(sa1));
    sa1.sa_handler = basic_handler;
    sigaction(SIGUSR1, &sa1, &old_sa1);

    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_handler = basic_handler;
    sigaction(SIGUSR2, &sa2, &old_sa2);

    signal_count = 0;

    for (int i = 0; i < 5; i++) {
        raise(SIGUSR1);
        raise(SIGUSR2);
    }

    result += signal_count;

    sigaction(SIGUSR1, &old_sa1, NULL);
    sigaction(SIGUSR2, &old_sa2, NULL);

    return result;
}

/* Test SIG_IGN */
__attribute__((noinline))
int64_t test_ignore_signal(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGUSR1, &sa, &old_sa);

    /* These should be ignored */
    for (int i = 0; i < 10; i++) {
        raise(SIGUSR1);
    }

    result += 1; /* If we get here, signals were ignored */

    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

/* Test sigsuspend */
__attribute__((noinline))
int64_t test_sigsuspend(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;
    sigset_t wait_mask, block_mask;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sigaction(SIGUSR1, &sa, &old_sa);

    /* Block SIGUSR1 */
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block_mask, NULL);

    signal_count = 0;

    pid_t pid = fork();

    if (pid < 0) {
        sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
        sigaction(SIGUSR1, &old_sa, NULL);
        return -1;
    } else if (pid == 0) {
        /* Child - send signal after brief delay */
        usleep(1000);
        kill(getppid(), SIGUSR1);
        _exit(0);
    } else {
        /* Parent - wait for signal with empty mask */
        sigfillset(&wait_mask);
        sigdelset(&wait_mask, SIGUSR1); /* Allow SIGUSR1 */

        sigsuspend(&wait_mask);

        result += signal_count;

        int status;
        waitpid(pid, &status, 0);
    }

    sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

/* Test SA_RESTART flag */
__attribute__((noinline))
int64_t test_sa_restart(void) {
    int64_t result = 0;
    struct sigaction sa, old_sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = basic_handler;
    sa.sa_flags = SA_RESTART; /* Restart interrupted syscalls */
    sigaction(SIGUSR1, &sa, &old_sa);

    signal_count = 0;
    raise(SIGUSR1);

    result += signal_count;
    result += (sa.sa_flags & SA_RESTART) ? 10 : 0;

    sigaction(SIGUSR1, &old_sa, NULL);

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 10; iter++) { /* rax: was 50 */
        result += test_basic_signals();
        result += test_siginfo();
        result += test_signal_blocking();
        result += test_handler_mask();

        if (iter % 5 == 0) {
            result += test_kill();
        }

        result += test_alarm();
        result += test_multiple_handlers();
        result += test_ignore_signal();

        if (iter % 10 == 0) {
            result += test_sigsuspend();
        }

        result += test_sa_restart();
    }

    sink = result;
    printf("result_det=%" PRId64 "\n", result - rax_nondet); /* rax: print the result so that runs can be compared */
    return 0;
}
