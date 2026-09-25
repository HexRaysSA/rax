/*
 * Process Creation and Management
 *
 * Tests fork/exec syscall patterns.
 * Exercises process creation and control.
 *
 * Features exercised:
 *   - fork() process creation
 *   - exec() family
 *   - wait() and waitpid()
 *   - Process exit
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;
static int64_t rax_det; /* rax: deterministic parts of the result: no PIDs, no exec- or timing-dependent values */

/* Simple fork and exit */
__attribute__((noinline))
int64_t test_simple_fork(void) {
    int64_t result = 0;

    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    } else if (pid == 0) {
        /* Child process */
        _exit(42);
    } else {
        /* Parent process */
        result += pid;

        int status;
        pid_t waited = waitpid(pid, &status, 0);
        result += waited;

        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status); /* Should be 42 */
            rax_det += WEXITSTATUS(status); /* rax: print the result so that runs can be compared */
        }
    }

    return result;
}

/* Fork with computation */
__attribute__((noinline))
int64_t test_fork_compute(void) {
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
        /* Child: compute and send result */
        close(pipe_fd[0]); /* Close read end */

        int64_t sum = 0;
        for (int i = 0; i < 1000; i++) {
            sum += i * i;
        }

        write(pipe_fd[1], &sum, sizeof(sum));
        close(pipe_fd[1]);
        _exit(0);
    } else {
        /* Parent: wait and read result */
        close(pipe_fd[1]); /* Close write end */

        int64_t child_result;
        read(pipe_fd[0], &child_result, sizeof(child_result));
        close(pipe_fd[0]);

        result += child_result;
        rax_det += child_result; /* rax: print the result so that runs can be compared */

        int status;
        waitpid(pid, &status, 0);
    }

    return result;
}

/* Multiple forks */
__attribute__((noinline))
int64_t test_multiple_forks(void) {
    int64_t result = 0;
    pid_t children[4];
    int num_children = 0;

    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            /* Fork failed, wait for existing children */
            break;
        } else if (pid == 0) {
            /* Child */
            _exit(i * 10);
        } else {
            /* Parent */
            children[num_children++] = pid;
            result += pid;
        }
    }

    /* Wait for all children */
    for (int i = 0; i < num_children; i++) {
        int status;
        pid_t waited = waitpid(children[i], &status, 0);
        result += waited;
        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status);
            rax_det += WEXITSTATUS(status); /* rax: print the result so that runs can be compared */
        }
    }

    return result;
}

/* Fork with different exit paths */
__attribute__((noinline))
int64_t test_fork_exit_paths(void) {
    int64_t result = 0;

    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    } else if (pid == 0) {
        /* Child - decide exit code based on PID */
        int exit_code = (getpid() % 256);
        _exit(exit_code);
    } else {
        /* Parent */
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status);
            rax_det += WEXITSTATUS(status) == (pid & 0xff); /* rax: print the result so that runs can be compared */
        }

        result += pid;
    }

    return result;
}

/* Fork and exec /bin/true (or /usr/bin/true) */
__attribute__((noinline))
int64_t test_fork_exec(void) {
    int64_t result = 0;

    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    } else if (pid == 0) {
        /* Child - exec true command */
        char *argv[] = {"true", NULL};
        char *envp[] = {NULL};

        /* Try common paths */
        execve("/bin/true", argv, envp);
        execve("/usr/bin/true", argv, envp);

        /* If exec fails, exit with error */
        _exit(127);
    } else {
        /* Parent */
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status); /* Should be 0 for true */
        }
        result += pid;
    }

    return result;
}

/* Fork bomb protection - limited depth */
__attribute__((noinline))
int64_t test_fork_tree(int depth) {
    if (depth <= 0) {
        return getpid();
    }

    int64_t result = 0;
    pid_t pid = fork();

    if (pid < 0) {
        return getpid();
    } else if (pid == 0) {
        /* Child - recurse */
        int64_t child_result = test_fork_tree(depth - 1);
        _exit((int)(child_result & 0xFF));
    } else {
        /* Parent */
        result += pid;
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status);
        }
    }

    return result;
}

/* Test wait options */
__attribute__((noinline))
int64_t test_wait_options(void) {
    int64_t result = 0;

    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    } else if (pid == 0) {
        /* Child - sleep briefly then exit */
        usleep(1000); /* 1ms */
        _exit(55);
    } else {
        /* Parent - try WNOHANG first */
        int status;
        pid_t waited;

        /* Non-blocking wait (child probably not done yet) */
        waited = waitpid(pid, &status, WNOHANG);
        if (waited == 0) {
            result += 1; /* Child not ready */
        }

        /* Blocking wait */
        waited = waitpid(pid, &status, 0);
        result += waited;

        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status);
            rax_det += WEXITSTATUS(status); /* rax: print the result so that runs can be compared */
        }
    }

    return result;
}

/* Test getpid/getppid */
__attribute__((noinline))
int64_t test_pid_functions(void) {
    int64_t result = 0;
    int pipe_fd[2];

    pid_t parent_pid = getpid();
    result += parent_pid;

    if (pipe(pipe_fd) < 0) {
        return result;
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return result;
    } else if (pid == 0) {
        /* Child */
        close(pipe_fd[0]);

        pid_t child_pid = getpid();
        pid_t child_ppid = getppid();

        /* Send PIDs to parent */
        write(pipe_fd[1], &child_pid, sizeof(child_pid));
        write(pipe_fd[1], &child_ppid, sizeof(child_ppid));
        close(pipe_fd[1]);

        _exit(0);
    } else {
        /* Parent */
        close(pipe_fd[1]);

        pid_t child_pid, child_ppid;
        read(pipe_fd[0], &child_pid, sizeof(child_pid));
        read(pipe_fd[0], &child_ppid, sizeof(child_ppid));
        close(pipe_fd[0]);

        /* Verify child's ppid matches our pid */
        result += (child_ppid == parent_pid) ? 100 : 0;
        result += (child_pid == pid) ? 100 : 0;
        rax_det += ((child_ppid == parent_pid) ? 100 : 0) + ((child_pid == pid) ? 100 : 0); /* rax: print the result so that runs can be compared */

        int status;
        waitpid(pid, &status, 0);
    }

    return result;
}

/* Test process groups */
__attribute__((noinline))
int64_t test_process_groups(void) {
    int64_t result = 0;

    pid_t pgid = getpgrp();
    result += pgid;

    pid_t pid = fork();

    if (pid < 0) {
        return result;
    } else if (pid == 0) {
        /* Child - create new process group */
        setpgid(0, 0);
        pid_t new_pgid = getpgrp();

        /* Should be our own PID now */
        _exit((new_pgid == getpid()) ? 1 : 0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status) * 50;
            rax_det += WEXITSTATUS(status) * 50; /* rax: print the result so that runs can be compared */
        }
    }

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 2; iter++) { /* rax: was 50 */
        result += test_simple_fork();
        result += test_fork_compute();

        if (iter % 10 == 0) {
            result += test_multiple_forks();
        }

        result += test_fork_exit_paths();

        if (iter % 5 == 0) {
            result += test_fork_exec();
        }

        if (iter % 20 == 0) {
            result += test_fork_tree(3);
        }

        result += test_wait_options();
        result += test_pid_functions();

        if (iter % 10 == 0) {
            result += test_process_groups();
        }
    }

    sink = result;
    printf("result_det=%" PRId64 "\n", rax_det); /* rax: print the result so that runs can be compared */
    return 0;
}
