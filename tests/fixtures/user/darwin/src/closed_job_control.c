// Compare guest-owned process groups and sessions with the native kernel.
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void check(int ok, const char *name) {
    if (!ok) {
        fprintf(stderr, "%s: errno=%d\n", name, errno);
        _exit(1);
    }
}

static void send_byte(int fd) {
    check(write(fd, "x", 1) == 1, "send");
}

static void receive_byte(int fd) {
    char byte;
    check(read(fd, &byte, 1) == 1 && byte == 'x', "receive");
}

static void reaped(pid_t selector, pid_t pid) {
    int status;
    check(waitpid(selector, &status, 0) == pid, "waitpid selection");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exit");
}

static void group_change(void) {
    int release[2];
    check(pipe(release) == 0, "group pipe");
    pid_t session = getsid(0);
    pid_t child = fork();
    check(child >= 0, "group fork");
    if (child == 0) {
        close(release[1]);
        receive_byte(release[0]);
        check(getpgrp() == getpid() && getpgid(0) == getpid(), "live group");
        check(getsid(0) == session, "unchanged session");
        check(setsid() == -1 && errno == EPERM, "group leader setsid");
        pid_t grandchild = fork();
        check(grandchild >= 0, "group grandchild");
        if (grandchild == 0) {
            check(getpgrp() == getppid(), "inherited group");
            _exit(0);
        }
        reaped(0, grandchild);
        _exit(0);
    }
    close(release[0]);
    check(setpgid(child, -1) == -1 && errno == EINVAL, "negative group");
    check(setpgid(child, 0) == 0 && getpgid(child) == child, "parent setpgid");
    check(waitpid(0, NULL, WNOHANG) == -1 && errno == ECHILD, "parent group wait");
    send_byte(release[1]);
    close(release[1]);
    reaped(-child, child);
}

static void session_change(void) {
    int ready[2], release[2];
    check(pipe(ready) == 0 && pipe(release) == 0, "session pipes");
    pid_t child = fork();
    check(child >= 0, "session fork");
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        pid_t pid = getpid();
        check(setsid() == pid && getsid(0) == pid && getpgrp() == pid, "new session");
        check(setpgid(0, 0) == -1 && errno == EPERM, "session leader setpgid");
        send_byte(ready[1]);
        receive_byte(release[0]);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    receive_byte(ready[0]);
    check(getsid(child) == child && getpgid(child) == child, "child session");
    check(setpgid(child, getpgrp()) == -1 && errno == EPERM, "cross-session setpgid");
    send_byte(release[1]);
    close(ready[0]);
    close(release[1]);
    reaped(child, child);
}

static void executed_child(const char *image, int spawn) {
    int ready[2], release[2];
    check(pipe(ready) == 0 && pipe(release) == 0, "exec pipes");
    check(fcntl(ready[0], F_SETFD, FD_CLOEXEC) == 0, "close ready reader on exec");
    check(fcntl(release[1], F_SETFD, FD_CLOEXEC) == 0, "close release writer on exec");
    char send_fd[16], recv_fd[16];
    snprintf(send_fd, sizeof(send_fd), "%d", ready[1]);
    snprintf(recv_fd, sizeof(recv_fd), "%d", release[0]);
    char *const args[] = {(char *)image, "--ready", send_fd, recv_fd, NULL};
    pid_t child;
    if (spawn) {
        check(posix_spawn(&child, image, NULL, NULL, args, environ) == 0, "exec spawn");
    } else {
        child = fork();
        check(child >= 0, "exec fork");
        if (child == 0) {
            execve(image, args, environ);
            check(0, "execve");
        }
    }
    close(ready[1]);
    close(release[0]);
    receive_byte(ready[0]);
    check(setpgid(child, 0) == -1 && errno == EACCES, "post-exec setpgid");
    send_byte(release[1]);
    close(ready[0]);
    close(release[1]);
    reaped(child, child);
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--ready") == 0) {
        send_byte(atoi(argv[2]));
        receive_byte(atoi(argv[3]));
        return 0;
    }
    group_change();
    session_change();
    executed_child(argv[0], 0);
    executed_child(argv[0], 1);
    puts("groups, sessions, and post-exec rules match");
    return 0;
}
