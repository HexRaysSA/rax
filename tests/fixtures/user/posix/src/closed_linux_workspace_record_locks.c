#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "workspace record lock line %d: %s (errno %d)\n",
                line, expression, errno);
        _exit(2);
    }
}
#define require(expression) require_at((expression), __LINE__, #expression)

static void send(int fd, char byte) {
    require(write(fd, &byte, 1) == 1);
}

static char receive(int fd) {
    char byte;
    require(read(fd, &byte, 1) == 1);
    return byte;
}

static void wait_success(pid_t child) {
    int status;
    require(waitpid(child, &status, 0) == child && status == 0);
}

static int set_lock(int fd, int cmd, short type, short whence, off_t start) {
    struct flock lock = {
        .l_type = type, .l_whence = whence, .l_start = start, .l_len = 8
    };
    return fcntl(fd, cmd, &lock) == 0 ? 0 : errno;
}

static struct flock get_lock(int fd, int cmd, off_t start) {
    struct flock lock = {
        .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = start, .l_len = 8
    };
    require(fcntl(fd, cmd, &lock) == 0);
    return lock;
}

static void yield_to_peer(void) {
    for (int i = 0; i < 32; ++i) sched_yield();
}

static void posix_alias(int fd, const char *alias) {
    int other = open(alias, O_RDWR);
    require(other >= 0);
    require(set_lock(fd, F_SETLK, F_WRLCK, SEEK_END, -32) == 0);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t parent = getpid();
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(fd) == 0 && close(ready[0]) == 0);
        struct flock conflict = get_lock(other, F_GETLK, 32);
        require(conflict.l_type == F_WRLCK && conflict.l_pid == parent);
        require(conflict.l_whence == SEEK_SET && conflict.l_start == 32 && conflict.l_len == 8);
        require(set_lock(other, F_SETLK, F_WRLCK, SEEK_SET, 32) == EAGAIN);
        send(ready[1], 'r');
        require(set_lock(other, F_SETLKW, F_WRLCK, SEEK_SET, 32) == 0);
        _exit(0);
    }
    require(close(ready[1]) == 0 && receive(ready[0]) == 'r');
    yield_to_peer();
    int status;
    require(waitpid(child, &status, WNOHANG) == 0);
    require(close(other) == 0);
    wait_success(child);
    require(get_lock(fd, F_GETLK, 32).l_type == F_UNLCK);
    require(close(ready[0]) == 0);
    puts("POSIX hard link and close");
}

static void ofd_alias(int fd, const char *alias) {
    int other = open(alias, O_RDWR);
    require(other >= 0);
    int duplicate = dup(other);
    require(duplicate >= 0);
    require(set_lock(other, F_OFD_SETLK, F_WRLCK, SEEK_SET, 40) == 0);
    require(close(other) == 0);
    require(get_lock(duplicate, F_OFD_GETLK, 40).l_type == F_UNLCK);
    struct flock conflict = get_lock(fd, F_GETLK, 40);
    require(conflict.l_type == F_WRLCK && conflict.l_pid == -1);
    require(set_lock(fd, F_OFD_SETLK, F_WRLCK, SEEK_SET, 40) == EAGAIN);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(duplicate) == 0 && close(ready[0]) == 0);
        send(ready[1], 'r');
        require(set_lock(fd, F_OFD_SETLKW, F_WRLCK, SEEK_SET, 40) == 0);
        require(set_lock(fd, F_OFD_SETLK, F_UNLCK, SEEK_SET, 40) == 0);
        _exit(0);
    }
    require(close(ready[1]) == 0 && receive(ready[0]) == 'r');
    yield_to_peer();
    int status;
    require(waitpid(child, &status, WNOHANG) == 0);
    require(close(duplicate) == 0);
    wait_success(child);
    require(get_lock(fd, F_GETLK, 40).l_type == F_UNLCK);
    require(close(ready[0]) == 0);
    puts("OFD sharing and last close");
}

static void detect_cycle(int fd) {
    int ready[2], result[2];
    require(pipe(ready) == 0 && pipe(result) == 0);
    require(set_lock(fd, F_SETLK, F_WRLCK, SEEK_SET, 0) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(ready[0]) == 0 && close(result[0]) == 0);
        require(set_lock(fd, F_SETLK, F_WRLCK, SEEK_SET, 8) == 0);
        send(ready[1], 'r');
        int error = set_lock(fd, F_SETLKW, F_WRLCK, SEEK_SET, 0);
        require(error == 0 || error == EDEADLK);
        require(set_lock(fd, F_SETLK, F_UNLCK, SEEK_SET, 8) == 0);
        send(result[1], error == EDEADLK ? 'd' : 'o');
        _exit(0);
    }
    require(close(ready[1]) == 0 && close(result[1]) == 0 && receive(ready[0]) == 'r');
    int error = set_lock(fd, F_SETLKW, F_WRLCK, SEEK_SET, 8);
    require(error == 0 || error == EDEADLK);
    require(set_lock(fd, F_SETLK, F_UNLCK, SEEK_SET, 0) == 0);
    require(receive(result[0]) == (error == EDEADLK ? 'o' : 'd'));
    wait_success(child);
    require(set_lock(fd, F_SETLK, F_UNLCK, SEEK_SET, 8) == 0);
    require(close(ready[0]) == 0 && close(result[0]) == 0);
    puts("POSIX deadlock rejection");
}

static void caught(int signal) {
    (void)signal;
}

static void interrupt_wait(int fd) {
    int ready[2];
    require(pipe(ready) == 0 && set_lock(fd, F_SETLK, F_WRLCK, SEEK_SET, 0) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(ready[0]) == 0);
        struct sigaction action = {.sa_handler = caught};
        sigemptyset(&action.sa_mask);
        require(sigaction(SIGUSR1, &action, NULL) == 0);
        send(ready[1], 'r');
        require(set_lock(fd, F_SETLKW, F_WRLCK, SEEK_SET, 0) == EINTR);
        _exit(0);
    }
    require(close(ready[1]) == 0 && receive(ready[0]) == 'r');
    yield_to_peer();
    int status;
    pid_t finished = 0;
    struct timespec begin;
    require(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    for (int i = 0; finished == 0; ++i) {
        require(kill(child, SIGUSR1) == 0 || errno == ESRCH);
        sched_yield();
        finished = waitpid(child, &status, WNOHANG);
        require(finished >= 0);
        if (i % 64 == 0) {
            struct timespec now;
            require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
            require(now.tv_sec - begin.tv_sec < 10);
        }
    }
    require(finished == child && status == 0);
    require(set_lock(fd, F_SETLK, F_UNLCK, SEEK_SET, 0) == 0);
    require(close(ready[0]) == 0);
    puts("POSIX signal interruption");
}

int main(int argc, char **argv) {
    require(argc == 2);
    char alias[PATH_MAX];
    int size = snprintf(alias, sizeof alias, "%s.alias", argv[1]);
    require(size > 0 && size < (int)sizeof alias);
    int fd = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0600);
    require(fd >= 0 && ftruncate(fd, 64) == 0 && link(argv[1], alias) == 0);
    posix_alias(fd, alias);
    ofd_alias(fd, alias);
    detect_cycle(fd);
    interrupt_wait(fd);
    require(close(fd) == 0 && unlink(alias) == 0 && unlink(argv[1]) == 0);
    return 0;
}
