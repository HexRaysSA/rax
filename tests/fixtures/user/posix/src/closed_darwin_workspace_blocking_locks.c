#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int lock_region(int fd, int command, short type, off_t start) {
    struct flock lock = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = 8};
    return fcntl(fd, command, &lock) == 0 ? 0 : errno;
}

static void send_byte(int fd, char byte) {
    if (write(fd, &byte, 1) != 1) _exit(10);
}

static char receive_byte(int fd) {
    char byte;
    if (read(fd, &byte, 1) != 1) _exit(11);
    return byte;
}

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "workspace lock fixture line %d: %s (errno %d)\n",
                line, expression, errno);
        _exit(12);
    }
}

#define require(condition) require_at((condition), __LINE__, #condition)

static void require_child(pid_t pid) {
    int status;
    require(waitpid(pid, &status, 0) == pid && status == 0);
}

static void yield_to_peer(void) {
    for (int i = 0; i < 32; ++i) sched_yield();
}

static void wait_for_release(int fd, int close_alias) {
    int ready[2];
    require(pipe(ready) == 0 && lock_region(fd, F_SETLK, F_WRLCK, 0) == 0);
    int alias = dup(fd);
    require(alias >= 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        send_byte(ready[1], 'r');
        require(lock_region(fd, F_SETLKW, F_WRLCK, 0) == 0);
        _exit(0);
    }
    require(receive_byte(ready[0]) == 'r');
    yield_to_peer();
    int status;
    require(waitpid(child, &status, WNOHANG) == 0);
    if (close_alias) {
        require(close(alias) == 0);
    } else {
        require(lock_region(fd, F_SETLK, F_UNLCK, 0) == 0);
        require(close(alias) == 0);
    }
    require_child(child);
    require(close(ready[0]) == 0 && close(ready[1]) == 0);
    puts(close_alias ? "released by close" : "released by unlock");
}

static void wait_for_owner_exit(int fd) {
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(lock_region(fd, F_SETLK, F_WRLCK, 0) == 0);
        send_byte(ready[1], 'r');
        yield_to_peer();
        _exit(0);
    }
    require(receive_byte(ready[0]) == 'r');
    require(lock_region(fd, F_SETLKW, F_WRLCK, 0) == 0);
    require(lock_region(fd, F_SETLK, F_UNLCK, 0) == 0);
    require_child(child);
    require(close(ready[0]) == 0 && close(ready[1]) == 0);
    puts("released by exit");
}

static volatile sig_atomic_t caught_signal;

static void caught(int signal) {
    (void)signal;
    caught_signal = 1;
}

static void interrupt_wait(int fd, int restart) {
    int ready[2];
    require(pipe(ready) == 0 && lock_region(fd, F_SETLK, F_WRLCK, 0) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        struct sigaction action = {.sa_handler = caught, .sa_flags = restart ? SA_RESTART : 0};
        sigemptyset(&action.sa_mask);
        require(sigaction(SIGUSR1, &action, NULL) == 0);
        send_byte(ready[1], 'r');
        require(lock_region(fd, F_SETLKW, F_WRLCK, 0) == (restart ? 0 : EINTR));
        require(caught_signal != 0);
        _exit(0);
    }
    require(receive_byte(ready[0]) == 'r');
    yield_to_peer();
    int status = -1;
    pid_t finished = 0;
    struct timespec begin;
    require(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    for (int i = 0; finished == 0; ++i) {
        require(kill(child, SIGUSR1) == 0 || errno == ESRCH);
        sched_yield();
        finished = waitpid(child, &status, WNOHANG);
        require(finished >= 0);
        if (restart && i == 7) break;
        if (i % 64 == 0) {
            struct timespec now;
            require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
            require(now.tv_sec - begin.tv_sec < 10);
        }
    }
    require(lock_region(fd, F_SETLK, F_UNLCK, 0) == 0);
    if (restart) {
        require(finished == 0);
        require_child(child);
    } else {
        require(finished == child && status == 0);
    }
    require(close(ready[0]) == 0 && close(ready[1]) == 0);
    puts(restart ? "restarted by signal" : "interrupted by signal");
}

static void detect_cycle(int fd) {
    int ready[2], result[2];
    require(pipe(ready) == 0 && pipe(result) == 0);
    require(lock_region(fd, F_SETLK, F_WRLCK, 0) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(lock_region(fd, F_SETLK, F_WRLCK, 8) == 0);
        send_byte(ready[1], 'r');
        int error = lock_region(fd, F_SETLKW, F_WRLCK, 0);
        require(error == 0 || error == EDEADLK);
        require(lock_region(fd, F_SETLK, F_UNLCK, 8) == 0);
        send_byte(result[1], error == EDEADLK ? 'd' : 'o');
        _exit(0);
    }
    require(receive_byte(ready[0]) == 'r');
    int error = lock_region(fd, F_SETLKW, F_WRLCK, 8);
    require(error == 0 || error == EDEADLK);
    require(lock_region(fd, F_SETLK, F_UNLCK, 0) == 0);
    require(receive_byte(result[0]) == (error == EDEADLK ? 'o' : 'd'));
    require_child(child);
    require(close(ready[0]) == 0 && close(ready[1]) == 0);
    require(close(result[0]) == 0 && close(result[1]) == 0);
    puts("one deadlock rejected");
}

int main(int argc, char **argv) {
    require(argc == 2);
    int fd = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0600);
    require(fd >= 0);
    require(lock_region(fd, F_SETLKW, F_WRLCK, 0) == 0);
    require(lock_region(fd, F_SETLKW, F_UNLCK, 0) == 0);
    puts("uncontended");
    wait_for_release(fd, 0);
    wait_for_release(fd, 1);
    wait_for_owner_exit(fd);
    interrupt_wait(fd, 0);
    interrupt_wait(fd, 1);
    detect_cycle(fd);
    require(close(fd) == 0 && unlink(argv[1]) == 0);
    return 0;
}
