#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "workspace flock line %d: %s (errno %d)\n",
                line, expression, errno);
        _exit(2);
    }
}
#define require(expression) require_at((expression), __LINE__, #expression)

static void expect_conflict(int fd, int mode) {
    require(flock(fd, mode | LOCK_NB) == -1 && errno == EWOULDBLOCK);
}

static void alias_and_conversion(const char *path, const char *alias) {
    int original = open(path, O_RDONLY);
    int other = open(alias, O_RDWR);
    require(original >= 0 && other >= 0);
    int duplicate = dup(original);
    require(duplicate >= 0);
    require(flock(original, LOCK_EX | LOCK_NB) == 0);
    expect_conflict(other, LOCK_SH);
    struct flock record = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    require(fcntl(other, F_SETLK, &record) == 0);
    require(close(original) == 0);
    expect_conflict(other, LOCK_EX);
    require(flock(duplicate, LOCK_SH) == 0);
    require(flock(other, LOCK_SH | LOCK_NB) == 0);
    expect_conflict(duplicate, LOCK_EX);
    require(flock(other, LOCK_EX | LOCK_NB) == 0);
    expect_conflict(duplicate, LOCK_SH);
    require(close(other) == 0);
    require(flock(duplicate, LOCK_EX | LOCK_NB) == 0);
    require(close(duplicate) == 0);
    puts("whole-file lock owner and conversion");
}

static void wait_for_last_close(const char *path) {
    int holder = open(path, O_RDONLY);
    int waiter = open(path, O_RDONLY);
    require(holder >= 0 && waiter >= 0 && flock(holder, LOCK_EX) == 0);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(holder) == 0 && close(ready[0]) == 0);
        expect_conflict(waiter, LOCK_EX);
        require(write(ready[1], "r", 1) == 1);
        require(flock(waiter, LOCK_EX) == 0);
        require(close(waiter) == 0);
        _exit(0);
    }
    require(close(waiter) == 0 && close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    for (int i = 0; i < 32; ++i) sched_yield();
    int status;
    require(waitpid(child, &status, WNOHANG) == 0);
    require(close(holder) == 0);
    require(waitpid(child, &status, 0) == child);
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    require(close(ready[0]) == 0);
    puts("whole-file lock wakes on last close");
}

int main(int argc, char **argv) {
    require(argc == 2);
    char alias[PATH_MAX];
    int size = snprintf(alias, sizeof alias, "%s.alias", argv[1]);
    require(size > 0 && size < (int)sizeof alias);
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    require(fd >= 0 && close(fd) == 0 && link(argv[1], alias) == 0);
    alias_and_conversion(argv[1], alias);
    wait_for_last_close(argv[1]);
    require(unlink(alias) == 0 && unlink(argv[1]) == 0);
    return 0;
}
