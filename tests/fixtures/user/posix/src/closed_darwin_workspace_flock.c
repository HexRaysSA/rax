#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "workspace flock line %d: %s (errno %d)\n",
                line, expression, errno);
        _exit(2);
    }
}
#define require(expression) require_at((expression), __LINE__, #expression)

static void conflict(int fd, int how) {
    require(flock(fd, how | LOCK_NB) == -1 && errno == EWOULDBLOCK);
}

static void lock_modes(const char *data, int a) {
    int b = open(data, O_RDONLY);
    require(b >= 0);
    require(flock(a, 0) == -1 && errno == EBADF);
    require(flock(a, LOCK_SH | LOCK_EX | LOCK_NB | 0x1000) == 0);
    conflict(b, LOCK_SH);
    struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 8, .l_len = 4};
    require(fcntl(a, F_GETLK, &query) == 0);
    require(query.l_type == F_WRLCK && query.l_pid == -1);
    require(query.l_start == 0 && query.l_len == 0 && query.l_whence == SEEK_SET);
    require(fcntl(a, F_SETLK, &query) == -1 && errno == EAGAIN);
    require(flock(a, LOCK_UN | LOCK_EX) == 0);
    require(fcntl(a, F_SETLK, &query) == 0);
    conflict(b, LOCK_EX);
    query.l_type = F_UNLCK;
    require(fcntl(a, F_SETLK, &query) == 0);
    require(flock(a, LOCK_SH) == 0 && flock(b, LOCK_SH) == 0);
    conflict(a, LOCK_EX);
    conflict(b, LOCK_EX);
    require(flock(a, LOCK_UN) == 0);
    require(flock(b, LOCK_EX | LOCK_NB) == 0);
    int duplicate = dup(b);
    require(duplicate >= 0 && close(b) == 0);
    conflict(a, LOCK_SH);
    require(close(duplicate) == 0);
    require(flock(a, LOCK_EX | LOCK_NB) == 0);
    require(flock(a, LOCK_UN) == 0);
    puts("APFS whole-file and record lock interaction");
}

static void wait_for_inherited_owner(const char *data) {
    int holder = open(data, O_RDONLY);
    int waiter = open(data, O_RDONLY);
    require(holder >= 0 && waiter >= 0 && flock(holder, LOCK_EX) == 0);
    int ready[2], release[2];
    require(pipe(ready) == 0 && pipe(release) == 0);
    pid_t owner = fork();
    require(owner >= 0);
    if (owner == 0) {
        require(close(waiter) == 0 && close(release[1]) == 0);
        char byte;
        require(read(release[0], &byte, 1) == 1 && byte == 'r');
        _exit(0);
    }
    require(close(holder) == 0 && close(release[0]) == 0);
    conflict(waiter, LOCK_EX);
    pid_t acquiring = fork();
    require(acquiring >= 0);
    if (acquiring == 0) {
        require(close(ready[0]) == 0);
        conflict(waiter, LOCK_EX);
        require(write(ready[1], "r", 1) == 1);
        require(flock(waiter, LOCK_EX) == 0);
        _exit(0);
    }
    require(close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    for (int i = 0; i < 32; ++i) sched_yield();
    int status;
    require(waitpid(acquiring, &status, WNOHANG) == 0);
    require(write(release[1], "r", 1) == 1 && close(release[1]) == 0);
    require(waitpid(owner, &status, 0) == owner && status == 0);
    require(waitpid(acquiring, &status, 0) == acquiring && status == 0);
    require(close(waiter) == 0 && close(ready[0]) == 0);
    puts("APFS lock inheritance and wake on owner exit");
}

static void wait_for_upgrade(const char *data) {
    int a = open(data, O_RDONLY);
    int b = open(data, O_RDONLY);
    require(a >= 0 && b >= 0);
    require(flock(a, LOCK_SH) == 0 && flock(b, LOCK_SH) == 0);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(a) == 0 && close(ready[0]) == 0);
        require(write(ready[1], "r", 1) == 1);
        require(flock(b, LOCK_EX) == 0);
        _exit(0);
    }
    require(close(b) == 0 && close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    struct timespec begin;
    require(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    while (flock(a, LOCK_EX | LOCK_NB) != 0) {
        require(errno == EWOULDBLOCK);
        sched_yield();
        struct timespec now;
        require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        require(now.tv_sec - begin.tv_sec < 5);
    }
    require(close(a) == 0 && close(ready[0]) == 0);
    int status;
    require(waitpid(child, &status, 0) == child && status == 0);
}

int main(int argc, char **argv) {
    require(argc == 2 && mkdir(argv[1], 0700) == 0);
    char data[PATH_MAX], alias[PATH_MAX], named[PATH_MAX];
    int n = snprintf(data, sizeof data, "%s/data", argv[1]);
    require(n > 0 && n < (int)sizeof data);
    n = snprintf(alias, sizeof alias, "%s/data.alias", argv[1]);
    require(n > 0 && n < (int)sizeof alias);
    n = snprintf(named, sizeof named, "%s/data/..namedfork/rsrc", argv[1]);
    require(n > 0 && n < (int)sizeof named);
    int a = open(data, O_RDWR | O_CREAT | O_EXCL, 0600);
    require(a >= 0 && link(data, alias) == 0);
    lock_modes(alias, a);
    wait_for_inherited_owner(data);
    wait_for_upgrade(data);

    int endpoints[2];
    require(pipe(endpoints) == 0);
    require(flock(endpoints[0], LOCK_EX | LOCK_NB) == -1 && errno == ENOTSUP);
    require(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);

    int first_dir = open(argv[1], O_RDONLY);
    int other_dir = open(argv[1], O_RDONLY);
    require(first_dir >= 0 && other_dir >= 0 && flock(first_dir, LOCK_EX) == 0);
    conflict(other_dir, LOCK_SH);
    require(flock(a, LOCK_EX) == 0);
    int resource = open(named, O_WRONLY | O_CREAT, 0600);
    require(resource >= 0 && write(resource, "x", 1) == 1);
    require(flock(resource, LOCK_EX | LOCK_NB) == 0);
    require(close(resource) == 0 && close(a) == 0);
    require(close(first_dir) == 0 && flock(other_dir, LOCK_EX | LOCK_NB) == 0);
    require(close(other_dir) == 0);
    require(unlink(alias) == 0 && unlink(data) == 0 && rmdir(argv[1]) == 0);
    puts("APFS directory and resource-fork lock identity");
    return 0;
}
