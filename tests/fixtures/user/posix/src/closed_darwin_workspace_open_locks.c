#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "open locking line %d: %s (errno %d)\n", line, expression, errno);
        _exit(2);
    }
}
#define require(expression) require_at((expression), __LINE__, #expression)

static off_t length(int fd) {
    struct stat st;
    require(fstat(fd, &st) == 0);
    return st.st_size;
}

static void conflicting_truncate(int directory) {
    int holder = openat(directory, "data", O_RDONLY | O_EXLOCK | O_SHLOCK | O_CLOEXEC);
    require(holder >= 0);
    require(fcntl(holder, F_GETFD) == FD_CLOEXEC);
    int status = fcntl(holder, F_GETFL);
    require(status >= 0 && (status & (O_SHLOCK | O_EXLOCK)) == 0);
    int duplicate = dup(holder);
    require(duplicate >= 0 && close(holder) == 0);
    require(openat(directory, "alias", O_WRONLY | O_TRUNC | O_SHLOCK | O_NONBLOCK)
            == -1 && errno == EWOULDBLOCK);
    require(length(duplicate) == 4 && close(duplicate) == 0);
    int a = openat(directory, "alias", O_RDONLY | O_SHLOCK | O_NONBLOCK);
    int b = openat(directory, "data", O_RDONLY | O_SHLOCK | O_NONBLOCK);
    require(a >= 0 && b >= 0);
    require(openat(directory, "data", O_RDONLY | O_EXLOCK | O_NONBLOCK)
            == -1 && errno == EWOULDBLOCK);
    require(close(a) == 0 && close(b) == 0);
    int truncated = openat(directory, "data", O_WRONLY | O_EXLOCK | O_TRUNC | O_NONBLOCK);
    require(truncated >= 0 && length(truncated) == 0);
    require(write(truncated, "later", 5) == 5 && close(truncated) == 0);
    puts("open locks share vnode identity and protect truncation");
}

static void blocking_open(int directory) {
    int holder = openat(directory, "data", O_RDONLY | O_EXLOCK);
    int started[2];
    require(holder >= 0 && pipe(started) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(holder) == 0 && close(started[0]) == 0);
        require(openat(directory, "data", O_RDWR | O_TRUNC | O_EXLOCK | O_NONBLOCK)
                == -1 && errno == EWOULDBLOCK);
        require(write(started[1], "r", 1) == 1);
        int acquired = openat(directory, "data", O_RDWR | O_TRUNC | O_EXLOCK);
        require(acquired >= 0 && length(acquired) == 0);
        require(write(acquired, "done", 4) == 4 && close(acquired) == 0);
        _exit(0);
    }
    require(close(started[1]) == 0);
    char byte;
    require(read(started[0], &byte, 1) == 1 && byte == 'r');
    for (int i = 0; i < 32; ++i) {
        sched_yield();
    }
    int status;
    require(waitpid(child, &status, WNOHANG) == 0);
    require(length(holder) == 5 && close(holder) == 0 && close(started[0]) == 0);
    require(waitpid(child, &status, 0) == child && status == 0);
    int file = openat(directory, "data", O_RDONLY);
    char contents[4];
    require(file >= 0 && read(file, contents, sizeof contents) == (ssize_t)sizeof contents);
    require(contents[0] == 'd' && contents[1] == 'o' && contents[2] == 'n' && contents[3] == 'e');
    require(close(file) == 0);
    puts("blocking open truncates after the owner releases its lock");
}

static volatile sig_atomic_t interrupted;

static void catch_signal(int signal_number) {
    interrupted = signal_number;
}

static void interrupted_open(int directory) {
    int holder = openat(directory, "data", O_RDONLY | O_EXLOCK);
    int ready[2];
    require(holder >= 0 && pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        require(close(holder) == 0 && close(ready[0]) == 0);
        int vacant = dup(directory);
        require(vacant >= 0 && close(vacant) == 0);
        struct sigaction action = {.sa_handler = catch_signal};
        sigemptyset(&action.sa_mask);
        require(sigaction(SIGUSR1, &action, NULL) == 0);
        require(write(ready[1], "r", 1) == 1);
        require(openat(directory, "data", O_RDONLY | O_EXLOCK) == -1 && errno == EINTR);
        require(interrupted == SIGUSR1);
        int available = openat(directory, "data", O_RDONLY);
        require(available == vacant && close(available) == 0);
        _exit(0);
    }
    require(close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    struct timespec begin;
    require(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    int status = -1;
    pid_t finished;
    do {
        require(kill(child, SIGUSR1) == 0 || errno == ESRCH);
        sched_yield();
        finished = waitpid(child, &status, WNOHANG);
        struct timespec now;
        require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        require(finished >= 0 && now.tv_sec - begin.tv_sec < 10);
    } while (finished == 0);
    require(finished == child && status == 0);
    require(close(ready[0]) == 0 && close(holder) == 0);
    puts("interrupted open releases its reserved descriptor");
}

static void different_vnodes(const char *workspace, int directory) {
    require(flock(directory, LOCK_EX | LOCK_NB) == 0);
    require(open(workspace, O_RDONLY | O_SHLOCK | O_NONBLOCK) == -1 && errno == EWOULDBLOCK);
    require(flock(directory, LOCK_UN) == 0);
    int named = openat(directory, "data/..namedfork/rsrc", O_RDWR | O_CREAT | O_EXLOCK, 0600);
    require(named >= 0 && write(named, "fork", 4) == 4);
    int data = openat(directory, "data", O_RDONLY | O_EXLOCK | O_NONBLOCK);
    require(data >= 0);
    require(openat(directory, "alias/..namedfork/rsrc", O_WRONLY | O_EXLOCK | O_TRUNC | O_NONBLOCK)
            == -1 && errno == EWOULDBLOCK);
    require(length(named) == 4 && length(data) == 4 && close(named) == 0);
    named = openat(directory, "alias/..namedfork/rsrc", O_WRONLY | O_EXLOCK | O_TRUNC | O_NONBLOCK);
    require(named >= 0 && length(named) == 0 && length(data) == 4);
    require(close(named) == 0 && close(data) == 0);
    puts("directory and resource fork use their own open locks");
}

int main(int argc, char **argv) {
    require(argc == 2 && mkdir(argv[1], 0700) == 0);
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY);
    require(directory >= 0);
    int data = openat(directory, "data", O_WRONLY | O_CREAT | O_EXCL | O_EXLOCK, 0600);
    require(data >= 0 && write(data, "seed", 4) == 4 && close(data) == 0);
    require(linkat(directory, "data", directory, "alias", 0) == 0);
    conflicting_truncate(directory);
    blocking_open(directory);
    interrupted_open(directory);
    different_vnodes(argv[1], directory);
    require(unlinkat(directory, "alias", 0) == 0 && unlinkat(directory, "data", 0) == 0);
    require(close(directory) == 0 && rmdir(argv[1]) == 0);
    return 0;
}
