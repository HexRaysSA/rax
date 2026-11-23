#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void require_at(int condition, int line, const char *expression) {
    if (!condition) {
        fprintf(stderr, "spawn open locking line %d: %s (errno %d)\n", line, expression, errno);
        _exit(2);
    }
}
#define require(expression) require_at((expression), __LINE__, #expression)

static off_t length(int fd) {
    struct stat st;
    require(fstat(fd, &st) == 0);
    return st.st_size;
}

static int spawn_locked(const char *image, const char *data, const char *marker,
                        int flags, pid_t *child) {
    posix_spawn_file_actions_t actions;
    require(posix_spawn_file_actions_init(&actions) == 0);
    if (marker != NULL) {
        require(posix_spawn_file_actions_addopen(
                    &actions, 8, marker, O_WRONLY | O_CREAT | O_EXCL, 0600) == 0);
    }
    require(posix_spawn_file_actions_addopen(&actions, 9, data, flags, 0600) == 0);
    char *const arguments[] = {(char *)image, "--child", (char *)data, NULL};
    int result = posix_spawn(child, image, &actions, NULL, arguments, environ);
    require(posix_spawn_file_actions_destroy(&actions) == 0);
    return result;
}

static void child_status(pid_t child) {
    int status;
    require(waitpid(child, &status, 0) == child && status == 0);
}

static int locked_file(const char *data) {
    int holder = open(data, O_RDWR | O_CREAT | O_TRUNC, 0600);
    require(holder >= 0 && write(holder, "retained", 8) == 8);
    require(flock(holder, LOCK_EX | LOCK_NB) == 0);
    return holder;
}

static void nonblocking(const char *image, const char *data) {
    int holder = locked_file(data);
    int flags = O_RDWR | O_EXLOCK | O_NONBLOCK | O_TRUNC;
    pid_t child;
    require(spawn_locked(image, data, NULL, flags, &child) == EWOULDBLOCK);
    require(length(holder) == 8 && flock(holder, LOCK_UN) == 0);
    require(spawn_locked(image, data, NULL, flags, &child) == 0);
    child_status(child);
    require(length(holder) == 0 && close(holder) == 0);
    puts("spawn open reports a nonblocking conflict and preserves truncation order");
}

static volatile sig_atomic_t interrupted;

static void catch_signal(int number) {
    interrupted = number;
}

static int before_deadline(struct timespec begin) {
    struct timespec now;
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return now.tv_sec - begin.tv_sec < 10;
}

static void blocking(const char *image, const char *data, const char *marker, int signal_it) {
    int holder = locked_file(data);
    pid_t launcher = fork();
    require(launcher >= 0);
    if (launcher == 0) {
        require(close(holder) == 0);
        if (signal_it) {
            struct sigaction action = {.sa_handler = catch_signal};
            sigemptyset(&action.sa_mask);
            require(sigaction(SIGUSR1, &action, NULL) == 0);
        }
        pid_t child;
        int result = spawn_locked(image, data, marker, O_RDWR | O_EXLOCK | O_TRUNC, &child);
        if (signal_it) {
            require(result == EINTR && interrupted == SIGUSR1);
        } else {
            require(result == 0);
            child_status(child);
        }
        _exit(0);
    }

    struct timespec begin;
    require(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    while (access(marker, F_OK) != 0) {
        require(errno == ENOENT && before_deadline(begin));
        sched_yield();
    }
    for (int i = 0; i < 32; ++i) {
        sched_yield();
    }
    int status;
    require(waitpid(launcher, &status, WNOHANG) == 0 && length(holder) == 8);
    if (signal_it) {
        pid_t finished;
        do {
            require(kill(launcher, SIGUSR1) == 0 || errno == ESRCH);
            sched_yield();
            finished = waitpid(launcher, &status, WNOHANG);
            require(finished >= 0 && before_deadline(begin));
        } while (finished == 0);
        require(finished == launcher && status == 0 && length(holder) == 8);
        puts("interrupted spawn leaves the locked file untruncated");
    } else {
        require(flock(holder, LOCK_UN) == 0);
        child_status(launcher);
        require(length(holder) == 0);
        puts("blocking spawn preserves earlier actions and passes the lock to its child");
    }
    require(close(holder) == 0 && unlink(marker) == 0);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--child") == 0) {
        require(length(9) == 0);
        int other = open(argv[2], O_RDONLY);
        require(other >= 0 && flock(other, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
        require(close(other) == 0);
        return 0;
    }

    require(argc == 2 && mkdir(argv[1], 0700) == 0);
    char data[PATH_MAX], marker[PATH_MAX];
    int data_length = snprintf(data, sizeof data, "%s/data", argv[1]);
    int marker_length = snprintf(marker, sizeof marker, "%s/marker", argv[1]);
    require(data_length > 0 && (size_t)data_length < sizeof data);
    require(marker_length > 0 && (size_t)marker_length < sizeof marker);
    nonblocking(argv[0], data);
    blocking(argv[0], data, marker, 0);
    blocking(argv[0], data, marker, 1);
    require(unlink(data) == 0 && rmdir(argv[1]) == 0);
    return 0;
}
