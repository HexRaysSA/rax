#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int lock_call(const char *label, int fd, int command, short type,
                     short whence, off_t start, off_t length, pid_t expected_owner) {
    struct flock lock = { .l_type = type, .l_whence = whence, .l_start = start,
                          .l_len = length, .l_pid = INT_MIN };
    errno = 0;
    int result = fcntl(fd, command, &lock);
    int error = errno;
    printf("%s rc=%d errno=%d type=%d whence=%d start=%lld len=%lld pid=%d\n",
           label, result, error, lock.l_type, lock.l_whence, lock.l_start,
           lock.l_len, lock.l_pid == expected_owner ? -2 : lock.l_pid);
    return result;
}

static void child_checks(int fd, int alias, pid_t parent, const char *phase) {
    if (fflush(stdout)) exit(20);
    pid_t child = fork();
    if (child < 0) exit(21);
    if (child == 0) {
        puts(phase);
        lock_call("query-range", alias, F_GETLK, F_WRLCK, SEEK_SET, 0, 0, parent);
        lock_call("query-tail", alias, F_GETLK, F_RDLCK, SEEK_SET, LLONG_MAX, 1, parent);
        lock_call("query-unlock", alias, F_GETLK, F_UNLCK, SEEK_SET, 0, 0, parent);
        lock_call("overlap-read", fd, F_SETLK, F_RDLCK, SEEK_SET, 14, 2, parent);
        lock_call("disjoint-write", fd, F_SETLK, F_WRLCK, SEEK_SET, 30, 3, parent);
        if (fflush(stdout)) _exit(22);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || status != 0) exit(23);
}

static int ranges(const char *path) {
    char alias_path[PATH_MAX];
    int length = snprintf(alias_path, sizeof(alias_path), "%s.link", path);
    if (length < 0 || (size_t)length >= sizeof(alias_path)) return 3;
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, 64) || link(path, alias_path)) return 4;
    int alias = open(alias_path, O_RDONLY);
    int writer = open(alias_path, O_WRONLY);
    int dupfd = dup(fd);
    if (alias < 0 || writer < 0 || dupfd < 0 || lseek(fd, 16, SEEK_SET) != 16) return 5;
    pid_t parent = getpid();
    lock_call("empty-set", fd, F_GETLK, F_WRLCK, SEEK_SET, 0, 0, parent);
    lock_call("empty-cur", fd, F_GETLK, F_WRLCK, SEEK_CUR, -1, 2, parent);
    lock_call("empty-end", fd, F_GETLK, F_RDLCK, SEEK_END, -4, 2, parent);
    lock_call("empty-end-negative", fd, F_GETLK, F_WRLCK, SEEK_END, -65, 1, parent);
    lock_call("empty-end-overflow", fd, F_GETLK, F_WRLCK, SEEK_END, LLONG_MAX, 1, parent);
    lock_call("empty-unlock-end", fd, F_SETLK, F_UNLCK, SEEK_END, -65, 1, parent);
    lock_call("empty-unlock-whence", fd, F_SETLK, F_UNLCK, 99, 0, 1, parent);
    lock_call("empty-unlock-set", fd, F_SETLK, F_UNLCK, SEEK_SET, -1, 1, parent);
    lock_call("invalid-mode", fd, F_SETLK, 7, SEEK_SET, 0, 5, parent);
    lock_call("invalid-whence", fd, F_SETLK, F_WRLCK, 99, 0, 5, parent);
    lock_call("negative-start", fd, F_SETLK, F_WRLCK, SEEK_SET, -1, 5, parent);
    lock_call("overflow-end", fd, F_SETLK, F_WRLCK, SEEK_SET, LLONG_MAX, 2, parent);
    lock_call("write-read-only", alias, F_SETLK, F_WRLCK, SEEK_SET, 0, 5, parent);
    lock_call("read-write-only", writer, F_SETLK, F_RDLCK, SEEK_SET, 0, 5, parent);
    lock_call("parent-write", fd, F_SETLK, F_WRLCK, SEEK_CUR, 4, -8, parent);
    lock_call("parent-adjacent", fd, F_SETLK, F_WRLCK, SEEK_SET, 20, 2, parent);
    lock_call("parent-tail", fd, F_SETLK, F_WRLCK, SEEK_SET, LLONG_MAX - 2, 0, parent);
    lock_call("parent-tail-subrange", fd, F_SETLK, F_WRLCK, SEEK_SET, LLONG_MAX - 1, 2, parent);
    lock_call("held-end-negative", fd, F_GETLK, F_WRLCK, SEEK_END, -65, 1, parent);
    lock_call("held-end-overflow", fd, F_GETLK, F_WRLCK, SEEK_END, LLONG_MAX, 1, parent);
    lock_call("held-unlock-end", fd, F_SETLK, F_UNLCK, SEEK_END, -65, 1, parent);
    lock_call("held-unlock-whence", fd, F_SETLK, F_UNLCK, 99, 0, 1, parent);
    lock_call("query-self", dupfd, F_GETLK, F_WRLCK, SEEK_SET, 0, 0, parent);
    child_checks(fd, alias, parent, "parent-lock");
    lock_call("parent-split", fd, F_SETLK, F_UNLCK, SEEK_SET, 13, 1, parent);
    child_checks(fd, alias, parent, "after-split");
    if (close(dupfd)) return 6;
    child_checks(fd, alias, parent, "after-duplicate-close");
    if (close(fd) || close(alias) || close(writer) || unlink(path) || unlink(alias_path)) return 7;
    return 0;
}

static int wait_ok(pid_t child) {
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && status == 0;
}

static int file_lock(int fd, int command, pid_t owner) {
    struct flock lock = { .l_whence = SEEK_SET, .l_type = F_WRLCK, .l_start = 4, .l_len = 12 };
    if (fcntl(fd, command, &lock)) return 30;
    if (command == F_GETLK) {
        printf("type=%d owner=%s start=%lld len=%lld\n", lock.l_type,
               lock.l_pid == owner ? "parent" : "none", lock.l_start, lock.l_len);
        if (fflush(stdout)) return 31;
    }
    return 0;
}

static int begin(const char *image, const char *mode, const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    int alias = dup(fd);
    int sync[2];
    if (fd < 0 || alias < 0 || pipe(sync) || file_lock(fd, F_SETLK, 0)) return 3;
    if ((!strcmp(mode, "cloexec-high") || !strcmp(mode, "cloexec-all"))
        && fcntl(alias, F_SETFD, FD_CLOEXEC)) return 4;
    if ((!strcmp(mode, "cloexec-low") || !strcmp(mode, "cloexec-all"))
        && fcntl(fd, F_SETFD, FD_CLOEXEC)) return 4;
    pid_t owner = getpid();
    pid_t child = fork();
    if (child < 0) return 5;
    if (child == 0) {
        char byte;
        if (close(sync[1]) || read(sync[0], &byte, 1) != 1) _exit(6);
        printf("%s ", mode);
        _exit(file_lock(fd, F_GETLK, owner));
    }
    if (close(sync[0])) return 7;
    char writer[32], child_id[32], fd_id[32], alias_id[32];
    snprintf(writer, sizeof(writer), "%d", sync[1]);
    snprintf(child_id, sizeof(child_id), "%d", child);
    snprintf(fd_id, sizeof(fd_id), "%d", fd);
    snprintf(alias_id, sizeof(alias_id), "%d", alias);
    char *const after[] = {(char *)image, "--after", writer, child_id, fd_id, alias_id, NULL};
    if (!strncmp(mode, "spawn-", 6)) {
        posix_spawnattr_t attrs;
        posix_spawn_file_actions_t actions;
        int selective = !strncmp(mode, "spawn-select-", 13);
        short flags = POSIX_SPAWN_SETEXEC;
        if (selective) flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
        if (posix_spawnattr_init(&attrs) || posix_spawnattr_setflags(&attrs, flags)
            || posix_spawn_file_actions_init(&actions)) return 8;
        if (selective) {
            int survivor = !strcmp(mode, "spawn-select-low") ? fd : alias;
            if (posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO)
                || posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO)
                || posix_spawn_file_actions_addinherit_np(&actions, sync[1])
                || posix_spawn_file_actions_addinherit_np(&actions, survivor)) return 8;
        } else {
            if (posix_spawn_file_actions_addclose(&actions, alias)) return 8;
            int action = !strcmp(mode, "spawn-close-all")
                ? posix_spawn_file_actions_addclose(&actions, fd)
                : posix_spawn_file_actions_adddup2(&actions, fd, alias);
            if (action) return 8;
        }
        int error = posix_spawn(NULL, image, &actions, &attrs, after, environ);
        fprintf(stderr, "posix_spawn returned %d\n", error);
        return 9;
    }
    execv(image, after);
    perror("execv");
    return 10;
}

int main(int argc, char **argv) {
    if (argc == 6 && !strcmp(argv[1], "--after")) {
        int writer = atoi(argv[2]);
        pid_t child = atoi(argv[3]);
        printf("after fd=%s alias=%s\n", fcntl(atoi(argv[4]), F_GETFD) == -1 ? "closed" : "open",
               fcntl(atoi(argv[5]), F_GETFD) == -1 ? "closed" : "open");
        if (fflush(stdout)) return 12;
        return write(writer, "!", 1) != 1 || close(writer) || !wait_ok(child);
    }
    if (argc != 2) return 1;
    int result = ranges(argv[1]);
    if (result) return result;
    const char *modes[] = {"keep", "cloexec-high", "cloexec-low", "cloexec-all",
                           "spawn-close-and-restore", "spawn-close-all",
                           "spawn-select-low", "spawn-select-high"};
    for (size_t phase = 0; phase < sizeof(modes) / sizeof(modes[0]); ++phase) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s.%zu", argv[1], phase);
        if (n < 0 || (size_t)n >= sizeof(path)) return 2;
        pid_t child = fork();
        if (child == 0) _exit(begin(argv[0], modes[phase], path));
        if (!wait_ok(child) || unlink(path)) return 11;
    }
    return 0;
}
