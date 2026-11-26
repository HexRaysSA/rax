#include <errno.h>
#include <fcntl.h>
#include <mach/machine.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#define ABI "arm64"
#else
#define ABI "x86_64"
#endif

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "child") == 0) {
        int inherited = fcntl(10, F_GETFD) == 0;
        int closed = fcntl(11, F_GETFD) == -1 && errno == EBADF;
        printf("child=%s inherited=%d closed=%d arg=%s\n", ABI, inherited, closed, argv[2]);
        return inherited && closed ? 17 : 91;
    }
    if (argc != 3) {
        return 90;
    }
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0 || dup2(fd, 10) != 10 || dup2(fd, 11) != 11 ||
        fcntl(11, F_SETFD, FD_CLOEXEC) != 0) {
        return 92;
    }
    close(fd);
    char *child[] = {argv[2], "child", "token", NULL};
    char *env[] = {"LC_ALL=C", NULL};
    if (strcmp(argv[1], "exec") == 0) {
        execve(argv[2], child, env);
        printf("exec_errno=%d\n", errno);
        return 93;
    }
    posix_spawnattr_t attrs;
    if (posix_spawnattr_init(&attrs) != 0) {
        return 94;
    }
    if (strcmp(argv[1], "prefer-arm64") == 0) {
        cpu_type_t preference = CPU_TYPE_ARM64;
        size_t count = 0;
        if (posix_spawnattr_setbinpref_np(&attrs, 1, &preference, &count) != 0 || count != 1) {
            return 95;
        }
    }
    pid_t pid;
    int error = posix_spawn(&pid, argv[2], NULL, &attrs, child, env);
    posix_spawnattr_destroy(&attrs);
    if (error != 0) {
        printf("spawn_error=%d\n", error);
        return 96;
    }
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        return 97;
    }
    printf("wait=%d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status) == 17 ? 0 : 98;
}
