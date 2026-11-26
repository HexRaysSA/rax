#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

extern int __mac_syscall(const char *, int, void *);

static int check_closed_policy(const char *host_executable)
{
    uint64_t output = 0;
    struct {
        uint64_t input;
        uint64_t *output;
    } request = { 0, &output };
    if (__mac_syscall("AMFI", 0x5a, &request) != 0 || output != 1)
        return 1;
    request.input = UINT64_MAX;
    if (__mac_syscall("AMFI", 0x5a, &request) != 0 || output != 0)
        return 1;
    request.output = NULL;
    if (__mac_syscall("AMFI", 0x5a, &request) != -1 || errno != EFAULT)
        return 1;
    if (__mac_syscall("Sandbox", 2, &request) != -1 || errno != EPERM)
        return 1;
    int fd = open(host_executable, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return errno != ENOENT;
}

int main(int argc, char **argv)
{
    if (argc == 2 && check_closed_policy(argv[1]) != 0) {
        fputs("closed dyld policy or filesystem check failed\n", stderr);
        return 1;
    }
    int found = dlsym(RTLD_DEFAULT, "perl_alloc") != NULL;
    printf("resolved installed perl_alloc: %d\n", found);
    return found ? 0 : 1;
}
