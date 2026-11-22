#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    const char payload[] = "guest pipe through installed libc";
    char received[sizeof(payload)];
    int fds[2], queued = 0;
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
        perror("pipe2");
        return 1;
    }
    if (fcntl(fds[0], F_GETFD) != FD_CLOEXEC ||
        fcntl(fds[1], F_GETFD) != FD_CLOEXEC)
        return 2;
    if (read(fds[0], received, sizeof(received)) != -1 || errno != EAGAIN)
        return 3;
    if (write(fds[1], payload, sizeof(payload)) != (ssize_t)sizeof(payload) ||
        ioctl(fds[1], FIONREAD, &queued) == -1 || queued != (int)sizeof(payload))
        return 4;
    if (close(fds[1]) == -1)
        return 5;
    struct pollfd ready = {.fd = fds[0], .events = POLLIN};
    if (poll(&ready, 1, 0) != 1 || ready.revents != (POLLIN | POLLHUP))
        return 6;
    if (read(fds[0], received, sizeof(received)) != (ssize_t)sizeof(received) ||
        memcmp(payload, received, sizeof(payload)) != 0 ||
        read(fds[0], received, sizeof(received)) != 0)
        return 7;
    if (close(fds[0]) == -1 || pipe(fds) == -1 ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR || close(fds[0]) == -1 ||
        write(fds[1], payload, sizeof(payload)) != -1 || errno != EPIPE ||
        close(fds[1]) == -1)
        return 8;
    puts(received);
    return 0;
}
