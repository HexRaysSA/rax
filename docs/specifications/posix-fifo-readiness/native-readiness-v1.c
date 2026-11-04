#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

static int ready(int fd) {
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(fd, &reads);
    struct timeval timeout = {0, 0};
    return select(fd + 1, &reads, NULL, NULL, &timeout);
}

int main(void) {
    char path[4096];
    const char *temporary = getenv("TMPDIR");
    if (temporary == NULL) return 2;
    int length = snprintf(path, sizeof(path), "%s/rax-fifo-native-readiness-%ld", temporary, (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(path)) return 3;
    if (mkfifo(path, 0600) != 0) return 4;
    int reader = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (reader < 0 || reader >= FD_SETSIZE) return 5;
    int writer = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (writer < 0) return 6;
    if (unlink(path) != 0 || close(writer) != 0) return 7;
    int before = ready(reader);
    unsigned char value = 0;
    ssize_t count = read(reader, &value, 1);
    int after = ready(reader);
    printf("{\"before_eof_read\":%d,\"read_result\":%ld,\"after_eof_read\":%d}\n", before, (long)count, after);
    return close(reader) == 0 ? 0 : 8;
}
