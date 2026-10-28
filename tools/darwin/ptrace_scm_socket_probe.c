/* Probe socket rights in flight while unrelated Unix sockets close.
 * xcrun --sdk macosx clang -isysroot "$(xcrun --show-sdk-path)" -O2 -Wall -pthread
 *   tools/darwin/ptrace_scm_socket_probe.c -o /tmp/ptrace-scm-probe
 * /tmp/ptrace-scm-probe [retain]
 * With retain, the sender keeps its descriptor until recvmsg completes.
 */
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static atomic_int running = 1;

static void *churn(void *unused) {
    (void)unused;
    while (atomic_load(&running)) {
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0) {
            close(sockets[0]);
            close(sockets[1]);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "retain"))) return 2;
    int retain = argc == 2;
    signal(SIGPIPE, SIG_IGN);
    pthread_t thread;
    if (pthread_create(&thread, NULL, churn, NULL)) return 2;
    int failures = 0, write_failed = 0, eof = 0, read_failed = 0;
    for (int i = 0; i < 10000; i++) {
        int carrier[2], data[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, carrier) ||
            socketpair(AF_UNIX, SOCK_STREAM, 0, data)) return 2;
        char byte = 'x';
        struct iovec vec = { &byte, 1 };
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
        struct msghdr message = {0};
        message.msg_iov = &vec;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &data[0], sizeof(int));
        if (sendmsg(carrier[0], &message, 0) != 1) return 2;
        if (!retain) close(data[0]);
        memset(control.bytes, 0, sizeof(control.bytes));
        message.msg_controllen = sizeof(control.bytes);
        if (recvmsg(carrier[1], &message, 0) != 1) return 2;
        header = CMSG_FIRSTHDR(&message);
        if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len != CMSG_LEN(sizeof(int))) return 2;
        int received;
        memcpy(&received, CMSG_DATA(header), sizeof(received));
        if (retain) close(data[0]);
        struct timeval timeout = { 0, 100000 };
        if (setsockopt(received, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 2;
        ssize_t written = write(data[1], &byte, 1);
        ssize_t read_count = read(received, &byte, 1);
        write_failed += written != 1;
        eof += read_count == 0;
        read_failed += read_count < 0;
        failures += written != 1 || read_count != 1;
        close(received);
        close(data[1]);
        close(carrier[0]);
        close(carrier[1]);
    }
    atomic_store(&running, 0);
    pthread_join(thread, NULL);
    printf("retained=%d iterations=10000 failures=%d write_failed=%d eof=%d read_failed=%d\n",
           retain, failures, write_failed, eof, read_failed);
    return failures != 0;
}
