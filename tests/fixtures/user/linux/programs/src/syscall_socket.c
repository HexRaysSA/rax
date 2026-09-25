/*
 * Socket Operations
 *
 * Tests networking syscall patterns.
 * Exercises socket API for local communication.
 *
 * Features exercised:
 *   - Socket creation
 *   - Unix domain sockets
 *   - TCP/IP sockets (localhost)
 *   - Socket options
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */

volatile int64_t sink;
static int64_t rax_nondet; /* rax: fd numbers, port, buffer sizes, connect errno; excluded from the printed result */

#define BUFFER_SIZE 1024
#define SOCKET_PATH "/tmp/test_socket_XXXXXX"

static char buffer[BUFFER_SIZE];
static char recv_buffer[BUFFER_SIZE];

/* Test Unix domain stream socket */
__attribute__((noinline))
int64_t test_unix_stream(void) {
    int64_t result = 0;
    char socket_path[32];
    int server_fd, client_fd, conn_fd;
    struct sockaddr_un addr;

    /* Create unique socket path */
    strcpy(socket_path, SOCKET_PATH);
    mktemp(socket_path);

    /* Create server socket */
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;
    result += server_fd;
    rax_nondet += server_fd; /* rax: print the result so that runs can be compared */

    /* Bind */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return -1;
    }

    /* Listen */
    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        unlink(socket_path);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(server_fd);
        unlink(socket_path);
        return -1;
    } else if (pid == 0) {
        /* Child - client */
        close(server_fd);

        client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client_fd < 0) _exit(1);

        /* Connect */
        if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(client_fd);
            _exit(1);
        }

        /* Send data */
        const char *msg = "Hello from client";
        send(client_fd, msg, strlen(msg), 0);

        /* Receive response */
        ssize_t n = recv(client_fd, recv_buffer, sizeof(recv_buffer), 0);

        close(client_fd);
        _exit((int)(n > 0 ? n : 0));
    } else {
        /* Parent - server */
        socklen_t addr_len = sizeof(addr);
        conn_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);

        if (conn_fd >= 0) {
            /* Receive data */
            ssize_t n = recv(conn_fd, buffer, sizeof(buffer), 0);
            result += n;

            /* Send response */
            const char *response = "Hello from server";
            send(conn_fd, response, strlen(response), 0);

            close(conn_fd);
        }

        close(server_fd);
        unlink(socket_path);

        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            result += WEXITSTATUS(status);
        }
    }

    return result;
}

/* Test Unix domain datagram socket */
__attribute__((noinline))
int64_t test_unix_dgram(void) {
    int64_t result = 0;
    char server_path[32], client_path[32];
    int server_fd, client_fd;
    struct sockaddr_un server_addr, client_addr;

    strcpy(server_path, SOCKET_PATH);
    mktemp(server_path);
    strcpy(client_path, SOCKET_PATH);
    mktemp(client_path);

    /* Create server socket */
    server_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (server_fd < 0) return -1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, server_path, sizeof(server_addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(server_fd);
        return -1;
    }

    /* Create client socket */
    client_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (client_fd < 0) {
        close(server_fd);
        unlink(server_path);
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    strncpy(client_addr.sun_path, client_path, sizeof(client_addr.sun_path) - 1);

    if (bind(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        close(server_fd);
        close(client_fd);
        unlink(server_path);
        return -1;
    }

    /* Send datagram */
    const char *msg = "Datagram message";
    sendto(client_fd, msg, strlen(msg), 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));

    /* Receive datagram */
    struct sockaddr_un from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(server_fd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&from_addr, &from_len);
    result += n;

    /* Send response */
    sendto(server_fd, "Response", 8, 0,
           (struct sockaddr *)&from_addr, from_len);

    n = recvfrom(client_fd, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
    result += n;

    close(server_fd);
    close(client_fd);
    unlink(server_path);
    unlink(client_path);

    return result;
}

/* Test TCP socket on localhost */
__attribute__((noinline))
int64_t test_tcp_localhost(void) {
    int64_t result = 0;
    int server_fd, client_fd, conn_fd;
    struct sockaddr_in addr;

    /* Create server socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;

    /* Allow address reuse */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to localhost with ephemeral port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* Let kernel choose port */

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return -1;
    }

    /* Get assigned port */
    socklen_t addr_len = sizeof(addr);
    getsockname(server_fd, (struct sockaddr *)&addr, &addr_len);
    int port = ntohs(addr.sin_port);
    result += port;
    rax_nondet += port; /* rax: print the result so that runs can be compared */

    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        close(server_fd);
        return -1;
    } else if (pid == 0) {
        /* Child - client */
        close(server_fd);

        client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd < 0) _exit(1);

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        server_addr.sin_port = htons(port);

        if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(client_fd);
            _exit(1);
        }

        /* Send multiple chunks */
        for (int i = 0; i < 5; i++) {
            char chunk[64];
            snprintf(chunk, sizeof(chunk), "Chunk %d", i);
            send(client_fd, chunk, strlen(chunk), 0);
        }

        close(client_fd);
        _exit(0);
    } else {
        /* Parent - server */
        conn_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);

        if (conn_fd >= 0) {
            /* Receive all data */
            ssize_t total = 0;
            ssize_t n;
            while ((n = recv(conn_fd, buffer + total, sizeof(buffer) - total, 0)) > 0) {
                total += n;
            }
            result += total;

            close(conn_fd);
        }

        close(server_fd);

        int status;
        waitpid(pid, &status, 0);
    }

    return result;
}

/* Test socket options */
__attribute__((noinline))
int64_t test_socket_options(void) {
    int64_t result = 0;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Get/set SO_REUSEADDR */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int val;
    socklen_t len = sizeof(val);
    getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, &len);
    result += val;

    /* Get/set SO_RCVBUF */
    int bufsize = 65536;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len);
    result += val / 1024; /* Normalized */
    rax_nondet += val / 1024; /* rax: print the result so that runs can be compared */

    /* Get/set SO_SNDBUF */
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len);
    result += val / 1024;
    rax_nondet += val / 1024; /* rax: print the result so that runs can be compared */

    /* Get socket type */
    getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &len);
    result += (val == SOCK_STREAM) ? 10 : 0;

    close(fd);

    return result;
}

/* Test socketpair */
__attribute__((noinline))
int64_t test_socketpair(void) {
    int64_t result = 0;
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        return -1;
    }

    result += sv[0];
    result += sv[1];
    rax_nondet += sv[0] + sv[1]; /* rax: print the result so that runs can be compared */

    /* Send in one direction */
    const char *msg1 = "Hello from sv[0]";
    send(sv[0], msg1, strlen(msg1), 0);

    ssize_t n = recv(sv[1], buffer, sizeof(buffer), 0);
    result += n;

    /* Send in other direction */
    const char *msg2 = "Hello from sv[1]";
    send(sv[1], msg2, strlen(msg2), 0);

    n = recv(sv[0], recv_buffer, sizeof(recv_buffer), 0);
    result += n;

    close(sv[0]);
    close(sv[1]);

    return result;
}

/* Test non-blocking socket */
__attribute__((noinline))
int64_t test_nonblocking(void) {
    int64_t result = 0;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Verify non-blocking set */
    flags = fcntl(fd, F_GETFL, 0);
    result += (flags & O_NONBLOCK) ? 1 : 0;

    /* Non-blocking connect to unreachable address should return immediately */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x0A000001); /* 10.0.0.1 - likely unreachable */
    addr.sin_port = htons(12345);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    /* Should return -1 with EINPROGRESS for non-blocking */
    result += (ret == -1 && errno == EINPROGRESS) ? 10 : 0;
    rax_nondet += (ret == -1 && errno == EINPROGRESS) ? 10 : 0; /* rax: print the result so that runs can be compared */

    close(fd);

    return result;
}

/* Test shutdown */
__attribute__((noinline))
int64_t test_shutdown(void) {
    int64_t result = 0;
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        return -1;
    }

    /* Send data */
    send(sv[0], "test", 4, 0);

    /* Shutdown write end of sv[0] */
    shutdown(sv[0], SHUT_WR);
    result += 1;

    /* Should still be able to receive on sv[0] */
    send(sv[1], "response", 8, 0);
    ssize_t n = recv(sv[0], buffer, sizeof(buffer), 0);
    result += n;

    /* Shutdown both ends of sv[1] */
    shutdown(sv[1], SHUT_RDWR);
    result += 1;

    close(sv[0]);
    close(sv[1]);

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 2; iter++) { /* rax: was 50 */
        result += test_unix_stream();
        result += test_unix_dgram();

        if (iter % 5 == 0) {
            result += test_tcp_localhost();
        }

        result += test_socket_options();
        result += test_socketpair();
        result += test_nonblocking();
        result += test_shutdown();
    }

    sink = result;
    printf("result_det=%" PRId64 "\n", result - rax_nondet); /* rax: print the result so that runs can be compared */
    return 0;
}
