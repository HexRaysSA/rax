#include <errno.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

static const int message_id = 0x524158;
static name_t service = "org.rax.fixture.bootstrap.parent";
static name_t transient = "org.rax.fixture.bootstrap.child";

static mach_port_t make_service(void) {
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS ||
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    return port;
}

static bool absent(mach_port_t bootstrap, name_t name) {
    mach_port_t found = MACH_PORT_NULL;
    int status = bootstrap_look_up(bootstrap, name, &found);
    if (status != BOOTSTRAP_UNKNOWN_SERVICE || found != MACH_PORT_NULL) {
        fprintf(stderr, "expected absent service, got status %d and port %u\n", status, found);
        return false;
    }
    return true;
}

static int child(void) {
    mach_port_t bootstrap = MACH_PORT_NULL, found = MACH_PORT_NULL;
    int special_status = task_get_bootstrap_port(mach_task_self(), &bootstrap);
    int lookup_status = bootstrap == MACH_PORT_NULL ? -1 : bootstrap_look_up(bootstrap, service, &found);
    if (special_status != KERN_SUCCESS || lookup_status != KERN_SUCCESS || found == MACH_PORT_NULL) {
        fprintf(stderr, "child bootstrap: special=%d bootstrap=%u lookup=%d service=%u\n",
                special_status, bootstrap, lookup_status, found);
        return 10;
    }
    mach_msg_header_t msg = {
        .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
        .msgh_size = sizeof(msg),
        .msgh_remote_port = found,
        .msgh_id = message_id,
    };
    if (mach_msg(&msg, MACH_SEND_MSG, msg.msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL) != KERN_SUCCESS) {
        return 11;
    }
    mach_port_t child_port = make_service();
    if (child_port == MACH_PORT_NULL || bootstrap_register(bootstrap, transient, child_port) != KERN_SUCCESS) {
        return 12;
    }
    return 0;
}

static bool wait_for_service(pid_t pid, mach_port_t port, const char *mode, int event_queue) {
    if (pid < 0) {
        return false;
    }
    if (event_queue >= 0) {
        struct kevent64_s ready;
        if (kevent64(event_queue, NULL, 0, &ready, 1, 0, NULL) != 1 ||
            ready.filter != EVFILT_MACHPORT || ready.ident != port || ready.data != port) {
            return false;
        }
    }
    struct {
        mach_msg_header_t hdr;
        mach_msg_max_trailer_t trailer;
    } incoming;
    // The child sends after resolving the named endpoint. The parent blocks on
    // the receive right before it waits for the child process to exit.
    if (mach_msg(&incoming.hdr, MACH_RCV_MSG, 0, sizeof(incoming),
                 port, 0, MACH_PORT_NULL) != KERN_SUCCESS || incoming.hdr.msgh_id != message_id) {
        return false;
    }
    int status = -1;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "%s service client exit: %d\n", mode, status);
        return false;
    }
    return true;
}

static bool guest_kevent_only(void) {
    int queue = kqueue();
    if (queue < 0) {
        perror("guest kqueue");
        return false;
    }
    struct kevent change, event = {0};
    const struct timespec zero = {0, 0};
    EV_SET(&change, getpid(), EVFILT_PROC, EV_ADD | EV_RECEIPT, NOTE_EXIT, 0, NULL);
    int received = kevent(queue, &change, 1, &event, 1, &zero);
    if (received != 1 || !(event.flags & EV_ERROR) || event.data != EPERM) {
        fprintf(stderr, "unexpected process-filter receipt: %d, flags=%u, data=%lld\n",
                received, event.flags, (long long)event.data);
        close(queue);
        return false;
    }
    EV_SET(&change, 7, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(queue, &change, 1, &event, 1, &zero) != 0) {
        perror("register guest user filter");
        close(queue);
        return false;
    }
    EV_SET(&change, 7, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    bool passed = kevent(queue, &change, 1, &event, 1, &zero) == 1 &&
                  event.filter == EVFILT_USER && event.ident == 7 &&
                  kevent(queue, NULL, 0, &event, 1, &zero) == 0;
    return close(queue) == 0 && passed;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "child") == 0) {
        return child();
    }
    if (!guest_kevent_only()) {
        fputs("legacy guest kqueue or host process-filter boundary failed\n", stderr);
        return 13;
    }
    mach_port_t bootstrap = MACH_PORT_NULL, found = MACH_PORT_NULL;
    if (task_get_bootstrap_port(mach_task_self(), &bootstrap) != KERN_SUCCESS ||
        bootstrap == MACH_PORT_NULL || !absent(bootstrap, service)) {
        return 1;
    }
    mach_port_t port = make_service();
    if (port == MACH_PORT_NULL || bootstrap_register(bootstrap, service, port) != KERN_SUCCESS ||
        bootstrap_look_up(bootstrap, service, &found) != KERN_SUCCESS || found != port) {
        return 2;
    }
    if (bootstrap_register(bootstrap, service, port) != BOOTSTRAP_NAME_IN_USE) {
        return 3;
    }
    int event_queue = kqueue();
    struct kevent64_s change, ready;
    const struct timespec zero = {0, 0};
    EV_SET64(&change, port, EVFILT_MACHPORT, EV_ADD, 0, 0, 0, 0, 0);
    if (event_queue < 0 || kevent64(event_queue, &change, 1, &ready, 1, 0, &zero) != 0) {
        perror("register Mach port with kqueue");
        return 9;
    }
    pid_t pid;
    char child_flag[] = "child";
    char *child_argv[] = {argv[0], child_flag, NULL};
    char *child_env[] = {NULL};
    int spawn_error = posix_spawn(&pid, argv[0], NULL, NULL, child_argv, child_env);
    if (spawn_error || !wait_for_service(pid, port, "spawned", event_queue) || !absent(bootstrap, transient)) {
        fprintf(stderr, "posix_spawn error: %d\n", spawn_error);
        return 4;
    }
    close(event_queue);
    pid = fork();
    if (pid == 0) {
        _exit(child());
    }
    if (!wait_for_service(pid, port, "forked", -1) || !absent(bootstrap, transient)) {
        return 5;
    }
    if (mach_port_destroy(mach_task_self(), port) != KERN_SUCCESS || !absent(bootstrap, service)) {
        return 7;
    }
    mach_port_t replacement = make_service();
    if (replacement == MACH_PORT_NULL || bootstrap_register(bootstrap, service, replacement) != KERN_SUCCESS) {
        return 8;
    }
    puts("guest bootstrap registration, inherited lookup and port delivery passed");
    return 0;
}
