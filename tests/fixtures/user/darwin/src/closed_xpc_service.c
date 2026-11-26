// Compile twice with and without RAX_XPC_SERVICE. The application and its
// service use the installed libxpc in both native and closed-guest runs.
#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define SERVICE_NAME "org.rax.validation.GuestEcho"

#if RAX_XPC_SERVICE
static void accept_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t request) {
        if (xpc_get_type(request) != XPC_TYPE_DICTIONARY) {
            return;
        }
        const char *text = xpc_dictionary_get_string(request, "text");
        xpc_object_t reply = xpc_dictionary_create_reply(request);
        if (text && reply) {
            const char *name = getenv("XPC_SERVICE_NAME");
            const char *environment = getenv("RAX_XPC_FIXTURE_VALUE");
            xpc_dictionary_set_string(reply, "echo", text);
            xpc_dictionary_set_int64(reply, "pid", getpid());
            xpc_dictionary_set_int64(reply, "ppid", getppid());
            xpc_dictionary_set_bool(reply, "service_identity",
                                    name && strcmp(name, SERVICE_NAME) == 0);
            xpc_dictionary_set_bool(reply, "service_environment",
                                    environment && strcmp(environment, "supplied by service manifest") == 0);
            xpc_connection_send_message(peer, reply);
        }
        if (reply) {
            xpc_release(reply);
        }
    });
    xpc_connection_resume(peer);
}

int main(void) {
    xpc_main(accept_peer);
}
#else
int main(void) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    xpc_connection_t connection = xpc_connection_create(SERVICE_NAME, NULL);
    if (!connection) {
        return 1;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) { (void)event; });
    xpc_connection_resume(connection);

    __block int result = 0;
    __block int64_t previous_pid = 0;
    for (int ordinal = 0; ordinal < 2 && result == 0; ++ordinal) {
        const char *text = ordinal == 0 ? "first request" : "second request";
        xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(request, "text", text);
        xpc_connection_send_message_with_reply(connection, request, NULL, ^(xpc_object_t reply) {
            if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
                const char *description = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
                fprintf(stderr, "%s\n", description ? description : "XPC reply error");
                result = 2;
            } else {
                const char *echo = xpc_dictionary_get_string(reply, "echo");
                const int64_t pid = xpc_dictionary_get_int64(reply, "pid");
                if (!echo || strcmp(echo, text) != 0 || pid <= 1 || pid == getpid() ||
                    xpc_dictionary_get_int64(reply, "ppid") != 1 ||
                    !xpc_dictionary_get_bool(reply, "service_identity") ||
                    !xpc_dictionary_get_bool(reply, "service_environment") ||
                    (previous_pid != 0 && previous_pid != pid)) {
                    result = 3;
                }
                previous_pid = pid;
            }
            dispatch_semaphore_signal(done);
        });
        xpc_release(request);
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC))) {
            fputs("echo timeout\n", stderr);
            result = 4;
        }
    }
    xpc_connection_cancel(connection);
    xpc_release(connection);
    if (!result) {
        puts("bundled XPC service echoed both requests");
    }
    return result;
}
#endif
