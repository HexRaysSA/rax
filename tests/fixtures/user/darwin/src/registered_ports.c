// mach_ports_register and mach_ports_lookup: the task's three registered
// ports (a dead name kept dead, a port turning dead with its receive
// right), the send rights the stash holds and hands out, the rights that
// may not be stashed (the read and inspect ports, which may not be special
// ports either), the task port a request needs, and inheritance by spawned
// children, whose registered ports (and exception handlers, dead names
// included) spawn attributes can set. A process's first registered port
// is its bootstrap port, and libSystem's fork registers it alone again (in
// the parent and the child).
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern kern_return_t _kernelrpc_mach_ports_register3(task_t, mach_port_t, mach_port_t, mach_port_t);
extern kern_return_t _kernelrpc_mach_ports_lookup3(task_t, mach_port_t *, mach_port_t *, mach_port_t *);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);

static const char *kind(mach_port_t p, mach_port_t mine) {
    if (p == MACH_PORT_NULL) return "null";
    if (p == MACH_PORT_DEAD) return "dead";
    return p == mine ? "mine" : "port";
}

static mach_port_urefs_t refs(mach_port_t p) {
    mach_port_urefs_t u = 0;
    mach_port_get_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, &u);
    return u;
}

// The registered ports as mach_ports_lookup returns them.
static void lookup(const char *what, mach_port_t mine) {
    mach_port_t *ports = NULL;
    mach_msg_type_number_t n = 0;
    kern_return_t kr = mach_ports_lookup(mach_task_self(), &ports, &n);
    printf("%s: kr=%d n=%u", what, kr, n);
    for (unsigned i = 0; i < n; i++) printf(" %s", kind(ports[i], mine));
    printf("\n");
    if (ports) vm_deallocate(mach_task_self(), (vm_address_t)ports, n * sizeof *ports);
}

static mach_port_t receive_with_send(void) {
    mach_port_t r;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &r);
    mach_port_insert_right(mach_task_self(), r, r, MACH_MSG_TYPE_MAKE_SEND);
    return r;
}

// A spawned child, with registered ports and a bad-access handler set by
// its attributes when given.
static void spawn_child(const char *what, const char *self, mach_port_t *ports, uint32_t count,
                        mach_port_t handler) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (handler != MACH_PORT_NULL)
        posix_spawnattr_setexceptionports_np(&attr, EXC_MASK_BAD_ACCESS, handler, EXCEPTION_DEFAULT, 0);
    if (ports) {
        int e = posix_spawnattr_set_registered_ports_np(&attr, ports, count);
        if (e) {
            printf("%s: attribute %d\n", what, e);
            posix_spawnattr_destroy(&attr);
            return;
        }
    }
    char *argv[] = {(char *)self, "child", (char *)what, NULL};
    pid_t pid;
    int e = posix_spawn(&pid, self, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (e) {
        printf("%s: posix_spawn %d\n", what, e);
        return;
    }
    int status;
    waitpid(pid, &status, 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t task = mach_task_self();
    if (argc == 3 && !strcmp(argv[1], "child")) {
        lookup(argv[2], MACH_PORT_NULL);
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_msg_type_number_t count = EXC_TYPES_COUNT;
        exception_handler_t handlers[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        kern_return_t kr = task_get_exception_ports(task, EXC_MASK_BAD_ACCESS, masks, &count, handlers,
                                                    behaviors, flavors);
        printf(" its bad-access handler: kr=%d %s\n", kr, count ? kind(handlers[0], MACH_PORT_NULL) : "none");
        return 0;
    }

    // The initial stash: the bootstrap port, then nothing.
    mach_port_t a, b, c;
    kern_return_t kr = _kernelrpc_mach_ports_lookup3(task, &a, &b, &c);
    printf("initial: kr=%d first_is_bootstrap=%d then %s %s\n", kr, a == bootstrap_port, kind(b, 0), kind(c, 0));

    // A port, nothing, and a dead name; the stash holds a send right of its
    // own, and each lookup hands out another.
    mach_port_t r = receive_with_send(), dead;
    mach_port_allocate(task, MACH_PORT_RIGHT_DEAD_NAME, &dead);
    mach_port_t set[3] = {r, MACH_PORT_NULL, dead};
    printf("register: %d refs %u\n", mach_ports_register(task, set, 3), refs(r));
    lookup("lookup", r);
    printf("refs after lookup %u\n", refs(r));
    mach_port_t three[3] = {r, r, r};
    printf("register three: %d\n", mach_ports_register(task, three, 3));
    lookup("lookup", r);
    printf("refs %u\n", refs(r));
    mach_port_t one[1] = {r};
    printf("register one: %d\n", mach_ports_register(task, one, 1));
    lookup("lookup", r);
    printf("register four: %d\n", mach_ports_register(task, three, 4));
    printf("register none: %d\n", mach_ports_register(task, NULL, 0));
    lookup("lookup", r);

    // Ports that may not be stashed; the others may.
    mach_port_t rd, insp, name;
    task_get_special_port(task, TASK_READ_PORT, &rd);
    task_get_special_port(task, TASK_INSPECT_PORT, &insp);
    task_get_special_port(task, TASK_NAME_PORT, &name);
    mach_port_t thread = mach_thread_self();
    printf("register read port: %d\n", _kernelrpc_mach_ports_register3(task, rd, 0, 0));
    printf("register inspect port: %d\n", _kernelrpc_mach_ports_register3(task, 0, 0, insp));
    printf("register r and the read port: %d\n", _kernelrpc_mach_ports_register3(task, r, rd, 0));
    lookup("lookup after refusals", r);
    printf("register name port: %d\n", _kernelrpc_mach_ports_register3(task, name, 0, 0));
    printf("register task port: %d\n", _kernelrpc_mach_ports_register3(task, task, 0, 0));
    printf("register thread port: %d\n", _kernelrpc_mach_ports_register3(task, thread, 0, 0));
    printf("register host port: %d\n", _kernelrpc_mach_ports_register3(task, mach_host_self(), 0, 0));
    kr = _kernelrpc_mach_ports_lookup3(task, &a, &b, &c);
    printf("lookup: kr=%d host=%d %s %s\n", kr, a == mach_host_self(), kind(b, 0), kind(c, 0));
    printf("bootstrap port set to the read port: %d\n", task_set_special_port(task, TASK_BOOTSTRAP_PORT, rd));
    printf("bootstrap port set to the inspect port: %d\n", task_set_special_port(task, TASK_BOOTSTRAP_PORT, insp));

    // The task a request is made through.
    printf("register through the read port: %d\n", _kernelrpc_mach_ports_register3(rd, 0, 0, 0));
    printf("lookup through the read port: %d\n", _kernelrpc_mach_ports_lookup3(rd, &a, &b, &c));
    printf("lookup through the inspect port: %d\n", _kernelrpc_mach_ports_lookup3(insp, &a, &b, &c));
    printf("lookup through the name port: %d\n", _kernelrpc_mach_ports_lookup3(name, &a, &b, &c));
    printf("register through the host port: %d\n", _kernelrpc_mach_ports_register3(mach_host_self(), 0, 0, 0));
    printf("lookup through null: %#x\n", _kernelrpc_mach_ports_lookup3(MACH_PORT_NULL, &a, &b, &c));

    // A registered port whose receive right is destroyed is dead.
    mach_port_t gone = receive_with_send();
    mach_port_t g[3] = {gone, MACH_PORT_NULL, gone};
    mach_ports_register(task, g, 3);
    mach_port_mod_refs(task, gone, MACH_PORT_RIGHT_RECEIVE, -1);
    lookup("lookup after the receive right is gone", gone);

    // Spawned children inherit the stash; an attribute replaces it.
    mach_port_t kept[3] = {r, dead, MACH_PORT_NULL};
    mach_ports_register(task, kept, 3);
    char self[4096];
    uint32_t size = sizeof self;
    _NSGetExecutablePath(self, &size);
    spawn_child("spawned child", self, NULL, 0, MACH_PORT_NULL);
    mach_port_t one_dead[1] = {dead};
    spawn_child("spawned with a dead name", self, one_dead, 1, MACH_PORT_NULL);
    mach_port_t literal_dead[1] = {MACH_PORT_DEAD};
    spawn_child("spawned with MACH_PORT_DEAD", self, literal_dead, 1, MACH_PORT_NULL);
    mach_port_t two[2] = {MACH_PORT_NULL, r};
    spawn_child("spawned with two", self, two, 2, MACH_PORT_NULL);
    mach_port_t four[4] = {r, r, r, r};
    spawn_child("spawned with four", self, four, 4, MACH_PORT_NULL);
    mach_port_t readp[1] = {rd};
    spawn_child("spawned with the read port", self, readp, 1, MACH_PORT_NULL);
    spawn_child("spawned with a handler", self, NULL, 0, r);
    spawn_child("spawned with a dead handler", self, NULL, 0, dead);
    spawn_child("spawned with MACH_PORT_DEAD as handler", self, NULL, 0, MACH_PORT_DEAD);
    lookup("the parent's", r);

    // libSystem's fork registers the bootstrap port alone, in both.
    pid_t pid = fork();
    if (pid == 0) {
        kr = _kernelrpc_mach_ports_lookup3(mach_task_self(), &a, &b, &c);
        printf("forked child: kr=%d first_is_bootstrap=%d then %s %s\n", kr, a == bootstrap_port, kind(b, 0),
               kind(c, 0));
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    kr = _kernelrpc_mach_ports_lookup3(task, &a, &b, &c);
    printf("parent after fork: kr=%d first_is_bootstrap=%d then %s %s\n", kr, a == bootstrap_port, kind(b, 0),
           kind(c, 0));
    return 0;
}
