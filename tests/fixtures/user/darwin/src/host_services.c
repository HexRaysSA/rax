// The host's services through the process's bootstrap port: launchd's
// lookups, the directory service (users, groups, memberships) as libinfo
// reaches it (XPC, a memory entry, a moved receive right), notifications
// (notifyd), the Sandbox policy's checks, memory entries of the process's
// own memory, and the machine's UUID; from a forked and a spawned child
// too. Only what is the same for the native and the emulated process is
// printed.
#include <errno.h>
#include <grp.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <notify.h>
#include <pwd.h>
#include <servers/bootstrap.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
int sandbox_check(pid_t, const char *, int, ...);
int sandbox_container_path_for_pid(pid_t, char *, size_t);
int __mac_syscall(const char *, int, void *);

static void directory(const char *who) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        printf("%s: getpwuid failed\n", who);
        return;
    }
    // The fields, compared with the environment's where it has them.
    const char *home = getenv("HOME");
    printf("%s: user %s uid_ok=%d gid_ok=%d home_ok=%d shell=%s\n", who, pw->pw_name, pw->pw_uid == getuid(),
           pw->pw_gid == getgid(), home ? strcmp(home, pw->pw_dir) == 0 : -1, pw->pw_shell);
    struct group *gr = getgrgid(getgid());
    printf("%s: group %s\n", who, gr ? gr->gr_name : "(none)");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) {
        directory(argv[1]);
        return 0;
    }

    // The bootstrap port and launchd's lookups.
    mach_port_t bp = MACH_PORT_NULL;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
    printf("bootstrap: set=%d same=%d\n", bp != MACH_PORT_NULL, bp == bootstrap_port);
    mach_port_t svc = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.apple.system.notification_center", &svc);
    printf("look up notifyd: %d valid=%d\n", kr, MACH_PORT_VALID(svc));
    kr = bootstrap_look_up(bootstrap_port, "com.example.rax.no-such-service", &svc);
    printf("look up nothing: %d\n", kr);

    // The directory service.
    directory("parent");
    struct passwd *root = getpwnam("root");
    printf("root: uid=%d dir=%s\n", root ? (int)root->pw_uid : -1, root ? root->pw_dir : "");
    errno = 0;
    printf("no such uid: %s\n", getpwuid(4000000) ? "found" : "none");
    int groups[64];
    int ngroups = 64;
    struct passwd *me = getpwuid(getuid());
    int r = getgrouplist(me->pw_name, (int)me->pw_gid, groups, &ngroups);
    printf("getgrouplist: %d count>1=%d\n", r, ngroups > 1);

    // Notifications.
    char name[64];
    snprintf(name, sizeof name, "com.example.rax.fixture.%d", getpid());
    int token = -1, check = -1;
    int st = notify_register_check(name, &token);
    printf("notify_register_check: %d\n", st);
    st = notify_check(token, &check);
    printf("first check: %d changed=%d\n", st, check);
    st = notify_check(token, &check);
    printf("second check: %d changed=%d\n", st, check);
    st = notify_post(name);
    printf("post: %d\n", st);
    // The post reaches notifyd in a message of its own: wait for it.
    check = 0;
    for (int i = 0; i < 200 && st == 0 && !check; i++) {
        st = notify_check(token, &check);
        if (!check) usleep(10000);
    }
    printf("after post: %d changed=%d\n", st, check);
    notify_cancel(token);

    // The Sandbox policy, for an unsandboxed process.
    printf("sandbox self: %d\n", sandbox_check(getpid(), NULL, 0));
    printf("sandbox read: %d\n", sandbox_check(getpid(), "file-read-data", 1, "/etc/hosts"));
    printf("sandbox lookup: %d\n", sandbox_check(getpid(), "mach-lookup", 2, "com.apple.cfprefsd.daemon"));
    printf("sandbox launchd: %d\n", sandbox_check(1, NULL, 0));
    char path[1024] = {0};
    errno = 0;
    r = sandbox_container_path_for_pid(getpid(), path, sizeof path);
    printf("container: %d errno=%d\n", r, errno);
    errno = 0;
    r = __mac_syscall("Sandbox", 9999, NULL);
    printf("unknown Sandbox call: %d errno=%d\n", r, errno);
    errno = 0;
    r = __mac_syscall("NoSuchPolicy", 1, NULL);
    printf("unknown policy: %d errno=%d\n", r, errno);

    // Memory entries of the process's own memory.
    mach_vm_address_t a = 0, b = 0, c = 0;
    mach_vm_size_t page = (mach_vm_size_t)getpagesize();
    mach_vm_allocate(mach_task_self(), &a, page, VM_FLAGS_ANYWHERE);
    strcpy((char *)a, "before");
    memory_object_size_t size = page;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, a, VM_PROT_READ | VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    printf("entry of memory: %d size_ok=%d\n", kr, size == page);
    kr = mach_vm_map(mach_task_self(), &b, page, 0, VM_FLAGS_ANYWHERE, entry, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                     VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    printf("map it: %d contents=%s\n", kr, kr ? "" : (char *)b);
    strcpy((char *)a, "shared");
    printf("through the mapping: %s\n", kr ? "" : (char *)b);
    kr = mach_vm_map(mach_task_self(), &c, page, 0, VM_FLAGS_ANYWHERE, entry, 0, TRUE, VM_PROT_READ | VM_PROT_WRITE,
                     VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    strcpy((char *)a, "later");
    printf("a copy: %d contents=%s\n", kr, kr ? "" : (char *)c);
    mach_port_t fresh = MACH_PORT_NULL;
    size = page;
    kr = mach_make_memory_entry_64(mach_task_self(), &size, 0, MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE,
                                   &fresh, MACH_PORT_NULL);
    mach_vm_address_t d = 0, e = 0;
    mach_vm_map(mach_task_self(), &d, page, 0, VM_FLAGS_ANYWHERE, fresh, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    mach_vm_map(mach_task_self(), &e, page, 0, VM_FLAGS_ANYWHERE, fresh, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    printf("new entry: %d zero=%d", kr, d && ((char *)d)[0] == 0);
    if (d && e) {
        strcpy((char *)d, "new");
        printf(" shared=%s", (char *)e);
    }
    printf("\n");

    // The machine's UUID.
    uuid_t u;
    struct timespec ts = {1, 0};
    memset(u, 0, sizeof u);
    r = gethostuuid(u, &ts);
    int nonzero = 0;
    for (int i = 0; i < 16; i++) nonzero |= u[i];
    printf("gethostuuid: %d nonzero=%d\n", r, nonzero != 0);
    errno = 0;
    r = gethostuuid(u, NULL);
    printf("gethostuuid without a timeout: %d errno=%d\n", r, errno);

    // Children reach the services too.
    pid_t pid = fork();
    if (pid == 0) {
        directory("forked child");
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    char self[4096];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "spawned child", NULL};
    if (posix_spawn(&pid, self, NULL, NULL, args, environ) == 0) waitpid(pid, &status, 0);
    return 0;
}
