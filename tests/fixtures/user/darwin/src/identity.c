// Per-thread identities: gettid without one (ESRCH), and settid and
// settid_with_pid, which need privilege (EPERM) after their own checks
// (ESRCH for no process).
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define SYS_settid 285
#define SYS_gettid 286
#define SYS_settid_with_pid 311
#define KAUTH_UID_NONE (~(uid_t)0 - 100)
#define KAUTH_GID_NONE (~(gid_t)0 - 100)

static void show(const char *what, long r) { printf("%s: %ld errno=%d\n", what, r, r ? errno : 0); }

static void *other(void *arg) {
    (void)arg;
    uid_t u = 7;
    gid_t g = 7;
    errno = 0;
    show("thread gettid", syscall(SYS_gettid, &u, &g));
    printf("thread untouched: %d\n", u == 7 && g == 7);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int root = geteuid() == 0;
    uid_t u = 7;
    gid_t g = 7;
    errno = 0;
    show("gettid", syscall(SYS_gettid, &u, &g));
    errno = 0;
    show("pthread_getugid_np", pthread_getugid_np(&u, &g) ? errno : 0);
    errno = 0;
    long r = syscall(SYS_settid, getuid(), getgid());
    printf("settid: %s errno=%d\n", root ? (r == 0 ? "ok" : "failed") : (r == 0 ? "?" : "refused"),
           root ? 0 : errno);
    errno = 0;
    show("settid none", syscall(SYS_settid, KAUTH_UID_NONE, KAUTH_GID_NONE));
    errno = 0;
    show("settid_with_pid 0", syscall(SYS_settid_with_pid, 0, 1));
    errno = 0;
    show("settid_with_pid missing", syscall(SYS_settid_with_pid, 99999999, 1));
    if (!root) {
        errno = 0;
        show("settid_with_pid self", syscall(SYS_settid_with_pid, getpid(), 1));
        errno = 0;
        show("settid_with_pid revert", syscall(SYS_settid_with_pid, getpid(), 0));
    }
    pthread_t t;
    pthread_create(&t, NULL, other, NULL);
    pthread_join(t, NULL);
    return 0;
}
