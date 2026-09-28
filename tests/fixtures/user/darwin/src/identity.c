// Per-thread identities: gettid without one (ESRCH), and settid and
// settid_with_pid, which need privilege (EPERM) after their own checks
// (ESRCH for no process).
// Personas (the process's, and queries of others'): a process started
// without one has none (ESRCH), info blocks are checked by version, and an
// unknown operation is not a system call (ENOSYS).
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYS_persona 494
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

    // Personas.
    uint32_t id = 7;
    errno = 0;
    show("persona get", syscall(SYS_persona, 4, 0, NULL, &id, NULL, NULL));
    unsigned char info[348];
    for (int v = 0; v <= 3; v++) {
        memset(info, 0, sizeof info);
        info[0] = (unsigned char)v;
        errno = 0;
        char what[32];
        snprintf(what, sizeof what, "persona pidinfo v%d", v);
        show(what, syscall(SYS_persona, 6, 0, info, (uint32_t[]){getpid()}, NULL, NULL));
    }
    memset(info, 0, sizeof info);
    info[0] = 2;
    errno = 0;
    show("persona pidinfo launchd", syscall(SYS_persona, 6, 0, info, (uint32_t[]){1}, NULL, NULL));
    errno = 0;
    show("persona pidinfo none", syscall(SYS_persona, 6, 0, info, (uint32_t[]){99999999}, NULL, NULL));
    errno = 0;
    show("persona info 0", syscall(SYS_persona, 5, 0, info, (uint32_t[]){0}, NULL, NULL));
    uint32_t ids[4];
    size_t n = 4;
    memset(info, 0, sizeof info);
    info[0] = 2;
    errno = 0;
    long fr = syscall(SYS_persona, 7, 0, info, ids, &n, NULL);
    printf("persona find: %ld errno=%d count=%zu\n", fr, fr ? errno : 0, n);
    char path[1024];
    errno = 0;
    show("persona getpath 0", syscall(SYS_persona, 8, 0, NULL, (uint32_t[]){0}, NULL, path));
    errno = 0;
    show("persona op 99", syscall(SYS_persona, 99, 0, NULL, NULL, NULL, NULL));
    errno = 0;
    show("persona alloc", syscall(SYS_persona, 1, 0, info, &id, NULL, NULL));
    return 0;
}
