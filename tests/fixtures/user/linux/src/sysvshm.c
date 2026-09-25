/* System V shared memory (ipc/shm.c). A segment's creation and status;
 * attaches seeing each other's stores; attaches counted by mapping (a split
 * counts twice, and is not merged again); shmdt and munmap detaching; a forked child's inherited
 * attach and its exit; read-only attaches; SHM_RND and SHM_REMAP; keys
 * (sizes, IPC_EXCL, ENOENT); access for another user; IPC_SET, SHM_STAT,
 * IPC_INFO, SHM_INFO; removal while attached (SHM_DEST, the key private,
 * still attachable by identifier) and at the last detach, also a dying
 * process's; /proc/self/maps. Values that depend on other segments in the
 * namespace are not printed. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#define PAGE 4096

static struct shmid_ds st(int id) {
    struct shmid_ds ds;
    memset(&ds, 0xff, sizeof ds);
    if (shmctl(id, IPC_STAT, &ds) != 0)
        ds.shm_segsz = 0;
    return ds;
}

/* The /proc/self/maps line of address a, if any. */
static int maps_line(void *a, char *out, size_t n) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    char want[32];
    snprintf(want, sizeof want, "%08lx-", (unsigned long)a);
    int found = 0;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, want, strlen(want))) {
            snprintf(out, n, "%s", line);
            found = 1;
        }
    if (f)
        fclose(f);
    return found;
}

static void lifecycle(void) {
    int id = shmget(IPC_PRIVATE, 3 * PAGE + 100, 0600);
    struct shmid_ds ds = st(id);
    CHECK("create", id >= 0 && ds.shm_segsz == 3 * PAGE + 100 && ds.shm_nattch == 0 &&
                        ds.shm_cpid == getpid() && ds.shm_lpid == 0 && ds.shm_atime == 0 &&
                        ds.shm_dtime == 0 && ds.shm_ctime > 0 && ds.shm_perm.mode == 0600 &&
                        ds.shm_perm.__key == IPC_PRIVATE && ds.shm_perm.uid == geteuid() &&
                        ds.shm_perm.cuid == geteuid());
    char *a = shmat(id, NULL, 0), *b = shmat(id, NULL, 0);
    CHECK("attach", a != (void *)-1 && b != (void *)-1 && a != b);
    a[3 * PAGE + 99] = 'x';
    CHECK("shared-stores", b[3 * PAGE + 99] == 'x');
    ds = st(id);
    CHECK("attach-count", ds.shm_nattch == 2 && ds.shm_lpid == getpid() && ds.shm_atime > 0);
    mprotect(a, PAGE, PROT_READ);
    CHECK("split-counts-twice", st(id).shm_nattch == 3);
    /* The pieces are not merged again (is_mergeable_vma: shm's VMAs have a
     * close operation). */
    mprotect(a, PAGE, PROT_READ | PROT_WRITE);
    CHECK("no-merge", st(id).shm_nattch == 3);
    char line[512];
    CHECK("maps", maps_line(a, line, sizeof line) && strstr(line, " rw-s 00000000 00:01 ") &&
                      strstr(line, "/SYSV00000000 (deleted)"));
    char ino[32];
    snprintf(ino, sizeof ino, " %d ", id);
    CHECK("maps-inode-is-id", strstr(line, ino) != NULL);
    CHECK("shmdt", shmdt(a) == 0 && st(id).shm_nattch == 1 && st(id).shm_dtime > 0);
    CHECK_ERR("shmdt-again", shmdt(a), EINVAL);
    CHECK_ERR("shmdt-unaligned", shmdt(b + 1), EINVAL);

    /* A forked child's attach is its own; its exit detaches it. */
    pid_t c = fork();
    if (c == 0) {
        int ok = b[3 * PAGE + 99] == 'x' && st(id).shm_nattch == 2;
        b[0] = 'c';
        _exit(ok ? 0 : 1);
    }
    int status = -1;
    waitpid(c, &status, 0);
    ds = st(id);
    CHECK("child-attach", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("child-exit-detaches", ds.shm_nattch == 1 && ds.shm_lpid == c && b[0] == 'c');

    CHECK("munmap-detaches", munmap(b, 4 * PAGE) == 0 && st(id).shm_nattch == 0);
    char *r = shmat(id, NULL, SHM_RDONLY);
    CHECK("read-only", r != (void *)-1 && r[3 * PAGE + 99] == 'x');
    CHECK_ERR("read-only-stays", mprotect(r, PAGE, PROT_READ | PROT_WRITE), EACCES);
    shmdt(r);

    /* Placement. */
    char *hole = mmap(NULL, 8 * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(hole, 8 * PAGE);
    CHECK_ERR("unaligned", (long)shmat(id, hole + 1, 0), EINVAL);
    CHECK("rounded", shmat(id, hole + 1, SHM_RND) == hole);
    CHECK_ERR("occupied", (long)shmat(id, hole, 0), EINVAL);
    CHECK("remap", shmat(id, hole, SHM_REMAP) == hole);
    CHECK_ERR("remap-needs-address", (long)shmat(id, NULL, SHM_REMAP), EINVAL);
    shmdt(hole);
    CHECK_ERR("no-such-id", (long)shmat(id + 1, NULL, 0), EINVAL);
    CHECK_ERR("negative-id", (long)shmat(-1, NULL, 0), EINVAL);

    /* Removal while attached. */
    a = shmat(id, NULL, 0);
    CHECK("rmid-attached", shmctl(id, IPC_RMID, NULL) == 0);
    ds = st(id);
    CHECK("rmid-marks", ds.shm_perm.mode == (0600 | 01000) && ds.shm_perm.__key == IPC_PRIVATE);
    b = shmat(id, NULL, 0);
    CHECK("attach-marked", b != (void *)-1 && b[0] == 'c');
    shmdt(a);
    CHECK("still-there", st(id).shm_nattch == 1);
    shmdt(b);
    CHECK_ERR("gone-at-last-detach", shmctl(id, IPC_STAT, &ds), EINVAL);
}

static void keys(void) {
    key_t key = 0x52410000 ^ getpid();
    int id = shmget(key, 100, IPC_CREAT | 0640);
    CHECK("key-create", id >= 0);
    CHECK("key-find", shmget(key, 50, 0) == id);
    CHECK_ERR("key-too-big", shmget(key, 101, 0), EINVAL);
    CHECK_ERR("key-exclusive", shmget(key, 1, IPC_CREAT | IPC_EXCL | 0600), EEXIST);
    CHECK_ERR("key-missing", shmget(key ^ 1, 1, 0), ENOENT);
    CHECK_ERR("size-zero", shmget(IPC_PRIVATE, 0, 0600), EINVAL);
    struct shmid_ds ds;
    CHECK("shm-stat-by-index", shmctl(id & 0x7fff, SHM_STAT, &ds) == id && ds.shm_perm.__key == key);
    ds = st(id);
    ds.shm_perm.mode = 0604;
    CHECK("ipc-set", shmctl(id, IPC_SET, &ds) == 0 && st(id).shm_perm.mode == 0604);
    struct shminfo info;
    CHECK("ipc-info", shmctl(0, IPC_INFO, (struct shmid_ds *)&info) >= 0 && info.shmmni == 4096 &&
                          info.shmmin == 1);
    struct shm_info si;
    CHECK("shm-info", shmctl(0, SHM_INFO, (struct shmid_ds *)&si) >= 0 && si.used_ids >= 1);
    CHECK_ERR("bad-command", shmctl(id, 99, &ds), EINVAL);
    CHECK_ERR("bad-buffer", shmctl(id, IPC_STAT, (struct shmid_ds *)8), EFAULT);
    shmctl(id, IPC_RMID, NULL);

    /* Another (unprivileged) user and a segment no one may use. */
    int locked = shmget(IPC_PRIVATE, 1, 0);
    pid_t c = fork();
    if (c == 0) {
        /* Root becomes another user; another user stays the owner, who
         * has no access to a mode-0 segment either but may remove it. */
        int other = geteuid() == 0;
        if (other && (setgid(65534) || setuid(65534)))
            _exit(2);
        int r = shmat(locked, NULL, SHM_RDONLY) == (void *)-1 && errno == EACCES &&
                (!other || (shmctl(locked, IPC_RMID, NULL) == -1 && errno == EPERM));
        _exit(r ? 0 : 1);
    }
    int status = -1;
    waitpid(c, &status, 0);
    CHECK("other-user", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    shmctl(locked, IPC_RMID, NULL);

    /* A process that dies attached to a removed segment removes it. */
    int dying = shmget(IPC_PRIVATE, PAGE, 0600);
    c = fork();
    if (c == 0) {
        shmat(dying, NULL, 0);
        shmctl(dying, IPC_RMID, NULL);
        _exit(0);
    }
    waitpid(c, &status, 0);
    struct shmid_ds gone;
    CHECK_ERR("removed-at-exit", shmctl(dying, IPC_STAT, &gone), EINVAL);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    lifecycle();
    keys();
    FINISH();
}
