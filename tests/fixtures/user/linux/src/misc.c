/* Supplementary groups, read-ahead, and syncing: getgroups (the count,
 * a small buffer, a bad size or buffer) and the /proc/self/status line;
 * setgroups for root (sorting, the invalid gid, NGROUPS_MAX, a bad buffer,
 * clearing) and refused for others; readahead on each kind of file;
 * sync_file_range's flag, range, and file checks; and fsync, fdatasync,
 * and syncfs on each kind of file (syncfs takes any file's file system;
 * fsync only files that have the operation; neither an O_PATH one). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "check.h"

/* Whether the "Groups:" line of /proc/self/status lists `g` (n IDs). */
static int status_lists(const gid_t *g, int n) {
    char want[1024] = "Groups:\t", line[1024];
    for (int i = 0; i < n; i++)
        snprintf(want + strlen(want), sizeof want - strlen(want), "%s%u", i ? " " : "", g[i]);
    strcat(want, " \n");
    FILE *f = fopen("/proc/self/status", "r");
    int found = 0;
    while (f && fgets(line, sizeof line, f))
        found |= !strcmp(line, want);
    if (f)
        fclose(f);
    return found;
}

static void groups(void) {
    gid_t g[128];
    int n = getgroups(0, 0);
    int sorted = 1;
    int got = getgroups(128, g);
    for (int i = 1; i < got; i++)
        sorted &= g[i - 1] <= g[i];
    CHECK("getgroups", n >= 0 && got == n && sorted);
    CHECK("status-groups", status_lists(g, n));
    CHECK_ERR("getgroups-negative", getgroups(-1, g), EINVAL);
    CHECK("getgroups-small", n == 0 || (getgroups(n - 1 > 0 ? n - 1 : 0, g) == (n - 1 > 0 ? -1 : n)));
    CHECK("getgroups-fault", n == 0 || (getgroups(n, (gid_t *)8) == -1 && errno == EFAULT));
    /* setgroups needs CAP_SETGID: root has it here. */
    int root = geteuid() == 0;
    gid_t set[3] = {9, 3, 5};
    int r = setgroups(3, set);
    gid_t out[8] = {0};
    CHECK("setgroups", root ? r == 0 && getgroups(8, out) == 3 && out[0] == 3 && out[1] == 5 &&
                                  out[2] == 9 && status_lists(out, 3)
                            : r == -1 && errno == EPERM);
    gid_t bad = (gid_t)-1;
    r = setgroups(1, &bad);
    CHECK("setgroups-invalid", r == -1 && errno == (root ? EINVAL : EPERM));
    r = setgroups(65537, set);
    CHECK("setgroups-too-many", r == -1 && errno == (root ? EINVAL : EPERM));
    r = setgroups(1, (gid_t *)8);
    CHECK("setgroups-fault", r == -1 && errno == (root ? EFAULT : EPERM));
    r = setgroups(0, 0);
    CHECK("setgroups-clear", root ? r == 0 && getgroups(0, 0) == 0 && status_lists(out, 0)
                                  : r == -1 && errno == EPERM);
}

static void ranges(void) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/rax-misc-%d", getpid());
    int f = open(path, O_CREAT | O_RDWR, 0644);
    write(f, "data", 4);
    int wo = open(path, O_WRONLY);
    int op = open(path, O_PATH);
    int d = open("/tmp", O_RDONLY | O_DIRECTORY);
    int p[2];
    pipe(p);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    int proc = open("/proc/self/status", O_RDONLY);
    CHECK("readahead", readahead(f, 0, 4096) == 0);
    CHECK("readahead-proc", readahead(proc, 0, 4096) == 0);
    CHECK_ERR("readahead-write-only", readahead(wo, 0, 4096), EBADF);
    CHECK_ERR("readahead-path-only", readahead(op, 0, 4096), EBADF);
    CHECK_ERR("readahead-closed", readahead(99, 0, 4096), EBADF);
    CHECK_ERR("readahead-dir", readahead(d, 0, 4096), EINVAL);
    CHECK_ERR("readahead-pipe", readahead(p[0], 0, 4096), EINVAL);
    CHECK_ERR("readahead-socket", readahead(s, 0, 4096), EINVAL);
    unsigned all = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    CHECK("sync-range", sync_file_range(f, 0, 4, all) == 0);
    CHECK("sync-range-to-end", sync_file_range(f, 2, 0, SYNC_FILE_RANGE_WRITE) == 0);
    CHECK("sync-range-write-only", sync_file_range(wo, 0, 0, 0) == 0);
    CHECK("sync-range-dir", sync_file_range(d, 0, 0, 0) == 0);
    CHECK_ERR("sync-range-flags", sync_file_range(f, 0, 4, 8), EINVAL);
    CHECK_ERR("sync-range-negative", sync_file_range(f, -1, 4, 0), EINVAL);
    CHECK_ERR("sync-range-overflow", sync_file_range(f, 0x7fffffffffffffffLL, 2, 0), EINVAL);
    CHECK_ERR("sync-range-pipe", sync_file_range(p[1], 0, 0, 0), ESPIPE);
    CHECK_ERR("sync-range-socket", sync_file_range(s, 0, 0, 0), ESPIPE);
    CHECK_ERR("sync-range-path-only", sync_file_range(op, 0, 0, 0), EBADF);
    CHECK_ERR("sync-range-flags-first", sync_file_range(p[1], 0, 0, 8), EINVAL);
    close(f);
    close(wo);
    close(op);
    close(d);
    close(p[0]);
    close(p[1]);
    close(s);
    close(proc);
    unlink(path);
}

static void syncs(void) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/rax-sync-%d", getpid());
    int f = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    int d = open("/tmp", O_RDONLY | O_DIRECTORY);
    int p[2];
    pipe(p);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    int e = eventfd(0, 0);
    int null = open("/dev/null", O_RDWR);
    int proc = open("/proc/self/status", O_RDONLY);
    int o = open(path, O_PATH);
    CHECK("fsync-file", fsync(f) == 0 && fdatasync(f) == 0);
    CHECK("fsync-directory", fsync(d) == 0);
    CHECK_ERR("fsync-pipe", fsync(p[0]), EINVAL);
    CHECK_ERR("fdatasync-pipe", fdatasync(p[1]), EINVAL);
    CHECK_ERR("fsync-socket", fsync(s), EINVAL);
    CHECK_ERR("fsync-eventfd", fsync(e), EINVAL);
    CHECK_ERR("fsync-dev-null", fsync(null), EINVAL);
    CHECK_ERR("fsync-proc", fsync(proc), EINVAL);
    CHECK_ERR("fsync-o-path", fsync(o), EBADF);
    CHECK("syncfs-file", syncfs(f) == 0 && syncfs(d) == 0);
    CHECK("syncfs-pipe", syncfs(p[0]) == 0);
    CHECK("syncfs-socket", syncfs(s) == 0);
    CHECK("syncfs-eventfd", syncfs(e) == 0);
    CHECK("syncfs-dev-null", syncfs(null) == 0);
    CHECK("syncfs-proc", syncfs(proc) == 0);
    CHECK_ERR("syncfs-o-path", syncfs(o), EBADF);
    CHECK_ERR("syncfs-closed", syncfs(999), EBADF);
    close(f);
    close(d);
    close(p[0]);
    close(p[1]);
    close(s);
    close(e);
    close(null);
    close(proc);
    close(o);
    unlink(path);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    groups();
    ranges();
    syncs();
    FINISH();
}
