// proc_info about the calling process: the size and flavor checks, the
// process record (names, identifiers, flags, the executable's UUID and
// architecture), task and thread records (names, run states, the thread
// lists), descriptors (types, the file record's status and offset,
// vnode, pipe, kqueue, and shared-memory records), memory regions and
// their files, the working directory, knote user data, the controls
// (thread names, process control), dyld's image-info registration,
// resource usage, and proc_info_extended_id's identifier checks; and a
// few questions about other processes (children live and zombie,
// launchd).
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int __proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor, uint32_t flags,
                            uint64_t ext_id, uint64_t arg, uint64_t buffer, int32_t buffersize);

// Private call numbers and flavors (bsd/sys/proc_info_private.h).
#define CALL_PIDINFO 0x2
#define CALL_PIDFDINFO 0x3
#define CALL_SETCONTROL 0x5
#define CALL_PIDFILEPORTINFO 0x6
#define CALL_PIDRUSAGE 0x9
#define CALL_PIDDYNKQUEUEINFO 0xd
#define CALL_SET_DYLD_IMAGES 0xf
#define PIF_COMPARE_IDVERSION 1
#define PIF_COMPARE_UNIQUEID 2
#define F_UNIQIDENTIFIERINFO 17
#define F_BSDINFOWITHUNIQID 18
#define F_COALITIONINFO 20
#define F_NOTEEXIT 21
#define F_REGIONPATHINFO2 22
#define F_REGIONPATHINFO3 23
#define F_EXITREASONBASICINFO 25
#define F_LISTUPTRS 26
#define F_LISTDYNKQUEUES 27
#define F_LISTTHREADIDS 28
#define F_VMRTFAULTINFO 29
#define F_PLATFORMINFO 30
#define F_REGIONPATH 31
#define F_IPCTABLEINFO 32
#define F_THREADSCHEDINFO 33
#define F_THREADCOUNTS 34
#define FD_KQUEUE_EXTINFO 9
#define PROC_FLAG_ROSETTA 0x2000000

struct uniqid {
    uint8_t uuid[16];
    uint64_t uniqueid, puniqueid;
    int32_t idversion, orig_ppidversion;
    uint64_t r2, r3;
};
struct regionpath {
    uint64_t addr, len;
    char path[1024];
};
struct kev_qos {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    int32_t qos;
    uint64_t udata;
    uint32_t fflags, xflags;
    int64_t data;
    uint64_t ext[4];
};
struct extinfo {
    struct kev_qos kev;
    uint64_t sdata;
    int status;
    int r0;
    uint64_t r1[2];
};

static int ret;

static const char *ename(int e) {
    switch (e) {
    case 0: return "0";
    case EPERM: return "EPERM";
    case ESRCH: return "ESRCH";
    case EINVAL: return "EINVAL";
    case ENOMEM: return "ENOMEM";
    case EFAULT: return "EFAULT";
    case EBADF: return "EBADF";
    case ENOTSUP: return "ENOTSUP";
    case EOVERFLOW: return "EOVERFLOW";
    case EACCES: return "EACCES";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOBUFS: return "ENOBUFS";
    default: {
        static char b[16];
        snprintf(b, sizeof b, "errno%d", e);
        return b;
    }
    }
}

static int pi(const char *label, int call, int pid, int flavor, uint64_t arg, void *buf, int size) {
    errno = 0;
    ret = __proc_info(call, pid, flavor, arg, buf, size);
    printf("%s: %d %s\n", label, ret, ename(ret < 0 ? errno : 0));
    return ret;
}

static int pix(const char *label, int pid, int flavor, uint32_t flags, uint64_t ext, void *buf, int size) {
    errno = 0;
    ret = __proc_info_extended_id(CALL_PIDINFO, pid, flavor, flags, ext, 0, (uint64_t)(uintptr_t)buf, size);
    printf("%s: %d %s\n", label, ret, ename(ret < 0 ? errno : 0));
    return ret;
}

// The main executable's LC_UUID.
static void exe_uuid(uint8_t out[16]) {
    const struct mach_header_64 *h = (const void *)_dyld_get_image_header(0);
    const struct load_command *lc = (const void *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (lc->cmd == LC_UUID) {
            memcpy(out, ((const struct uuid_command *)lc)->uuid, 16);
            return;
        }
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
}

// Whether a path field holds what vn_getpath leaves: the path, zeros,
// and the copy it was built as at the field's end.
static const char *built_backwards(const char *field, size_t size) {
    size_t n = strlen(field) + 1;
    if (n > size / 2)
        return "long";
    for (size_t i = n; i < size - n; i++)
        if (field[i])
            return "not zeroed";
    return memcmp(field + size - n, field, n) == 0 ? "copy at end" : "no copy";
}

static char exe[PATH_MAX];
static char *base;

static int pipe_r;
static uint64_t second_tid;

static void *second(void *arg) {
    (void)arg;
    pthread_setname_np("second");
    pthread_threadid_np(NULL, &second_tid);
    char c;
    // Blocks until the main thread writes.
    return (void *)(long)read(pipe_r, &c, 1);
}

static void sizes(void) {
    struct proc_bsdinfo b;
    pid_t self = getpid();
    pi("tbsdinfo exact", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    pi("tbsdinfo short", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b - 1);
    unsigned char big[sizeof b + 100];
    memset(big, 0xa5, sizeof big);
    pi("tbsdinfo long", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, big, sizeof big);
    printf("  tail untouched: %d\n", big[sizeof b] == 0xa5 && big[sizeof big - 1] == 0xa5);
    pi("tbsdinfo NULL", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, NULL, sizeof b);
    pi("tbsdinfo NULL 0", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, NULL, 0);
    pi("tbsdinfo size -1", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, -1);
    int bad[] = {0, -1, 16, 36, 40};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char label[32];
        snprintf(label, sizeof label, "flavor %d", bad[i]);
        pi(label, CALL_PIDINFO, self, bad[i], 0, big, sizeof big);
    }
    pi("bad callnum", 0x40, self, 0, 0, big, sizeof big);

    char path[4097];
    memset(path, 0xa5, sizeof path);
    pi("pathinfo 1024", CALL_PIDINFO, self, PROC_PIDPATHINFO, 0, path, 1024);
    printf("  path is the executable: %d, %s, past untouched: %d\n", strcmp(path, exe) == 0,
           built_backwards(path, 1024), (unsigned char)path[1024] == 0xa5);
    pi("pathinfo 4096", CALL_PIDINFO, self, PROC_PIDPATHINFO, 0, path, 4096);
    pi("pathinfo 4097", CALL_PIDINFO, self, PROC_PIDPATHINFO, 0, path, 4097);
    pi("pathinfo 1023", CALL_PIDINFO, self, PROC_PIDPATHINFO, 0, path, 1023);
    pi("pathinfo NULL", CALL_PIDINFO, self, PROC_PIDPATHINFO, 0, NULL, 1024);
    char p2[PATH_MAX];
    printf("proc_pidpath: %d, proc_name: %d \"%s\"\n", proc_pidpath(self, p2, sizeof p2) == (int)strlen(exe),
           proc_name(self, p2, sizeof p2), p2);
}

static void records(void) {
    pid_t self = getpid();
    struct proc_bsdinfo b;
    pi("tbsdinfo", CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    printf("  pid %d ppid %d pgid %d status %u xstatus %u\n", b.pbi_pid == (uint32_t)self,
           b.pbi_ppid == (uint32_t)getppid(), b.pbi_pgid == (uint32_t)getpgrp(), b.pbi_status, b.pbi_xstatus);
    printf("  ids %d %d %d %d %d %d nice %d\n", b.pbi_uid == geteuid(), b.pbi_gid == getegid(),
           b.pbi_ruid == getuid(), b.pbi_rgid == getgid(), b.pbi_svuid == geteuid(), b.pbi_svgid == getegid(),
           b.pbi_nice);
    printf("  comm \"%s\" name \"%s\" (basename %d)\n", b.pbi_comm, b.pbi_name, strncmp(b.pbi_name, base, 31) == 0);
    printf("  flags %#x nfiles %u\n", b.pbi_flags & ~PROC_FLAG_ROSETTA, b.pbi_nfiles);

    struct proc_bsdshortinfo s;
    pi("shortbsdinfo", CALL_PIDINFO, self, PROC_PIDT_SHORTBSDINFO, 0, &s, sizeof s);
    printf("  pid %d ppid %d pgid %d status %u comm \"%s\" flags %#x uid %d\n", s.pbsi_pid == (uint32_t)self,
           s.pbsi_ppid == (uint32_t)getppid(), s.pbsi_pgid == (uint32_t)getpgrp(), s.pbsi_status, s.pbsi_comm,
           s.pbsi_flags & ~PROC_FLAG_ROSETTA, s.pbsi_uid == geteuid());

    uint8_t uuid[16] = {0};
    exe_uuid(uuid);
    struct uniqid u;
    pi("uniqidentifierinfo", CALL_PIDINFO, self, F_UNIQIDENTIFIERINFO, 0, &u, sizeof u);
    audit_token_t tok;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&tok, &cnt);
    printf("  uuid is LC_UUID %d, idversion is the token's %d, uniqueid %d\n", memcmp(u.uuid, uuid, 16) == 0,
           u.idversion == (int32_t)tok.val[7], u.uniqueid != 0);
    struct {
        struct proc_bsdinfo b;
        struct uniqid u;
    } bu;
    pi("bsdinfowithuniqid", CALL_PIDINFO, self, F_BSDINFOWITHUNIQID, 0, &bu, sizeof bu);
    printf("  same %d %d\n", bu.b.pbi_pid == (uint32_t)self, bu.u.uniqueid == u.uniqueid);

    pix("extended idversion", self, PROC_PIDTBSDINFO, PIF_COMPARE_IDVERSION, (uint32_t)u.idversion, &b, sizeof b);
    pix("extended idversion other", self, PROC_PIDTBSDINFO, PIF_COMPARE_IDVERSION, (uint32_t)u.idversion + 1, &b,
        sizeof b);
    pix("extended uniqueid", self, PROC_PIDTBSDINFO, PIF_COMPARE_UNIQUEID, u.uniqueid, &b, sizeof b);
    pix("extended uniqueid other", self, PROC_PIDTBSDINFO, PIF_COMPARE_UNIQUEID, u.uniqueid + 1, &b, sizeof b);
    pix("extended both", self, PROC_PIDTBSDINFO, 3, 0, &b, sizeof b);
    pix("extended none", self, PROC_PIDTBSDINFO, 0, 12345, &b, sizeof b);

    uint32_t arch[2];
    pi("archinfo", CALL_PIDINFO, self, PROC_PIDARCHINFO, 0, arch, sizeof arch);
    printf("  cputype %#x cpusubtype %#x\n", arch[0], arch[1]);
    uint32_t platform = 0;
    pi("platforminfo", CALL_PIDINFO, self, F_PLATFORMINFO, 0, &platform, sizeof platform);
    printf("  platform %u\n", platform);
    uint64_t coal[5];
    pi("coalitioninfo", CALL_PIDINFO, self, F_COALITIONINFO, 0, coal, sizeof coal);
    printf("  ids %d\n", coal[0] != 0 && coal[1] != 0);
    uint32_t ipc[2];
    pi("ipctableinfo", CALL_PIDINFO, self, F_IPCTABLEINFO, 0, ipc, sizeof ipc);
    printf("  free below size %d\n", ipc[1] < ipc[0]);
    uint32_t w[4];
    pi("workqueueinfo", CALL_PIDINFO, self, PROC_PIDWORKQUEUEINFO, 0, w, sizeof w);
    int note;
    pi("noteexit", CALL_PIDINFO, self, F_NOTEEXIT, 0, &note, sizeof note);
    char reason[24];
    pi("exitreasonbasicinfo", CALL_PIDINFO, self, F_EXITREASONBASICINFO, 0, reason, sizeof reason);
}

static void threads(void) {
    pid_t self = getpid();
    pthread_setname_np("main-thread");
    uint64_t me;
    pthread_threadid_np(NULL, &me);
    uint64_t tsd = (uint64_t)(uintptr_t)pthread_self() + 0xe0;

    struct proc_threadinfo t;
    pi("threadinfo pthread_self", CALL_PIDINFO, self, PROC_PIDTHREADINFO, (uint64_t)(uintptr_t)pthread_self(), &t,
       sizeof t);
    pi("threadinfo tsd", CALL_PIDINFO, self, PROC_PIDTHREADINFO, tsd, &t, sizeof t);
    printf("  policy %d run %d curpri %d pri %d maxpri %d name \"%s\"\n", t.pth_policy, t.pth_run_state,
           t.pth_curpri, t.pth_priority, t.pth_maxpriority, t.pth_name);
    pi("threadinfo short", CALL_PIDINFO, self, PROC_PIDTHREADINFO, tsd, &t, sizeof t - 1);
    pi("threadid64info", CALL_PIDINFO, self, PROC_PIDTHREADID64INFO, me, &t, sizeof t);
    printf("  run %d name \"%s\"\n", t.pth_run_state, t.pth_name);
    pi("threadid64info second", CALL_PIDINFO, self, PROC_PIDTHREADID64INFO, second_tid, &t, sizeof t);
    printf("  run %d name \"%s\"\n", t.pth_run_state, t.pth_name);
    pi("threadid64info bogus", CALL_PIDINFO, self, PROC_PIDTHREADID64INFO, 12345, &t, sizeof t);

    // (Rosetta runs a thread of its own, so the lists' lengths are
    // printed for arm64 only.)
    uint64_t list[64];
    int n = __proc_info(CALL_PIDINFO, self, PROC_PIDLISTTHREADS, 0, list, sizeof list);
    int found = 0;
    for (int i = 0; i < n / 8; i++)
        found += list[i] == tsd;
    printf("  own tsd listed %d\n", found);
    pi("listthreads 8", CALL_PIDINFO, self, PROC_PIDLISTTHREADS, 0, list, 8);
    pi("listthreads 7", CALL_PIDINFO, self, PROC_PIDLISTTHREADS, 0, list, 7);
    pi("listthreads NULL", CALL_PIDINFO, self, PROC_PIDLISTTHREADS, 0, NULL, 8);
    n = __proc_info(CALL_PIDINFO, self, F_LISTTHREADIDS, 0, list, sizeof list);
    found = 0;
    for (int i = 0; i < n / 8; i++)
        found += (list[i] == me) + (list[i] == second_tid) * 2;
    printf("  listed %d\n", found);
    pi("listthreadids 12", CALL_PIDINFO, self, F_LISTTHREADIDS, 0, list, 12);

    uint64_t sched;
    pi("threadschedinfo own", CALL_PIDINFO, self, F_THREADSCHEDINFO, me, &sched, sizeof sched);
    pi("threadschedinfo other", CALL_PIDINFO, self, F_THREADSCHEDINFO, second_tid, &sched, sizeof sched);
    unsigned char counts[200];
    n = pi("threadcounts 8", CALL_PIDINFO, self, F_THREADCOUNTS, me, counts, 8);
    pi("threadcounts bogus", CALL_PIDINFO, self, F_THREADCOUNTS, 12345, counts, sizeof counts);

    struct proc_taskinfo ti;
    pi("taskinfo", CALL_PIDINFO, self, PROC_PIDTASKINFO, 0, &ti, sizeof ti);
    printf("  policy %d priority %d sizes %d times %d\n", ti.pti_policy, ti.pti_priority,
           ti.pti_virtual_size > 0 && ti.pti_resident_size > 0, ti.pti_total_user >= ti.pti_threads_user);
    struct proc_taskallinfo all;
    pi("taskallinfo", CALL_PIDINFO, self, PROC_PIDTASKALLINFO, 0, &all, sizeof all);
    printf("  pid %d\n", all.pbsd.pbi_pid == (uint32_t)self);
#if defined(__arm64__)
    // Rosetta runs a thread of its own, and its kernel is Apple silicon's.
    printf("  threads %d running %d\n", ti.pti_threadnum, ti.pti_numrunning);
    printf("  listed threads %d\n", pi("listthreads count", CALL_PIDINFO, self, PROC_PIDLISTTHREADS, 0, list,
                                         sizeof list) / 8);
    n = pi("threadcounts", CALL_PIDINFO, self, F_THREADCOUNTS, me, counts, sizeof counts);
    printf("  levels %u\n", *(uint16_t *)counts);
#endif

    // SETCONTROL's thread name: at most 63 characters, only for the
    // caller.
    char name[80];
    memset(name, 'n', sizeof name);
    pi("setcontrol name 64", CALL_SETCONTROL, self, 2, 0, name, 64);
    pi("setcontrol name 63", CALL_SETCONTROL, self, 2, 0, name, 63);
    pi("threadid64info", CALL_PIDINFO, self, PROC_PIDTHREADID64INFO, me, &t, sizeof t);
    printf("  name length %zu\n", strlen(t.pth_name));
    pi("setcontrol name raw", CALL_SETCONTROL, self, 2, 0, "raw", 3);
    pi("threadid64info", CALL_PIDINFO, self, PROC_PIDTHREADID64INFO, me, &t, sizeof t);
    char user[64];
    pthread_getname_np(pthread_self(), user, sizeof user);
    printf("  name \"%s\", libpthread's \"%s\"\n", t.pth_name, user);
    pi("setcontrol name bad", CALL_SETCONTROL, self, 2, 0, (void *)8, 10);
    pi("setcontrol name empty", CALL_SETCONTROL, self, 2, 0, NULL, 0);
    pi("setcontrol parent", CALL_SETCONTROL, getppid(), 2, 0, "x", 1);
    pi("setcontrol flavor 0", CALL_SETCONTROL, self, 0, 0, NULL, 0);
    pi("setcontrol flavor 5", CALL_SETCONTROL, self, 5, 0, NULL, 0);
    pi("setcontrol vm owner", CALL_SETCONTROL, self, 3, 0, NULL, 0);
    struct proc_bsdinfo b;
    pi("setcontrol pcontrol throttle", CALL_SETCONTROL, self, 1, 1, NULL, 0);
    __proc_info(CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    printf("  pcontrol %#x\n", b.pbi_flags & 0x600);
    pi("setcontrol pcontrol 4", CALL_SETCONTROL, self, 1, 4, NULL, 0);
    pi("setcontrol delay idle sleep", CALL_SETCONTROL, self, 4, 1, NULL, 0);
    __proc_info(CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    printf("  delayidlesleep %#x\n", b.pbi_flags & 0x40000);
    pi("setcontrol delay idle sleep off", CALL_SETCONTROL, self, 4, 0, NULL, 0);
    __proc_info(CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    printf("  delayidlesleep %#x\n", b.pbi_flags & 0x40000);
    pthread_setname_np("main-thread");
}

static void descriptors(void) {
    pid_t self = getpid();
    char tmpl[] = "procinfo-XXXXXX";
    int file = mkstemp(tmpl);
    char filepath[PATH_MAX];
    realpath(tmpl, filepath);
    write(file, "0123456789", 10);
    close(file);
    file = open(tmpl, O_RDONLY | O_CLOEXEC);
    lseek(file, 7, SEEK_SET);
    int dup_fd = dup(file);
    int wfile = open(tmpl, O_RDWR | O_APPEND | O_NONBLOCK);
    write(wfile, "abc", 3);
    int p[2];
    pipe(p);
    write(p[1], "xyz", 3);
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, p[0], EVFILT_READ, EV_ADD, 0, 0, (void *)0x1234);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    char shm_name[32];
    snprintf(shm_name, sizeof shm_name, "/rax-pi-%d", self);
    shm_unlink(shm_name);
    int shm = shm_open(shm_name, O_RDWR | O_CREAT, 0600);
    ftruncate(shm, 4096);

    struct proc_bsdinfo b;
    __proc_info(CALL_PIDINFO, self, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    int est = pi("listfds NULL", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, NULL, 0);
    printf("  (nfiles + 20) * 8: %d\n", est == (int)(b.pbi_nfiles + 20) * 8);
    pi("listfds NULL 12345", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, NULL, 12345);
    struct proc_fdinfo fds[64];
    pi("listfds 0", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, fds, 0);
    pi("listfds 7", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, fds, 7);
    pi("listfds 20", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, fds, 20);
    int n = pi("listfds", CALL_PIDINFO, self, PROC_PIDLISTFDS, 0, fds, sizeof fds) / (int)sizeof fds[0];
    for (int i = 0; i < n; i++) {
        int fd = fds[i].proc_fd;
        const char *what = fd == file ? "file" : fd == dup_fd ? "dup" : fd == wfile ? "wfile" : fd == p[0] ? "pipe read"
                           : fd == p[1] ? "pipe write" : fd == kq ? "kqueue" : fd == shm ? "shm" : NULL;
        if (what)
            printf("  %s type %u\n", what, fds[i].proc_fdtype);
    }

    struct vnode_fdinfowithpath vp;
    struct stat st;
    fstat(file, &st);
    struct statfs sfs;
    fstatfs(file, &sfs);
    pi("vnodepathinfo file", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, file, &vp, sizeof vp);
    printf("  openflags %#x status %#x offset %lld type %d guard %u\n", vp.pfi.fi_openflags, vp.pfi.fi_status,
           vp.pfi.fi_offset, vp.pfi.fi_type, vp.pfi.fi_guardflags);
    struct vinfo_stat *vs = &vp.pvip.vip_vi.vi_stat;
    printf("  %s\n", built_backwards(vp.pvip.vip_path, sizeof vp.pvip.vip_path));
    printf("  vtype %d path %d ino %d dev %d mode %o size %lld nlink %u blksize %d fsid %d\n", vp.pvip.vip_vi.vi_type,
           strcmp(vp.pvip.vip_path, filepath) == 0, vs->vst_ino == st.st_ino, vs->vst_dev == (uint32_t)st.st_dev,
           vs->vst_mode, vs->vst_size, vs->vst_nlink, vs->vst_blksize,
           memcmp(&vp.pvip.vip_vi.vi_fsid, &sfs.f_fsid, sizeof sfs.f_fsid) == 0);
    struct vnode_fdinfo vn;
    pi("vnodeinfo file", CALL_PIDFDINFO, self, PROC_PIDFDVNODEINFO, file, &vn, sizeof vn);
    printf("  mtime %d\n", vn.pvi.vi_stat.vst_mtime == st.st_mtimespec.tv_sec);
    pi("vnodepathinfo dup", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, dup_fd, &vp, sizeof vp);
    printf("  status %#x offset %lld\n", vp.pfi.fi_status, vp.pfi.fi_offset);
    pi("vnodepathinfo wfile", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, wfile, &vp, sizeof vp);
    printf("  openflags %#x status %#x offset %lld\n", vp.pfi.fi_openflags, vp.pfi.fi_status, vp.pfi.fi_offset);
    pi("vnodepathinfo truncated fd", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, 0x100000000ull | (unsigned)file,
       &vp, sizeof vp);
    pi("vnodepathinfo short", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, file, &vp, sizeof vp - 1);
    pi("vnodepathinfo NULL", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, file, NULL, sizeof vp);
    pi("vnodepathinfo pipe", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, p[0], &vp, sizeof vp);
    pi("vnodepathinfo kqueue", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, kq, &vp, sizeof vp);
    pi("vnodepathinfo shm", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, shm, &vp, sizeof vp);
    pi("vnodepathinfo fd 999", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, 999, &vp, sizeof vp);
    pi("vnodepathinfo fd -1", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, (uint64_t)-1, &vp, sizeof vp);
    pi("vnodepathinfo fd 100000", CALL_PIDFDINFO, self, PROC_PIDFDVNODEPATHINFO, 100000, &vp, sizeof vp);
    pi("socketinfo file", CALL_PIDFDINFO, self, PROC_PIDFDSOCKETINFO, file, &vp, sizeof vp);
    pi("pipeinfo file", CALL_PIDFDINFO, self, PROC_PIDFDPIPEINFO, file, &vp, sizeof vp);
    pi("pseminfo file", CALL_PIDFDINFO, self, PROC_PIDFDPSEMINFO, file, &vp, sizeof vp);
    pi("atalkinfo file", CALL_PIDFDINFO, self, PROC_PIDFDATALKINFO, file, &vp, sizeof vp);
    pi("channelinfo file", CALL_PIDFDINFO, self, 10, file, &vp, sizeof vp);
    pi("fd flavor 0", CALL_PIDFDINFO, self, 0, file, &vp, sizeof vp);
    pi("fd flavor 11", CALL_PIDFDINFO, self, 11, file, &vp, sizeof vp);

    struct pipe_fdinfo pr, pw;
    pi("pipeinfo read", CALL_PIDFDINFO, self, PROC_PIDFDPIPEINFO, p[0], &pr, sizeof pr);
    pi("pipeinfo write", CALL_PIDFDINFO, self, PROC_PIDFDPIPEINFO, p[1], &pw, sizeof pw);
    printf("  openflags %#x %#x status %#x %#x mode %o size %lld blksize %d peers %d\n", pr.pfi.fi_openflags,
           pw.pfi.fi_openflags, pr.pfi.fi_status, pw.pfi.fi_status, pr.pipeinfo.pipe_stat.vst_mode,
           pr.pipeinfo.pipe_stat.vst_size, pr.pipeinfo.pipe_stat.vst_blksize,
           pr.pipeinfo.pipe_handle == pw.pipeinfo.pipe_peerhandle &&
               pw.pipeinfo.pipe_handle == pr.pipeinfo.pipe_peerhandle);
    pi("pipeinfo short", CALL_PIDFDINFO, self, PROC_PIDFDPIPEINFO, p[0], &pr, sizeof pr - 1);

    struct kqueue_fdinfo kqi;
    pi("kqueueinfo", CALL_PIDFDINFO, self, PROC_PIDFDKQUEUEINFO, kq, &kqi, sizeof kqi);
    printf("  openflags %#x status %#x type %d size %lld blksize %d mode %o state %#x\n", kqi.pfi.fi_openflags,
           kqi.pfi.fi_status, kqi.pfi.fi_type, kqi.kqueueinfo.kq_stat.vst_size, kqi.kqueueinfo.kq_stat.vst_blksize,
           kqi.kqueueinfo.kq_stat.vst_mode, kqi.kqueueinfo.kq_state);
    pi("kqueueinfo work queue", CALL_PIDFDINFO, self, PROC_PIDFDKQUEUEINFO, (uint64_t)-1, &kqi, sizeof kqi);
    struct extinfo ext[4];
    pi("kqueue extinfo NULL", CALL_PIDFDINFO, self, FD_KQUEUE_EXTINFO, kq, NULL, 0);
    memset(ext, 0, sizeof ext);
    pi("kqueue extinfo", CALL_PIDFDINFO, self, FD_KQUEUE_EXTINFO, kq, ext, sizeof ext);
    printf("  ident %d filter %d flags %#x udata %#llx status %#x\n", ext[0].kev.ident == (uint64_t)p[0],
           ext[0].kev.filter, ext[0].kev.flags, ext[0].kev.udata, ext[0].status);
    pi("kqueue extinfo 103", CALL_PIDFDINFO, self, FD_KQUEUE_EXTINFO, kq, ext, 103);
    pi("kqueue extinfo work queue", CALL_PIDFDINFO, self, FD_KQUEUE_EXTINFO, (uint64_t)-1, ext, sizeof ext);

    struct pshm_fdinfo ps;
    pi("pshminfo", CALL_PIDFDINFO, self, PROC_PIDFDPSHMINFO, shm, &ps, sizeof ps);
    printf("  openflags %#x status %#x type %d mode %o name %d\n", ps.pfi.fi_openflags, ps.pfi.fi_status,
           ps.pfi.fi_type, ps.pshminfo.pshm_stat.vst_mode, strcmp(ps.pshminfo.pshm_name, shm_name) == 0);
    pi("pshminfo file", CALL_PIDFDINFO, self, PROC_PIDFDPSHMINFO, file, &ps, sizeof ps);

    // Knote user data and the workloops (none).
    uint64_t uptrs[8];
    pi("listuptrs NULL", CALL_PIDINFO, self, F_LISTUPTRS, 0, NULL, 0);
    n = pi("listuptrs", CALL_PIDINFO, self, F_LISTUPTRS, 0, uptrs, sizeof uptrs);
    printf("  first %#llx\n", n > 0 ? uptrs[0] : 0);
    pi("listuptrs 4", CALL_PIDINFO, self, F_LISTUPTRS, 0, uptrs, 4);
    pi("listdynkqueues NULL", CALL_PIDINFO, self, F_LISTDYNKQUEUES, 0, NULL, 0);
    pi("listdynkqueues", CALL_PIDINFO, self, F_LISTDYNKQUEUES, 0, uptrs, sizeof uptrs);
    unsigned char big[1300];
    pi("dynkqueueinfo NULL", CALL_PIDDYNKQUEUEINFO, self, 0, 1, NULL, 208);
    pi("dynkqueueinfo short", CALL_PIDDYNKQUEUEINFO, self, 0, 1, big, 100);
    pi("dynkqueueinfo unknown", CALL_PIDDYNKQUEUEINFO, self, 0, 1, big, 208);
    pi("dynkqueueinfo extinfo unknown", CALL_PIDDYNKQUEUEINFO, self, 1, 1, big, 208);
    pi("dynkqueueinfo flavor 2", CALL_PIDDYNKQUEUEINFO, self, 2, 1, big, 208);
    pi("vmrtfaultinfo NULL", CALL_PIDINFO, self, F_VMRTFAULTINFO, 0, NULL, 0);
    pi("vmrtfaultinfo", CALL_PIDINFO, self, F_VMRTFAULTINFO, 0, big, 560);
    pi("listfileports NULL", CALL_PIDINFO, self, PROC_PIDLISTFILEPORTS, 0, NULL, 0);
    pi("fileportinfo bogus", CALL_PIDFILEPORTINFO, self, PROC_PIDFILEPORTVNODEPATHINFO, 0x1234, big, 1200);
    pi("fileportinfo short", CALL_PIDFILEPORTINFO, self, PROC_PIDFILEPORTVNODEPATHINFO, 0x1234, big, 1199);
    pi("fileportinfo flavor 1", CALL_PIDFILEPORTINFO, self, 1, 0x1234, big, 1200);

    close(file);
    close(dup_fd);
    close(wfile);
    close(p[0]);
    close(p[1]);
    close(kq);
    close(shm);
    shm_unlink(shm_name);
    unlink(tmpl);
}

static void regions(void) {
    pid_t self = getpid();
    long page = getpagesize();
    // Tagged mappings stand alone.
    char *solo = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, VM_MAKE_TAG(240), 0);
    struct proc_regioninfo r;
    pi("regioninfo", CALL_PIDINFO, self, PROC_PIDREGIONINFO, (uint64_t)(uintptr_t)solo + 5, &r, sizeof r);
    printf("  here %d pages %llu prot %u max %u inherit %u tag %u share %u resident %u offset %llu\n",
           r.pri_address == (uint64_t)(uintptr_t)solo, r.pri_size / page, r.pri_protection, r.pri_max_protection,
           r.pri_inheritance, r.pri_user_tag, r.pri_share_mode, r.pri_pages_resident, r.pri_offset);
    solo[0] = 1;
    pi("regioninfo touched", CALL_PIDINFO, self, PROC_PIDREGIONINFO, (uint64_t)(uintptr_t)solo, &r, sizeof r);
#if defined(__arm64__)
    // (Rosetta counts the 16 KiB pages of its kernel in 4 KiB units.)
    printf("  share %u resident %u\n", r.pri_share_mode, r.pri_pages_resident);
#endif
    char *shared = mmap(NULL, page, PROT_READ, MAP_ANON | MAP_SHARED, VM_MAKE_TAG(242), 0);
    pi("regioninfo shared", CALL_PIDINFO, self, PROC_PIDREGIONINFO, (uint64_t)(uintptr_t)shared, &r, sizeof r);
    printf("  prot %u max %u inherit %u tag %u\n", r.pri_protection, r.pri_max_protection, r.pri_inheritance,
           r.pri_user_tag);
    // (The pages either side of a hole are one memory object, which the
    // share mode would show.)
    char *m = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, VM_MAKE_TAG(241), 0);
    munmap(m + page, page);
    pi("regioninfo hole", CALL_PIDINFO, self, PROC_PIDREGIONINFO, (uint64_t)(uintptr_t)(m + page), &r, sizeof r);
    printf("  next %d pages %llu tag %u\n", r.pri_address == (uint64_t)(uintptr_t)(m + 2 * page), r.pri_size / page,
           r.pri_user_tag);
    pi("regioninfo top", CALL_PIDINFO, self, PROC_PIDREGIONINFO, 0xfffffffffffff000ull, &r, sizeof r);
    pi("regioninfo short", CALL_PIDINFO, self, PROC_PIDREGIONINFO, 0, &r, sizeof r - 1);
    pi("regioninfo NULL", CALL_PIDINFO, self, PROC_PIDREGIONINFO, 0, NULL, sizeof r);

    uint64_t text = (uint64_t)(uintptr_t)_dyld_get_image_header(0);
    struct proc_regionwithpathinfo rp;
    pi("regionpathinfo text", CALL_PIDINFO, self, PROC_PIDREGIONPATHINFO, text, &rp, sizeof rp);
    printf("  here %d prot %u path %d vtype %d %s\n", rp.prp_prinfo.pri_address == text,
           rp.prp_prinfo.pri_protection, strcmp(rp.prp_vip.vip_path, exe) == 0, rp.prp_vip.vip_vi.vi_type,
           built_backwards(rp.prp_vip.vip_path, sizeof rp.prp_vip.vip_path));
    pi("regionpathinfo anonymous", CALL_PIDINFO, self, PROC_PIDREGIONPATHINFO, (uint64_t)(uintptr_t)m, &rp,
       sizeof rp);
    printf("  path \"%s\" vtype %d\n", rp.prp_vip.vip_path, rp.prp_vip.vip_vi.vi_type);
    pi("regionpathinfo2 0", CALL_PIDINFO, self, F_REGIONPATHINFO2, 0, &rp, sizeof rp);
    printf("  text %d path %d resident %u\n", rp.prp_prinfo.pri_address == text,
           strcmp(rp.prp_vip.vip_path, exe) == 0, rp.prp_prinfo.pri_pages_resident);
    struct statfs sfs;
    statfs(exe, &sfs);
    uint64_t fsid = (uint32_t)sfs.f_fsid.val[0] | (uint64_t)(uint32_t)sfs.f_fsid.val[1] << 32;
    struct stat st;
    stat(exe, &st);
    pi("regionpathinfo3 dev", CALL_PIDINFO, self, F_REGIONPATHINFO3, (uint32_t)st.st_dev, &rp, sizeof rp);
    pi("regionpathinfo3 fsid", CALL_PIDINFO, self, F_REGIONPATHINFO3, fsid, &rp, sizeof rp);
    printf("  on the volume %d\n", memcmp(&rp.prp_vip.vip_vi.vi_fsid, &sfs.f_fsid, sizeof sfs.f_fsid) == 0);
    struct regionpath rpath;
    pi("regionpath text", CALL_PIDINFO, self, F_REGIONPATH, text + 5, &rpath, sizeof rpath);
    printf("  here %d path %d %s\n", rpath.addr == text, strcmp(rpath.path, exe) == 0,
           built_backwards(rpath.path, sizeof rpath.path));
    pi("regionpath 0", CALL_PIDINFO, self, F_REGIONPATH, 0, &rpath, sizeof rpath);
    printf("  text %d\n", rpath.addr == text);
    pi("regionpath short", CALL_PIDINFO, self, F_REGIONPATH, 0, &rpath, sizeof rpath - 1);
    char name[PATH_MAX];
    printf("proc_regionfilename: %d\n", proc_regionfilename(self, text, name, sizeof name) == (int)strlen(exe));
    munmap(m, page);
    munmap(m + 2 * page, page);
    munmap(solo, 2 * page);
    munmap(shared, page);

    char dir[] = "procinfo-dir-XXXXXX";
    mkdtemp(dir);
    char before[PATH_MAX], real[PATH_MAX];
    getcwd(before, sizeof before);
    chdir(dir);
    realpath(".", real);
    struct proc_vnodepathinfo vpi;
    pi("vnodepathinfo cwd", CALL_PIDINFO, self, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof vpi);
    int root_zero = 1;
    for (size_t i = 0; i < sizeof vpi.pvi_rdir; i++)
        root_zero &= ((unsigned char *)&vpi.pvi_rdir)[i] == 0;
    printf("  path %d vtype %d %s, no root %d\n", strcmp(vpi.pvi_cdir.vip_path, real) == 0,
           vpi.pvi_cdir.vip_vi.vi_type, built_backwards(vpi.pvi_cdir.vip_path, sizeof vpi.pvi_cdir.vip_path),
           root_zero);
    chdir(before);
    rmdir(dir);
}

static void dyld_and_usage(void) {
    pid_t self = getpid();
    struct task_dyld_info info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &cnt);
    printf("dyld info: %d\n", info.all_image_info_addr != 0 && info.all_image_info_size != 0);
    pi("set dyld images parent", CALL_SET_DYLD_IMAGES, getppid(), 0, 0, (void *)(uintptr_t)info.all_image_info_addr,
       (int)info.all_image_info_size);
    pi("set dyld images NULL", CALL_SET_DYLD_IMAGES, self, 0, 0, NULL, 16);

    uint8_t uuid[16] = {0};
    exe_uuid(uuid);
    for (int v = 0; v <= 6; v++) {
        unsigned char buf[512];
        memset(buf, 0xa5, sizeof buf);
        char label[32];
        snprintf(label, sizeof label, "rusage v%d", v);
        pi(label, CALL_PIDRUSAGE, self, v, 0, buf, 0);
        size_t n = 0;
        while (n < sizeof buf && !(buf[n] == 0xa5 && buf[n + 1] == 0xa5 && buf[n + 2] == 0xa5 && buf[n + 3] == 0xa5))
            n += 8;
        printf("  uuid %d written %s\n", memcmp(buf, uuid, 16) == 0, n >= 96 ? "yes" : "no");
    }
    unsigned char buf[512];
    pi("rusage v7", CALL_PIDRUSAGE, self, 7, 0, buf, 0);
    pi("rusage NULL", CALL_PIDRUSAGE, self, 6, 0, NULL, 0);
}

static void others(void) {
    pid_t self = getpid();
    struct proc_bsdinfo b;
    struct proc_bsdshortinfo s;
    pi("tbsdinfo launchd", CALL_PIDINFO, 1, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    pi("shortbsdinfo launchd", CALL_PIDINFO, 1, PROC_PIDT_SHORTBSDINFO, 0, &s, sizeof s);
    printf("  pid %u ppid %u comm \"%s\"\n", s.pbsi_pid, s.pbsi_ppid, s.pbsi_comm);
    pi("workqueueinfo kernel", CALL_PIDINFO, 0, PROC_PIDWORKQUEUEINFO, 0, &s, 16);

    int go[2];
    pipe(go);
    pid_t live = fork();
    if (live == 0) {
        char c;
        read(go[0], &c, 1);
        _exit(0);
    }
    pid_t zombie = fork();
    if (zombie == 0)
        _exit(3);
    pid_t gone = fork();
    if (gone == 0)
        _exit(0);
    waitpid(gone, NULL, 0);
    siginfo_t si;
    waitid(P_PID, zombie, &si, WEXITED | WNOWAIT);

    pi("shortbsdinfo child", CALL_PIDINFO, live, PROC_PIDT_SHORTBSDINFO, 0, &s, sizeof s);
    printf("  pid %d ppid %d\n", s.pbsi_pid == (uint32_t)live, s.pbsi_ppid == (uint32_t)self);
    pi("tbsdinfo zombie", CALL_PIDINFO, zombie, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    pi("tbsdinfo zombie arg 1", CALL_PIDINFO, zombie, PROC_PIDTBSDINFO, 1, &b, sizeof b);
    printf("  status %u xstatus %#x ppid %d\n", b.pbi_status, b.pbi_xstatus, b.pbi_ppid == (uint32_t)self);
    pi("tbsdinfo reaped", CALL_PIDINFO, gone, PROC_PIDTBSDINFO, 0, &b, sizeof b);
    pi("pathinfo reaped", CALL_PIDINFO, gone, PROC_PIDPATHINFO, 0, &b, 1024);
    pid_t kids[16];
    int n = proc_listchildpids(self, kids, sizeof kids);
    int found = 0;
    for (int i = 0; i < n; i++)
        found += (kids[i] == live) + 2 * (kids[i] == zombie);
    printf("children listed %d\n", found);
    unsigned char r[512];
    pi("rusage zombie", CALL_PIDRUSAGE, zombie, 6, 0, r, 0);
    pi("setcontrol child", CALL_SETCONTROL, live, 2, 0, "x", 1);
    pi("set dyld images child", CALL_SET_DYLD_IMAGES, live, 0, 0, r, 16);
    pi("vmrtfaultinfo child", CALL_PIDINFO, live, F_VMRTFAULTINFO, 0, r, 560);
    write(go[1], "g", 1);
    waitpid(live, NULL, 0);
    waitpid(zombie, NULL, 0);
}

int main(int argc, char **argv) {
    (void)argc;
    setvbuf(stdout, NULL, _IONBF, 0);
    char raw[PATH_MAX];
    uint32_t size = sizeof raw;
    _NSGetExecutablePath(raw, &size);
    realpath(raw, exe);
    base = strrchr(exe, '/') + 1;
    (void)argv;

    int p[2];
    pipe(p);
    pipe_r = p[0];
    pthread_t th;
    pthread_create(&th, NULL, second, NULL);
    while (__atomic_load_n(&second_tid, __ATOMIC_ACQUIRE) == 0)
        usleep(1000);
    // Let it block.
    usleep(50000);

    sizes();
    records();
    threads();
    descriptors();
    regions();
    dyld_and_usage();
    others();

    write(p[1], "x", 1);
    pthread_join(th, NULL);
    return 0;
}
