// csops and csops_audittoken: what the kernel reports of the process's
// code signature (status flags, cdhash, slice offset, identity, team ID,
// entitlements in XML and DER, the signature blob, validation category)
// with each call's size rules and errors; the flags a process changes
// (hard, kill, restrict, set status, installer, library validation, and
// invalidation, which kills a process with CS_KILL, as marking an invalid
// process killable does); audit-token checks;
// questions about another process; and a copy of the program re-signed
// by codesign with an identifier, entitlements, and the hardened runtime,
// reporting on itself.
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);

enum {
    STATUS = 0,
    MARKINVALID = 1,
    MARKHARD = 2,
    MARKKILL = 3,
    CDHASH = 5,
    PIDOFFSET = 6,
    ENTITLEMENTS = 7,
    MARKRESTRICT = 8,
    SET_STATUS = 9,
    BLOB = 10,
    IDENTITY = 11,
    CLEARINSTALLER = 12,
    CLEARPLATFORM = 13,
    TEAMID = 14,
    CLEAR_LV = 15,
    DER_ENTITLEMENTS = 16,
    VALIDATION_CATEGORY = 17,
    CDHASH_WITH_INFO = 18,
};

static int call(pid_t pid, unsigned op, void *buf, size_t size) {
    errno = 0;
    return csops(pid, op, buf, size) == 0 ? 0 : errno;
}

static uint32_t be32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint32_t status(void) {
    uint32_t f = 0;
    call(0, STATUS, &f, sizeof f);
    return f;
}

// Everything a process may ask about itself, printed as the same for a
// native and an emulated run.
static void report(const char *who) {
    unsigned char buf[65536];
    printf("%s: status %#x\n", who, status());
    printf("%s: status without a buffer: %d\n", who, call(0, STATUS, NULL, 0));
    unsigned char hash[20];
    int r = call(0, CDHASH, hash, sizeof hash);
    int r2 = call(0, CDHASH, hash, 19);
    unsigned char info[21];
    int r3 = call(0, CDHASH_WITH_INFO, info, sizeof info);
    printf("%s: cdhash %d, 19 bytes %d, with info %d\n", who, r, r2, r3);
    uint64_t off = 1;
    r = call(0, PIDOFFSET, &off, sizeof off);
    printf("%s: slice offset %d %s\n", who, r, off ? "nonzero" : "zero");
    for (unsigned op = IDENTITY; op <= TEAMID; op += TEAMID - IDENTITY) {
        const char *what = op == IDENTITY ? "identity" : "team";
        memset(buf, 0, sizeof buf);
        r = call(0, op, buf, 7);
        int small = call(0, op, buf, 9);
        uint32_t len = be32(buf + 4);
        memset(buf, 0, sizeof buf);
        int full = call(0, op, buf, sizeof buf);
        printf("%s: %s %d [%s], small %d %d len=%u\n", who, what, full, full ? "" : (char *)buf + 8, r, small,
               len);
    }
    unsigned ents[] = {ENTITLEMENTS, DER_ENTITLEMENTS, BLOB};
    const char *names[] = {"entitlements", "der entitlements", "blob"};
    for (int i = 0; i < 3; i++) {
        memset(buf, 0, sizeof buf);
        r = call(0, ents[i], buf, 8);
        uint32_t magic = be32(buf), len = be32(buf + 4);
        memset(buf, 0, sizeof buf);
        int full = call(0, ents[i], buf, sizeof buf);
        int tiny = call(0, ents[i], buf, 4);
        printf("%s: %s %d magic %#x, probe %d len>8 %d, tiny %d\n", who, names[i], full, be32(buf), r, len > 8,
               tiny);
        (void)magic;
        if (ents[i] == ENTITLEMENTS && full == 0 && be32(buf) == 0xfade7171) {
            buf[be32(buf + 4)] = 0;
            printf("%s: has get-task-allow %d\n", who, strstr((char *)buf + 8, "get-task-allow") != NULL);
        }
    }
    uint32_t cat = 0;
    r = call(0, VALIDATION_CATEGORY, &cat, sizeof cat);
    printf("%s: category %d %u\n", who, r, cat);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) {
        report(argv[1]);
        return 0;
    }
    report("self");

    // The flags a process may change.
    printf("unknown op: %d\n", call(0, 99, NULL, 0));
    printf("clear platform: %d\n", call(0, CLEARPLATFORM, NULL, 0));
    printf("clear library validation: %d\n", call(0, CLEAR_LV, NULL, 0));
    uint32_t want = 0x800 | 0x1 | 0x10000; // CS_RESTRICT, and bits it may not set
    printf("set status small: %d\n", call(0, SET_STATUS, &want, 2));
    printf("set status: %d -> %#x\n", call(0, SET_STATUS, &want, sizeof want), status());
    printf("mark hard: %d -> %#x\n", call(0, MARKHARD, NULL, 0), status());
    printf("mark restrict: %d -> %#x\n", call(0, MARKRESTRICT, NULL, 0), status());
    printf("clear installer: %d -> %#x\n", call(0, CLEARINSTALLER, NULL, 0), status());

    // Audit tokens.
    audit_token_t tok;
    mach_msg_type_number_t n = TASK_AUDIT_TOKEN_COUNT;
    task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&tok, &n);
    uint32_t f = 0;
    errno = 0;
    int r = csops_audittoken(getpid(), STATUS, &f, sizeof f, &tok);
    printf("audit token: %d match=%d\n", r ? errno : 0, f == status());
    tok.val[7]++;
    errno = 0;
    r = csops_audittoken(getpid(), STATUS, &f, sizeof f, &tok);
    printf("stale audit token: %d\n", r ? errno : 0);
    errno = 0;
    r = csops_audittoken(getpid(), STATUS, &f, sizeof f, NULL);
    printf("no audit token: %d\n", r ? errno : 0);

    // Another process: launchd.
    f = 0;
    printf("launchd status: %d %#x\n", call(1, STATUS, &f, sizeof f), f);
    printf("launchd mark hard: %d\n", call(1, MARKHARD, NULL, 0));
    printf("no such process: %d\n", call(99999, STATUS, &f, sizeof f));

    // Marked killable, a process dies when invalidated (or at once when it
    // is not valid).
    pid_t pid = fork();
    if (pid == 0) {
        printf("mark kill: %d -> %#x\n", call(0, MARKKILL, NULL, 0), status());
        call(0, MARKINVALID, NULL, 0);
        printf("child survived\n");
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("invalidated child: signaled=%d sig=%d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);

    // A copy re-signed with an identifier, entitlements, and the hardened
    // runtime.
    char self[4096], copy[4200], ents[4200];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char dir[] = "/tmp/rax-codesign-XXXXXX";
    if (!mkdtemp(dir)) return 1;
    snprintf(copy, sizeof copy, "%s/signed", dir);
    snprintf(ents, sizeof ents, "%s/ents.plist", dir);
    FILE *e = fopen(ents, "w");
    fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
          "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>"
          "<key>com.apple.security.get-task-allow</key><true/>"
          "<key>com.apple.security.cs.allow-jit</key><true/></dict></plist>\n",
          e);
    fclose(e);
    char *cp[] = {"/bin/cp", self, copy, NULL};
    if (posix_spawn(&pid, cp[0], NULL, NULL, cp, environ) == 0) waitpid(pid, &st, 0);
    char *sign[] = {"/usr/bin/codesign", "-f", "-s", "-", "-i", "org.rax.fixture.signed", "-o", "runtime",
                    "--entitlements", ents, copy, NULL};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    st = -1;
    if (posix_spawn(&pid, sign[0], &fa, NULL, sign, environ) == 0) waitpid(pid, &st, 0);
    printf("signed: %d\n", st);
    char *run[] = {copy, "signed copy", NULL};
    if (posix_spawn(&pid, copy, NULL, NULL, run, environ) == 0) waitpid(pid, &st, 0);
    printf("signed copy: %d\n", st);
    unlink(copy);
    unlink(ents);
    rmdir(dir);
    return 0;
}
