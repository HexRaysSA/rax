// kern.procargs2 and kern.procargs of the calling process: the argument
// count, the executable path, the arguments and environment as exec laid
// them out, read from memory as it is now (an argument changed in place
// shows); the length a size query gives; a short buffer (the kernel's old
// copy leaves it zero); the path procargs appends after its marker; the
// buffer-size refusals; the same in a forked child; and a write refused.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static char buf[1 << 20] __attribute__((aligned(16)));

static int query(int which, pid_t pid, void *out, size_t *len) {
    int mib[3] = {CTL_KERN, which, pid};
    errno = 0;
    return sysctl(mib, 3, out, len, NULL, 0) == 0 ? 0 : errno;
}

// Walks procargs2's layout: argc, the path and its padding, argv, envp.
static void report(const char *who, char **argv, int argc) {
    size_t need = 0;
    int r = query(KERN_PROCARGS2, getpid(), NULL, &need);
    size_t len = sizeof buf;
    int r2 = query(KERN_PROCARGS2, getpid(), buf, &len);
    printf("%s: size query %d, read %d, sizes agree %d\n", who, r, r2, need == len);
    if (r2) return;
    const char *p = buf + 4, *end = buf + len;
    int n;
    memcpy(&n, buf, 4);
    printf("%s: argc %d (main's %d), path %s\n", who, n, argc, p);
    p += strlen(p) + 1;
    int pad = 0;
    while (p < end && *p == 0) p++, pad++;
    printf("%s: padding ok %d\n", who, pad < 8);
    for (int i = 0; i < n && p < end; i++) {
        printf("%s: argv[%d] %s (same %d)\n", who, i, p, strcmp(p, argv[i]) == 0);
        p += strlen(p) + 1;
    }
    int envs = 0, same = 1;
    for (char **e = environ; *e && p < end; e++, envs++) {
        same &= strcmp(p, *e) == 0;
        p += strlen(p) + 1;
    }
    printf("%s: environment strings follow %d (%d)\n", who, same, envs > 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    report("self", argv, argc);

    // The buffer-size rules: none, one too large, smaller than argc.
    size_t len = 0;
    printf("empty buffer: %d\n", query(KERN_PROCARGS2, getpid(), buf, &len));
    len = (1 << 20) + 5;
    printf("oversized buffer: %d\n", query(KERN_PROCARGS2, getpid(), buf, &len));
    len = 3;
    printf("below argc: %d\n", query(KERN_PROCARGS2, getpid(), buf, &len));
    len = 1;
    printf("procargs one byte: %d len=%zu\n", query(KERN_PROCARGS, getpid(), buf, &len), len);

    // A buffer shorter than the area gets zeros where the old copy left them.
    memset(buf, 0x55, sizeof buf);
    len = 68;
    int r = query(KERN_PROCARGS2, getpid(), buf, &len);
    int zero = 1;
    for (int i = 4; i < 68; i++) zero &= buf[i] == 0;
    printf("short buffer: %d len=%zu zero=%d untouched after=%d\n", r, len, zero,
           (unsigned char)buf[68] == 0x55);

    // procargs: the area, then (with room) 0, the marker, 0, the path, 0.
    size_t area = sizeof buf;
    query(KERN_PROCARGS2, getpid(), buf, &area);
    area -= 4;
    size_t need = 0;
    r = query(KERN_PROCARGS, getpid(), NULL, &need);
    printf("procargs size query: %d, adds path room %d\n", r, need >= area + 1024 + 24);
    memset(buf, 0x55, sizeof buf);
    len = need;
    r = query(KERN_PROCARGS, getpid(), buf, &len);
    size_t at = (area + 3) & ~(size_t)3;
    uint32_t w[3];
    memcpy(w, buf + at, sizeof w);
    printf("procargs: %d path %s, appended %d marker %#x %#x %#x path again %d\n", r, buf, len > area,
           w[0], w[1], w[2], strcmp(buf + at + 12, buf) == 0);
    memset(buf, 0x55, sizeof buf);
    len = area;
    r = query(KERN_PROCARGS, getpid(), buf, &len);
    printf("procargs exact: %d nothing appended %d\n", r, len == area && (unsigned char)buf[area] == 0x55);

    // Memory as it is now.
    char saved = argv[0][0];
    argv[0][0] = 'X';
    len = sizeof buf;
    query(KERN_PROCARGS2, getpid(), buf, &len);
    const char *p = buf + 4;
    p += strlen(p) + 1;
    while (*p == 0) p++;
    printf("changed argv[0] shows: %d\n", p[0] == 'X');
    argv[0][0] = saved;

    // A write is refused.
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, getpid()};
    int v = 1;
    len = sizeof buf;
    errno = 0;
    r = sysctl(mib, 3, buf, &len, &v, sizeof v);
    printf("write: %d\n", r ? errno : 0);

    pid_t pid = fork();
    if (pid == 0) {
        report("child", argv, argc);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    return 0;
}
