/* PID 1 of the kernel oracle's initramfs (see record-kernel.sh).
 *
 * Mounts /proc, /sys, and /dev, then runs each line of /cases.txt ("arch
 * name program stdin-or-dash args...") as a child process in a fresh
 * container of its own, as Docker ran each recording: new IPC, mount,
 * UTS, and network namespaces with a fresh /tmp, /dev/shm (without exec),
 * /dev/mqueue, and /dev/pts, the loopback interface up, in /, with the environment the Docker recordings had
 * (PATH, HOME, RAX_FIXTURE_VAR=set), standard input from the named file or
 * /dev/null, standard error discarded, and as root with the capabilities a
 * Docker container's root has by default (the rest dropped from the
 * bounding, permitted, effective, and inheritable sets). For each case it
 * writes to the console
 *
 *     @@case <arch> <name>
 *     <standard output, hex, 64 bytes a line>
 *     @@status <status>
 *
 * where the status is the exit code, or 128 + N after signal N, as a
 * shell reports it (-1 if the case ran past its 120 s limit and was
 * killed). A case runs in a process group of its own, so what it leaves
 * behind is killed with it. After the last case the machine powers off. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/capability.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LIMIT_SECONDS 120

static void out(const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t w = write(1, s, n);
        if (w <= 0)
            return;
        s += w;
        n -= (size_t)w;
    }
}

static void setup(void) {
    mkdir("/proc", 0555);
    mount("proc", "/proc", "proc", 0, NULL);
    mkdir("/sys", 0555);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mkdir("/dev", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mkdir("/dev/shm", 01777);
    mkdir("/dev/mqueue", 01777);
    mkdir("/dev/pts", 0755);
    mkdir("/tmp", 01777);
    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

/* A fresh container for the calling process (see the header). */
static void container(void) {
    unshare(CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET);
    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
    mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777");
    mount("shm", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777");
    mount("mqueue", "/dev/mqueue", "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq r = {0};
        strcpy(r.ifr_name, "lo");
        if (ioctl(s, SIOCGIFFLAGS, &r) == 0) {
            r.ifr_flags |= IFF_UP;
            ioctl(s, SIOCSIFFLAGS, &r);
        }
        close(s);
    }
    sethostname("rax-oracle", 10);
}

/* Docker's default capabilities (moby's DefaultCapabilities). */
static const int docker_caps[] = {
    CAP_CHOWN,  CAP_DAC_OVERRIDE, CAP_FSETID,   CAP_FOWNER,     CAP_MKNOD,
    CAP_NET_RAW, CAP_SETGID,      CAP_SETUID,   CAP_SETFCAP,    CAP_SETPCAP,
    CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE,
};

/* Leaves the calling process Docker's default capabilities. */
static void docker_capabilities(void) {
    unsigned long long keep = 0;
    for (size_t i = 0; i < sizeof docker_caps / sizeof docker_caps[0]; i++)
        keep |= 1ULL << docker_caps[i];
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++)
        if (!(keep & (1ULL << cap)))
            prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2] = {
        {(unsigned)keep, (unsigned)keep, (unsigned)keep},
        {(unsigned)(keep >> 32), (unsigned)(keep >> 32), (unsigned)(keep >> 32)},
    };
    syscall(SYS_capset, &h, d);
}

/* Runs one case; returns its shell status. */
static int run(char **argv, const char *input, int outfd) {
    pid_t p = fork();
    if (p == 0) {
        setpgid(0, 0);
        container();
        int in = open(input ? input : "/dev/null", O_RDONLY);
        dup2(in, 0);
        dup2(outfd, 1);
        int null = open("/dev/null", O_WRONLY);
        dup2(null, 2);
        for (int fd = 3; fd < 64; fd++)
            close(fd);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        for (int sig = 1; sig < 65; sig++)
            signal(sig, SIG_DFL);
        docker_capabilities();
        char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "HOSTNAME=rax-oracle", "HOME=/root", "RAX_FIXTURE_VAR=set", NULL};
        chdir("/");
        execve(argv[0], argv, envp);
        _exit(127);
    }
    setpgid(p, p);
    time_t start = time(NULL);
    for (;;) {
        int st;
        pid_t r = waitpid(p, &st, WNOHANG);
        if (r == p) {
            kill(-p, SIGKILL);
            return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
        }
        if (time(NULL) - start > LIMIT_SECONDS) {
            kill(-p, SIGKILL);
            waitpid(p, &st, 0);
            return -1;
        }
        struct timespec t = {0, 10 * 1000 * 1000};
        nanosleep(&t, NULL);
    }
}

int main(void) {
    setup();
    int con = open("/dev/console", O_WRONLY);
    if (con >= 0) {
        dup2(con, 1);
        dup2(con, 2);
    }
    FILE *cases = fopen("/cases.txt", "r");
    char line[1024];
    while (cases && fgets(line, sizeof line, cases)) {
        char *words[64];
        int n = 0;
        for (char *w = strtok(line, " \t\n"); w && n < 63; w = strtok(NULL, " \t\n"))
            words[n++] = w;
        if (n < 4 || words[0][0] == '#')
            continue;
        char path[256], input[256];
        snprintf(path, sizeof path, "/w/%s/%s", words[0], words[2]);
        int has_input = strcmp(words[3], "-") != 0;
        if (has_input)
            snprintf(input, sizeof input, "/w/%s", words[3]);
        char *argv[64];
        argv[0] = path;
        int argc = 1;
        for (int i = 4; i < n; i++)
            argv[argc++] = words[i];
        argv[argc] = NULL;
        /* Standard output goes to a file, read back once the case ends. */
        int fd = open("/.oracle-out", O_RDWR | O_CREAT | O_TRUNC, 0600);
        int status = run(argv, has_input ? input : NULL, fd);
        char head[600];
        snprintf(head, sizeof head, "@@case %s %s\n", words[0], words[1]);
        out(head);
        lseek(fd, 0, SEEK_SET);
        unsigned char buf[64];
        ssize_t got;
        while ((got = read(fd, buf, sizeof buf)) > 0) {
            char hex[2 * sizeof buf + 2];
            for (ssize_t i = 0; i < got; i++)
                sprintf(hex + 2 * i, "%02x", buf[i]);
            strcat(hex, "\n");
            out(hex);
        }
        close(fd);
        unlink("/.oracle-out");
        snprintf(head, sizeof head, "@@status %d\n", status);
        out(head);
    }
    out("@@done\n");
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
