/* System V message queues (ipc/msg.c). Queues and their status; msgsnd's
 * and msgrcv's checks in order; types (the first, a given type, any but a
 * type, the least type up to a bound); E2BIG and MSG_NOERROR; ENOMSG; a
 * full queue (EAGAIN, and a sender waiting for room); receivers waiting
 * across processes, ended by a message, a removal (EIDRM), or a handled
 * signal (EINTR, even with SA_RESTART); the sender and receiver
 * processes in the status; IPC_SET; access for another user. Values that
 * depend on other queues in the namespace are not printed. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

/* linux/msg.h: musl does not define it. */
#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

struct m {
    long type;
    char text[8192];
};

static struct m buf;

static int snd(int id, long type, const char *text, size_t len, int flg) {
    struct m b;
    b.type = type;
    memcpy(b.text, text, len);
    return msgsnd(id, &b, len, flg);
}

static void sleep_ms(int ms) {
    struct timespec t = {0, ms * 1000000L};
    nanosleep(&t, NULL);
}

static void on_usr1(int sig) {
    (void)sig;
}

static void basics(void) {
    int id = msgget(IPC_PRIVATE, 0600);
    CHECK("create", id >= 0);
    CHECK_ERR("send-bad-type-pointer", msgsnd(id, (void *)8, 1, 0), EFAULT);
    CHECK_ERR("send-type-zero", snd(id, 0, "x", 1, 0), EINVAL);
    buf.type = 1;
    CHECK_ERR("send-too-big", msgsnd(id, &buf, 8193, 0), EINVAL);
    CHECK_ERR("send-bad-id", snd(-1, 1, "x", 1, 0), EINVAL);
    snd(id, 3, "ccc", 3, 0);
    snd(id, 1, "aaa", 3, 0);
    snd(id, 2, "bbb", 3, 0);
    snd(id, 1, "ddd", 3, 0);
    CHECK("least-type", msgrcv(id, &buf, 16, -2, 0) == 3 && buf.type == 1 && !memcmp(buf.text, "aaa", 3));
    CHECK("given-type", msgrcv(id, &buf, 16, 2, 0) == 3 && buf.type == 2);
    CHECK("except-type", msgrcv(id, &buf, 16, 1, MSG_EXCEPT) == 3 && buf.type == 3);
    CHECK_ERR("no-message", msgrcv(id, &buf, 16, 7, IPC_NOWAIT), ENOMSG);
    CHECK_ERR("too-big", msgrcv(id, &buf, 2, 0, 0), E2BIG);
    CHECK("noerror-cuts", msgrcv(id, &buf, 2, 0, MSG_NOERROR) == 2 && !memcmp(buf.text, "dd", 2));
    CHECK_ERR("copy-needs-nowait", msgrcv(id, &buf, 16, 0, MSG_COPY), EINVAL);
    CHECK_ERR("negative-size", msgrcv(id, &buf, (size_t)-1, 0, 0), EINVAL);
    /* A full queue. */
    memset(buf.text, 7, sizeof buf.text);
    buf.type = 1;
    msgsnd(id, &buf, 8192, 0);
    msgsnd(id, &buf, 8192, 0);
    CHECK_ERR("full", msgsnd(id, &buf, 1, IPC_NOWAIT), EAGAIN);
    struct msqid_ds ds;
    CHECK("stat", msgctl(id, IPC_STAT, &ds) == 0 && ds.msg_qnum == 2 && ds.__msg_cbytes == 16384 &&
                      ds.msg_qbytes == 16384 && ds.msg_lspid == getpid() && ds.msg_lrpid == getpid() &&
                      ds.msg_stime > 0 && ds.msg_rtime > 0 && ds.msg_perm.mode == 0600);
    /* A sender waits for room. */
    pid_t c = fork();
    if (c == 0)
        _exit(snd(id, 9, "late", 4, 0) == 0 ? 0 : 1);
    sleep_ms(50);
    int st;
    CHECK("sender-waiting", waitpid(c, &st, WNOHANG) == 0);
    msgrcv(id, &buf, sizeof buf.text, 0, 0);
    waitpid(c, &st, 0);
    CHECK("sender-woken", WIFEXITED(st) && WEXITSTATUS(st) == 0 && msgctl(id, IPC_STAT, &ds) == 0 &&
                              ds.msg_qnum == 2 && ds.msg_lspid == c);
    CHECK("msg-stat-by-index", msgctl(id & 0x7fff, MSG_STAT, &ds) == id);
    struct msginfo mi;
    CHECK("ipc-info", msgctl(0, IPC_INFO, (struct msqid_ds *)&mi) >= 0 && mi.msgmax == 8192 &&
                          mi.msgmnb == 16384 && mi.msgssz == 16);
    CHECK("msg-info", msgctl(0, MSG_INFO, (struct msqid_ds *)&mi) >= 0 && mi.msgpool >= 1);
    msgctl(id, IPC_STAT, &ds);
    ds.msg_qbytes = 100;
    ds.msg_perm.mode = 0640;
    CHECK("ipc-set", msgctl(id, IPC_SET, &ds) == 0 && msgctl(id, IPC_STAT, &ds) == 0 &&
                         ds.msg_qbytes == 100 && ds.msg_perm.mode == 0640);
    CHECK_ERR("bad-command", msgctl(id, 99, &ds), EINVAL);
    msgctl(id, IPC_RMID, NULL);
    CHECK_ERR("removed", msgctl(id, IPC_STAT, &ds), EINVAL);
}

static void receivers(void) {
    int id = msgget(IPC_PRIVATE, 0600);
    /* Waiting for a type another process sends. */
    pid_t c = fork();
    if (c == 0)
        _exit(msgrcv(id, &buf, 16, 5, 0) == 3 && !memcmp(buf.text, "yes", 3) ? 0 : 1);
    sleep_ms(50);
    snd(id, 4, "no", 2, 0);
    sleep_ms(20);
    snd(id, 5, "yes", 3, 0);
    int st;
    waitpid(c, &st, 0);
    struct msqid_ds ds;
    CHECK("receiver-woken", WIFEXITED(st) && WEXITSTATUS(st) == 0 && msgctl(id, IPC_STAT, &ds) == 0 &&
                                ds.msg_qnum == 1 && ds.msg_lrpid == c);
    /* Removed while waiting. */
    c = fork();
    if (c == 0)
        _exit(msgrcv(id, &buf, 16, 9, 0) == -1 && errno == EIDRM ? 0 : 1);
    sleep_ms(50);
    msgctl(id, IPC_RMID, NULL);
    waitpid(c, &st, 0);
    CHECK("removed-while-waiting", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* A handled signal ends a wait with EINTR, SA_RESTART or not
     * (-ERESTARTNOHAND restarts only when no handler runs). */
    id = msgget(IPC_PRIVATE, 0600);
    for (int restart = 0; restart < 2; restart++) {
        c = fork();
        if (c == 0) {
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = on_usr1;
            sa.sa_flags = restart ? SA_RESTART : 0;
            sigaction(SIGUSR1, &sa, NULL);
            _exit(msgrcv(id, &buf, 16, 0, 0) == -1 && errno == EINTR ? 0 : 1);
        }
        sleep_ms(50);
        kill(c, SIGUSR1);
        waitpid(c, &st, 0);
        CHECK(restart ? "signal-interrupts-sa-restart" : "signal-interrupts",
              WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    /* Another user, and a queue no one may use. */
    int locked = msgget(IPC_PRIVATE, 0);
    c = fork();
    if (c == 0) {
        int other = geteuid() == 0;
        if (other && (setgid(65534) || setuid(65534)))
            _exit(2);
        int r = snd(locked, 1, "x", 1, IPC_NOWAIT) == -1 && errno == EACCES &&
                msgrcv(locked, &buf, 16, 0, IPC_NOWAIT) == -1 && errno == EACCES &&
                (!other || (msgctl(locked, IPC_RMID, NULL) == -1 && errno == EPERM));
        _exit(r ? 0 : 1);
    }
    waitpid(c, &st, 0);
    CHECK("other-user", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    msgctl(locked, IPC_RMID, NULL);
    msgctl(id, IPC_RMID, NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    basics();
    receivers();
    FINISH();
}
