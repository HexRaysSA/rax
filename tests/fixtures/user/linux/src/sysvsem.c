/* System V semaphores (ipc/sem.c). Sets and values (semget, SETVAL,
 * SETALL, GETALL, GETPID, the limits and errors); operation lists applied
 * all or none; waits across processes, counted by GETNCNT and GETZCNT and
 * ended by a value, a timeout (EAGAIN), a removal (EIDRM), or a signal
 * (EINTR); SEM_UNDO undone at exit, also a killed process's; status
 * (IPC_STAT, SEM_STAT, IPC_INFO, SEM_INFO, IPC_SET); access for another
 * user. Values that depend on other sets in the namespace are not
 * printed. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *info;
};

static int op(int id, unsigned short num, short o, short flg) {
    struct sembuf b = {num, o, flg};
    return semop(id, &b, 1);
}

static int ctl(int id, int num, int cmd, int val) {
    union semun u = {.val = val};
    return semctl(id, num, cmd, u);
}

static void sleep_ms(int ms) {
    struct timespec t = {0, ms * 1000000L};
    nanosleep(&t, NULL);
}

static void on_usr1(int sig) {
    (void)sig;
}

static void values(void) {
    CHECK_ERR("nsems-zero", semget(IPC_PRIVATE, 0, 0600), EINVAL);
    CHECK_ERR("nsems-too-many", semget(IPC_PRIVATE, 32001, 0600), EINVAL);
    key_t key = 0x53450000 ^ getpid();
    int id = semget(key, 3, IPC_CREAT | 0600);
    CHECK("create", id >= 0 && semget(key, 2, 0) == id);
    CHECK_ERR("key-more-sems", semget(key, 4, 0), EINVAL);
    CHECK("setval", ctl(id, 1, SETVAL, 7) == 0 && ctl(id, 1, GETVAL, 0) == 7 &&
                        ctl(id, 1, GETPID, 0) == getpid());
    CHECK_ERR("setval-range", ctl(id, 0, SETVAL, 32768), ERANGE);
    CHECK_ERR("semnum-range", ctl(id, 3, GETVAL, 0), EINVAL);
    unsigned short in[3] = {1, 2, 3}, out[3] = {0};
    union semun u = {.array = in};
    semctl(id, 0, SETALL, u);
    u.array = out;
    CHECK("setall-getall", semctl(id, 0, GETALL, u) == 0 && out[0] == 1 && out[1] == 2 && out[2] == 3);
    /* All or none, in order. */
    struct sembuf two[2] = {{0, 5, 0}, {1, -3, IPC_NOWAIT}};
    CHECK_ERR("all-or-none", semop(id, two, 2), EAGAIN);
    CHECK("undone", ctl(id, 0, GETVAL, 0) == 1);
    struct sembuf seq[2] = {{0, 2, 0}, {0, -3, 0}};
    CHECK("in-order", semop(id, seq, 2) == 0 && ctl(id, 0, GETVAL, 0) == 0);
    CHECK_ERR("efbig", op(id, 3, 1, 0), EFBIG);
    CHECK_ERR("erange", op(id, 2, 32767, 0), ERANGE);
    struct sembuf many[501];
    memset(many, 0, sizeof many);
    CHECK_ERR("e2big", semop(id, many, 501), E2BIG);
    CHECK_ERR("no-ops", semop(id, many, 0), EINVAL);
    /* Status. */
    struct semid_ds ds;
    u.buf = &ds;
    CHECK("stat", semctl(id, 0, IPC_STAT, u) == 0 && ds.sem_nsems == 3 && ds.sem_otime > 0 &&
                      ds.sem_ctime > 0 && ds.sem_perm.__key == key && ds.sem_perm.mode == 0600);
    CHECK("sem-stat-by-index", semctl(id & 0x7fff, 0, SEM_STAT, u) == id);
    struct seminfo si;
    u.info = &si;
    CHECK("ipc-info", semctl(0, 0, IPC_INFO, u) >= 0 && si.semmsl == 32000 && si.semopm == 500 &&
                          si.semvmx == 32767);
    CHECK("sem-info", semctl(0, 0, SEM_INFO, u) >= 0 && si.semusz >= 1);
    u.buf = &ds;
    semctl(id, 0, IPC_STAT, u);
    ds.sem_perm.mode = 0640;
    CHECK("ipc-set", semctl(id, 0, IPC_SET, u) == 0 && semctl(id, 0, IPC_STAT, u) == 0 &&
                         ds.sem_perm.mode == 0640);
    CHECK_ERR("bad-command", ctl(id, 0, 99, 0), EINVAL);
    semctl(id, 0, IPC_RMID);
    CHECK_ERR("removed", ctl(id, 0, GETVAL, 0), EINVAL);
}

static void waits(void) {
    int id = semget(IPC_PRIVATE, 1, 0600);
    /* A decrement waits for a value from another process. */
    pid_t c = fork();
    if (c == 0)
        _exit(op(id, 0, -1, 0) == 0 ? 0 : 1);
    sleep_ms(50);
    CHECK("ncnt", ctl(id, 0, GETNCNT, 0) == 1);
    ctl(id, 0, SETVAL, 1);
    int st = -1;
    waitpid(c, &st, 0);
    CHECK("woken-by-value", WIFEXITED(st) && WEXITSTATUS(st) == 0 && ctl(id, 0, GETVAL, 0) == 0 &&
                                ctl(id, 0, GETNCNT, 0) == 0);
    /* A timeout. */
    struct sembuf dec = {0, -1, 0};
    struct timespec t = {0, 30000000};
    CHECK_ERR("timeout", semtimedop(id, &dec, 1, &t), EAGAIN);
    t.tv_nsec = -1;
    CHECK_ERR("bad-timeout", semtimedop(id, &dec, 1, &t), EINVAL);
    /* A wait for zero, ended by removal. */
    ctl(id, 0, SETVAL, 1);
    c = fork();
    if (c == 0)
        _exit(op(id, 0, 0, 0) == -1 && errno == EIDRM ? 0 : 1);
    sleep_ms(50);
    CHECK("zcnt", ctl(id, 0, GETZCNT, 0) == 1);
    semctl(id, 0, IPC_RMID);
    waitpid(c, &st, 0);
    CHECK("removed-while-waiting", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    /* A signal ends a wait: EINTR. */
    id = semget(IPC_PRIVATE, 1, 0600);
    c = fork();
    if (c == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1;
        sigaction(SIGUSR1, &sa, NULL);
        _exit(op(id, 0, -1, 0) == -1 && errno == EINTR ? 0 : 1);
    }
    sleep_ms(50);
    kill(c, SIGUSR1);
    waitpid(c, &st, 0);
    CHECK("interrupted", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    semctl(id, 0, IPC_RMID);
}

static void undo(void) {
    int id = semget(IPC_PRIVATE, 2, 0600);
    ctl(id, 0, SETVAL, 5);
    pid_t c = fork();
    if (c == 0) {
        struct sembuf b[2] = {{0, -3, SEM_UNDO}, {1, 4, SEM_UNDO}};
        _exit(semop(id, b, 2) == 0 ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK("undo-at-exit", ctl(id, 0, GETVAL, 0) == 5 && ctl(id, 1, GETVAL, 0) == 0 &&
                              ctl(id, 0, GETPID, 0) == c);
    /* A killed process's undo too. */
    c = fork();
    if (c == 0) {
        op(id, 1, 2, SEM_UNDO);
        pause();
        _exit(0);
    }
    sleep_ms(50);
    int held = ctl(id, 1, GETVAL, 0);
    kill(c, SIGKILL);
    waitpid(c, &st, 0);
    CHECK("undo-when-killed", held == 2 && ctl(id, 1, GETVAL, 0) == 0);
    /* Clamped at 0: an increment undone after the value dropped. */
    c = fork();
    if (c == 0) {
        op(id, 0, 1, SEM_UNDO);
        ctl(id, 0, SETVAL, 0);
        op(id, 0, 1, SEM_UNDO);
        op(id, 0, -1, 0);
        _exit(0);
    }
    waitpid(c, &st, 0);
    CHECK("undo-clamped", ctl(id, 0, GETVAL, 0) == 0);
    /* Another user, and a set no one may use. */
    int locked = semget(IPC_PRIVATE, 1, 0);
    c = fork();
    if (c == 0) {
        int other = geteuid() == 0;
        if (other && (setgid(65534) || setuid(65534)))
            _exit(2);
        int r = op(locked, 0, 1, 0) == -1 && errno == EACCES && ctl(locked, 0, GETVAL, 0) == -1 &&
                errno == EACCES && (!other || (semctl(locked, 0, IPC_RMID) == -1 && errno == EPERM));
        _exit(r ? 0 : 1);
    }
    waitpid(c, &st, 0);
    CHECK("other-user", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    semctl(locked, 0, IPC_RMID);
    semctl(id, 0, IPC_RMID);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    values();
    waits();
    undo();
    FINISH();
}
