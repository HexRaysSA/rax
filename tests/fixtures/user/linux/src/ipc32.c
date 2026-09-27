/* System V IPC of an i386 task (i386 only), past what libc's calls
 * through the ipc multiplexer reach: the direct calls (compat_sys_semctl,
 * compat_sys_msgctl, compat_sys_shmctl) with their struct compat_*64_ds
 * layouts and whole commands, the multiplexer's old layouts (no IPC_64)
 * with 16-bit IDs, MSGRCV's struct compat_ipc_kludge, SHMAT's stored
 * address and version check, SEMTIMEDOP's struct old_timespec32,
 * semtimedop_time64's padding, and attaches ended by SHMDT and by a
 * mapping over them. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "ipc32 is an i386 program"
#endif

#define NR_IPC 117
#define NR_SEMGET 393
#define NR_SEMCTL 394
#define NR_SHMCTL 396
#define NR_SHMAT 397
#define NR_MSGGET 399
#define NR_MSGSND 400
#define NR_MSGRCV 401
#define NR_MSGCTL 402
#define NR_SEMTIMEDOP_TIME64 420

/* The multiplexer's operations, and an operation's version 1. */
#define SEMOP 1
#define SEMCTL 3
#define SEMTIMEDOP 4
#define MSGSND 11
#define MSGRCV 12
#define MSGCTL 14
#define SHMAT 21
#define SHMDT 22
#define SHMGET 23
#define SHMCTL 24
#define VERSION_1 (1u << 16)

/* The kernel's commands (libc's IPC_STAT differs on i386), and IPC_64. */
#define K_IPC_PRIVATE 0
#define K_IPC_NOWAIT 04000
#define K_IPC_RMID 0
#define K_IPC_SET 1
#define K_IPC_STAT 2
#define K_IPC_INFO 3
#define K_SHM_INFO 14
#define K_GETVAL 12
#define K_SETVAL 16
#define K_SEM_INFO 19
#define K_IPC_64 0x100

static long ipc(unsigned call, long first, long second, long third, const void *ptr,
                long fifth) {
    return syscall(NR_IPC, call, first, second, third, ptr, fifth);
}

static uint16_t u16_at(const unsigned char *b, int at) {
    uint16_t v;
    memcpy(&v, b + at, 2);
    return v;
}

static uint32_t u32_at(const unsigned char *b, int at) {
    uint32_t v;
    memcpy(&v, b + at, 4);
    return v;
}

/* Whether b[from..to) still holds the 0xEE fill (nothing written past a
 * structure's end). */
static int untouched(const unsigned char *b, int from, int to) {
    for (int i = from; i < to; i++)
        if (b[i] != 0xEE) return 0;
    return 1;
}

struct sop {
    uint16_t num;
    int16_t op, flg;
};

struct msg {
    int32_t type;
    char text[12];
};

int main(void) {
    unsigned char ds[128];
    union {
        int val;
        void *buf;
    } arg;

    /* Semaphores through the multiplexer: the union's word, and the
     * structure IPC_64 selects. */
    int sem = syscall(NR_SEMGET, K_IPC_PRIVATE, 3, 0600);
    CHECK("semget", sem >= 0);
    arg.val = 7;
    CHECK("ipc-setval", ipc(SEMCTL, sem, 1, K_SETVAL, &arg, 0) == 0);
    CHECK("ipc-getval", ipc(SEMCTL, sem, 1, K_GETVAL, &arg, 0) == 7);
    arg.buf = ds;
    memset(ds, 0xEE, sizeof ds);
    CHECK("ipc-stat-64", ipc(SEMCTL, sem, 0, K_IPC_STAT | K_IPC_64, &arg, 0) == 0 &&
                             u16_at(ds, 20) == 0600 && u32_at(ds, 52) == 3 &&
                             untouched(ds, 64, 72));
    memset(ds, 0xEE, sizeof ds);
    CHECK("ipc-stat-old", ipc(SEMCTL, sem, 0, K_IPC_STAT, &arg, 0) == 0 &&
                              u16_at(ds, 12) == 0600 && u16_at(ds, 40) == 3 &&
                              untouched(ds, 44, 52));
    CHECK_ERR("ipc-semctl-null", ipc(SEMCTL, sem, 0, K_IPC_STAT, 0, 0), EINVAL);
    CHECK_ERR("ipc-semctl-fault", ipc(SEMCTL, sem, 0, K_IPC_STAT, (void *)16, 0), EFAULT);
    CHECK_ERR("ipc-unknown", ipc(99, 0, 0, 0, 0, 0), ENOSYS);

    /* The direct call: struct compat_semid64_ds, the command whole. */
    memset(ds, 0xEE, sizeof ds);
    CHECK("semctl-stat", syscall(NR_SEMCTL, sem, 0, K_IPC_STAT, ds) == 0 &&
                             u32_at(ds, 52) == 3 && untouched(ds, 64, 72));
    CHECK("semctl-stat-64-is-id", syscall(NR_SEMCTL, sem, 0, K_IPC_STAT | K_IPC_64, ds) == sem);
    CHECK("semctl-setval-64", syscall(NR_SEMCTL, sem, 2, K_SETVAL | K_IPC_64, 9) == 0 &&
                                  syscall(NR_SEMCTL, sem, 2, K_GETVAL, 0) == 9);
    CHECK_ERR("semctl-getval-64", syscall(NR_SEMCTL, sem, 2, K_GETVAL | K_IPC_64, 0), EINVAL);
    CHECK("sem-info-64-is-ipc-info",
          syscall(NR_SEMCTL, 0, 0, K_SEM_INFO | K_IPC_64, ds) >= 0 && u32_at(ds, 28) == 20 &&
              u32_at(ds, 36) == 32767);
    CHECK_ERR("semctl-rmid-64", syscall(NR_SEMCTL, sem, 0, K_IPC_RMID | K_IPC_64, 0), EINVAL);

    /* struct compat_ipc_perm's 16-bit IDs. */
    CHECK("semctl-stat-again", syscall(NR_SEMCTL, sem, 0, K_IPC_STAT, ds) == 0);
    uint32_t uid = 70000;
    memcpy(ds + 4, &uid, 4);
    CHECK("set-uid-70000", syscall(NR_SEMCTL, sem, 0, K_IPC_SET, ds) == 0);
    CHECK("old-uid-overflow", ipc(SEMCTL, sem, 0, K_IPC_STAT, &arg, 0) == 0 &&
                                  u16_at(ds, 4) == 65534);
    uint16_t low = 0xFFFF;
    memcpy(ds + 4, &low, 2);
    CHECK("old-set-65535", ipc(SEMCTL, sem, 0, K_IPC_SET, &arg, 0) == 0 &&
                               syscall(NR_SEMCTL, sem, 0, K_IPC_STAT, ds) == 0 &&
                               u32_at(ds, 4) == 65535);
    uid = 0xFFFFFFFF;
    memcpy(ds + 4, &uid, 4);
    CHECK_ERR("set-uid-invalid", syscall(NR_SEMCTL, sem, 0, K_IPC_SET, ds), EINVAL);

    /* Timeouts: SEMTIMEDOP's struct old_timespec32, semtimedop_time64's
     * padding; a decrement of a zero semaphore without waiting. */
    struct sop dec = {0, -1, K_IPC_NOWAIT};
    int32_t ts32[4] = {5, 1000, 0x7FFFFFFF, 0x7FFFFFFF};
    CHECK_ERR("semtimedop-time32", ipc(SEMTIMEDOP, sem, 1, 0, &dec, (long)ts32), EAGAIN);
    int32_t bad32[2] = {0, 1000000000};
    CHECK_ERR("semtimedop-time32-invalid", ipc(SEMTIMEDOP, sem, 1, 0, &dec, (long)bad32),
              EINVAL);
    uint32_t ts64[4] = {0, 0, 1000, 0xFFFFFFFF};
    CHECK_ERR("semtimedop-time64-padding", syscall(NR_SEMTIMEDOP_TIME64, sem, &dec, 1, ts64),
              EAGAIN);
    CHECK_ERR("ipc-semop", ipc(SEMOP, sem, 1, 0, &dec, 0), EAGAIN);
    CHECK("semctl-rmid", syscall(NR_SEMCTL, sem, 0, K_IPC_RMID, 0) == 0);

    /* Messages: struct compat_msgbuf's 32-bit type. */
    int q = syscall(NR_MSGGET, K_IPC_PRIVATE, 0600);
    CHECK("msgget", q >= 0);
    struct msg m = {3, "abc"};
    CHECK("msgsnd", syscall(NR_MSGSND, q, &m, 3, 0) == 0);
    m = (struct msg){5, "de"};
    CHECK("ipc-msgsnd", ipc(MSGSND, q, 2, 0, &m, 0) == 0);
    memset(&m, 0xEE, sizeof m);
    CHECK("msgrcv-negative-type", syscall(NR_MSGRCV, q, &m, 8, -5, K_IPC_NOWAIT) == 3 &&
                                      m.type == 3 && !memcmp(m.text, "abc", 3) &&
                                      (unsigned char)m.text[3] == 0xEE);
    struct {
        void *msgp;
        int32_t msgtyp;
    } kludge = {&m, 5};
    CHECK("ipc-msgrcv-kludge", ipc(MSGRCV, q, 8, K_IPC_NOWAIT, &kludge, 0) == 2 &&
                                   m.type == 5 && !memcmp(m.text, "de", 2));
    CHECK_ERR("ipc-msgrcv-v1", ipc(MSGRCV | VERSION_1, q, 8, K_IPC_NOWAIT, &m, 5), ENOMSG);
    CHECK_ERR("ipc-msgrcv-negative-size", ipc(MSGRCV, q, -1, 0, &kludge, 0), EINVAL);
    CHECK_ERR("msgrcv-negative-size", syscall(NR_MSGRCV, q, &m, -1, 0, K_IPC_NOWAIT), EINVAL);
    CHECK_ERR("ipc-msgrcv-null-kludge", ipc(MSGRCV, q, 8, K_IPC_NOWAIT, 0, 0), EINVAL);
    CHECK("msgsnd-again", syscall(NR_MSGSND, q, &m, 2, 0) == 0);
    memset(ds, 0xEE, sizeof ds);
    CHECK("msgctl-stat", syscall(NR_MSGCTL, q, K_IPC_STAT, ds) == 0 && u32_at(ds, 60) == 2 &&
                             u32_at(ds, 64) == 1 && u32_at(ds, 68) == 16384 &&
                             u32_at(ds, 72) == (uint32_t)getpid() && untouched(ds, 88, 96));
    memset(ds, 0xEE, sizeof ds);
    CHECK("ipc-msgctl-old", ipc(MSGCTL, q, K_IPC_STAT, 0, ds, 0) == 0 && u16_at(ds, 44) == 2 &&
                                u16_at(ds, 46) == 1 && u16_at(ds, 48) == 16384 &&
                                u16_at(ds, 50) == (uint16_t)getpid() && untouched(ds, 56, 64));
    uint16_t qbytes = 100;
    memcpy(ds + 48, &qbytes, 2);
    CHECK("ipc-msgctl-old-set", ipc(MSGCTL, q, K_IPC_SET, 0, ds, 0) == 0 &&
                                    syscall(NR_MSGCTL, q, K_IPC_STAT, ds) == 0 &&
                                    u32_at(ds, 68) == 100);
    CHECK("msgctl-stat-64-is-id", syscall(NR_MSGCTL, q, K_IPC_STAT | K_IPC_64, ds) == q);
    CHECK_ERR("msgctl-set-64", syscall(NR_MSGCTL, q, K_IPC_SET | K_IPC_64, ds), EINVAL);
    CHECK("msgctl-rmid", syscall(NR_MSGCTL, q, K_IPC_RMID, 0) == 0);

    /* Shared memory: SHMAT's stored address, the layouts, whole commands,
     * and the ends of attaches. */
    int shm = ipc(SHMGET, K_IPC_PRIVATE, 5000, 0600, 0, 0);
    CHECK("ipc-shmget", shm >= 0);
    uint32_t raddr = 0;
    CHECK("ipc-shmat", ipc(SHMAT, shm, 0, (long)&raddr, 0, 0) == 0 && raddr != 0);
    CHECK_ERR("ipc-shmat-v1", ipc(SHMAT | VERSION_1, shm, 0, (long)&raddr, 0, 0), EINVAL);
    memset(ds, 0xEE, sizeof ds);
    CHECK("shmctl-stat", syscall(NR_SHMCTL, shm, K_IPC_STAT, ds) == 0 && u32_at(ds, 36) == 5000 &&
                             u32_at(ds, 72) == 1 && untouched(ds, 84, 92));
    memset(ds, 0xEE, sizeof ds);
    CHECK("ipc-shmctl-old", ipc(SHMCTL, shm, K_IPC_STAT, 0, ds, 0) == 0 &&
                                u32_at(ds, 16) == 5000 && u16_at(ds, 36) == 1 &&
                                untouched(ds, 48, 56));
    CHECK_ERR("shmctl-stat-64", syscall(NR_SHMCTL, shm, K_IPC_STAT | K_IPC_64, ds), EINVAL);
    memset(ds, 0xEE, sizeof ds);
    CHECK("shmctl-info", syscall(NR_SHMCTL, 0, K_IPC_INFO, ds) >= 0 &&
                             u32_at(ds, 0) == 0x7FFFFFFF && untouched(ds, 36, 44));
    memset(ds, 0xEE, sizeof ds);
    CHECK("ipc-shmctl-info-old", ipc(SHMCTL, 0, K_IPC_INFO, 0, ds, 0) >= 0 &&
                                     u32_at(ds, 0) == 0x7FFFFFFF && untouched(ds, 20, 28));
    memset(ds, 0xEE, sizeof ds);
    CHECK("shmctl-shm-info", syscall(NR_SHMCTL, 0, K_SHM_INFO, ds) >= 0 && u32_at(ds, 0) >= 1 &&
                                 untouched(ds, 24, 32));
    CHECK("ipc-shmdt", ipc(SHMDT, 0, 0, 0, (void *)raddr, 0) == 0 &&
                           syscall(NR_SHMCTL, shm, K_IPC_STAT, ds) == 0 && u32_at(ds, 72) == 0);
    void *at = (void *)syscall(NR_SHMAT, shm, 0, 0);
    CHECK("shmat", at != (void *)-1 && syscall(NR_SHMCTL, shm, K_IPC_STAT, ds) == 0 &&
                       u32_at(ds, 72) == 1);
    CHECK("mmap-over-attach",
          mmap(at, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) ==
                  at &&
              syscall(NR_SHMCTL, shm, K_IPC_STAT, ds) == 0 && u32_at(ds, 72) == 0);
    CHECK("shmctl-rmid", syscall(NR_SHMCTL, shm, K_IPC_RMID, 0) == 0);
    FINISH();
}
