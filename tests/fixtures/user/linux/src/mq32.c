/* POSIX message queues of an i386 task (i386 only): struct compat_mq_attr
 * (32-bit longs, which compat_sys_mq_open reads only to create a queue),
 * mq_notify's struct compat_sigevent, and mq_timedsend_time32 and
 * mq_timedreceive_time32 beside the *_time64 calls. Structures that must
 * be read at their 32-bit size sit at the end of a page whose successor
 * is not mapped. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "check.h"

#ifndef __i386__
#error "mq32 is an i386 program"
#endif

#define NR_MQ_OPEN 277
#define NR_MQ_UNLINK 278
#define NR_MQ_TIMEDSEND 279
#define NR_MQ_TIMEDRECEIVE 280
#define NR_MQ_NOTIFY 281
#define NR_MQ_GETSETATTR 282
#define NR_MQ_TIMEDSEND_TIME64 418
#define NR_MQ_TIMEDRECEIVE_TIME64 419
#define BAD ((void *)16)

int main(void) {
    char *page = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    char *end = page + 4096;
    syscall(NR_MQ_UNLINK, "mq32");

    /* The attributes are read only to create, 32 bytes of them. */
    CHECK_ERR("open-no-create", syscall(NR_MQ_OPEN, "mq32", O_RDWR, 0, BAD), ENOENT);
    CHECK_ERR("open-create-fault", syscall(NR_MQ_OPEN, "mq32", O_RDWR | O_CREAT, 0600, BAD),
              EFAULT);
    int32_t *attr = (int32_t *)(end - 32);
    memset(attr, 0, 32);
    attr[1] = -1;
    attr[2] = 64;
    CHECK_ERR("open-negative-maxmsg",
              syscall(NR_MQ_OPEN, "mq32", O_RDWR | O_CREAT, 0600, attr), EINVAL);
    attr[1] = 3;
    int q = syscall(NR_MQ_OPEN, "mq32", O_RDWR | O_CREAT | O_NONBLOCK, 0600, attr);
    CHECK("open", q >= 0);
    uint32_t got[10];
    memset(got, 0xEE, sizeof got);
    CHECK("getattr", syscall(NR_MQ_GETSETATTR, q, 0, got) == 0 && got[0] == O_NONBLOCK &&
                         got[1] == 3 && got[2] == 64 && got[3] == 0 && got[4] == 0 &&
                         got[7] == 0 && got[8] == 0xEEEEEEEE);
    CHECK("getattr-at-page-end", syscall(NR_MQ_GETSETATTR, q, 0, attr) == 0 && attr[1] == 3);

    /* Timeouts: an old_timespec32 of 8 bytes; the *_time64 padding. */
    int32_t *ts = (int32_t *)(end - 8);
    ts[0] = 1;
    ts[1] = 1000;
    CHECK("send-time32", syscall(NR_MQ_TIMEDSEND, q, "hi", 2, 5, ts) == 0);
    ts[1] = 1000000000;
    CHECK_ERR("send-time32-invalid", syscall(NR_MQ_TIMEDSEND, q, "hi", 2, 5, ts), EINVAL);
    int32_t *ts64 = (int32_t *)(end - 16);
    ts64[0] = 1;
    ts64[1] = 0;
    ts64[2] = 1000;
    ts64[3] = -1;
    char buf[64];
    unsigned prio = 0;
    CHECK("receive-time64-padding",
          syscall(NR_MQ_TIMEDRECEIVE_TIME64, q, buf, 64, &prio, ts64) == 2 && prio == 5 &&
              !memcmp(buf, "hi", 2));
    ts[0] = 1;
    ts[1] = 1000;
    CHECK_ERR("receive-time32-empty", syscall(NR_MQ_TIMEDRECEIVE, q, buf, 64, &prio, ts),
              EAGAIN);
    ts64[0] = ts64[1] = 0;
    ts64[2] = 1000000000;
    ts64[3] = 0;
    CHECK_ERR("send-time64-invalid", syscall(NR_MQ_TIMEDSEND_TIME64, q, "hi", 2, 5, ts64),
              EINVAL);

    /* mq_notify: struct compat_sigevent's value, signal, and kind. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, 0);
    int32_t *ev = (int32_t *)(end - 16);
    ev[0] = 0xfeed;
    ev[1] = SIGUSR2;
    ev[2] = 3;
    ev[3] = 0;
    CHECK_ERR("notify-bad-kind", syscall(NR_MQ_NOTIFY, q, ev), EINVAL);
    ev[2] = SIGEV_SIGNAL;
    CHECK("notify", syscall(NR_MQ_NOTIFY, q, ev) == 0);
    CHECK("send", syscall(NR_MQ_TIMEDSEND, q, "x", 1, 0, 0) == 0);
    siginfo_t si;
    CHECK("notified", sigwaitinfo(&set, &si) == SIGUSR2 && si.si_code == SI_MESGQ &&
                          si.si_value.sival_int == 0xfeed);
    CHECK("unlink", syscall(NR_MQ_UNLINK, "mq32") == 0);
    FINISH();
}
