// kqueue and kevent: registration errors and receipts, EV_ONESHOT,
// EV_CLEAR, EV_DISPATCH, EV_DISABLE/EV_ENABLE, EV_UDATA_SPECIFIC; the read
// and write filters on pipes (data, EV_EOF), vnode events on a file,
// timers (one-shot, repeating, units), user events, signal counts, Mach
// ports (reporting and receiving), a kqueue inside a kqueue, kevent64 and
// kevent_qos, timeouts, and an interrupted wait.
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

static void show(const char *what, int n, struct kevent *ev) {
    printf("%s: n=%d", what, n);
    for (int i = 0; i < n; i++) {
        printf(" [id=%lu f=%d fl=%#x ff=%#x d=%ld u=%lu]", (unsigned long)ev[i].ident,
               ev[i].filter, ev[i].flags, ev[i].fflags, (long)ev[i].data,
               (unsigned long)(uintptr_t)ev[i].udata);
    }
    printf("\n");
}

static const struct timespec zero = {0, 0};

// kevent_qos is private SPI (bsd/sys/event_private.h).
struct kev_qos {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    int32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t data;
    uint64_t ext[4];
};
extern int kevent_qos(int kq, const void *changelist, int nchanges, void *eventlist, int nevents,
                      void *data_out, size_t *data_available, unsigned int flags);
#define KEVENT_FLAG_IMMEDIATE_ 0x1

static void on_alrm(int sig) { (void)sig; }

int main(void) {
    struct kevent ch[4], ev[8];
    int kq = kqueue();
    printf("kqueue: %s\n", kq >= 0 ? "ok" : "failed");

    // Errors come back as events with EV_ERROR, receipts with data 0.
    EV_SET(&ch[0], 12345, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&ch[1], 1, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    EV_SET(&ch[2], 2, EVFILT_USER, EV_ADD | EV_RECEIPT, 0, 0, (void *)7);
    EV_SET(&ch[3], 3, -99, EV_ADD, 0, 0, NULL);
    int n = kevent(kq, ch, 4, ev, 8, &zero);
    show("errors", n, ev);
    errno = 0;
    n = kevent(kq, ch, 1, NULL, 0, &zero);
    printf("error without room: n=%d errno=%d\n", n, errno);

    // Pipes: level-triggered read data, EV_CLEAR edges, EV_EOF.
    int p[2];
    pipe(p);
    EV_SET(&ch[0], p[0], EVFILT_READ, EV_ADD, 0, 0, (void *)1);
    EV_SET(&ch[1], p[1], EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, (void *)2);
    n = kevent(kq, ch, 2, ev, 8, &zero);
    printf("write ready: n=%d filter=%d\n", n, n ? ev[0].filter : 0);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("nothing yet", n, ev);
    write(p[1], "abcde", 5);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("read ready", n, ev);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("still ready (level)", n, ev);
    char buf[16];
    read(p[0], buf, 5);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("drained", n, ev);
    EV_SET(&ch[0], p[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)1);
    kevent(kq, ch, 1, NULL, 0, &zero);
    write(p[1], "xy", 2);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("clear edge", n, ev);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("clear no repeat", n, ev);
    close(p[1]);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("eof", n, ev);
    close(p[0]);
    EV_SET(&ch[0], p[0], EVFILT_READ, EV_DELETE, 0, 0, NULL);
    n = kevent(kq, ch, 1, ev, 8, &zero);
    show("closed fd knote gone", n, ev);

    // Vnode events.
    char path[] = "/tmp/rax_kqueue_XXXXXX";
    int f = mkstemp(path);
    EV_SET(&ch[0], f, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB,
           0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    write(f, "data", 4);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("vnode", n, ev);
    unlink(path);
    close(f);

    // Timers. The one-shot timer's data counts the intervals that passed by
    // the time it is delivered: a critical timer (no coalescing, which a
    // QoS-clamped host stretches to several 20 ms intervals) of 200 ms
    // makes that one wherever the fixture runs.
    EV_SET(&ch[0], 10, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_CRITICAL, 200, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("timer early: n=%d\n", n);
    n = kevent(kq, NULL, 0, ev, 8, NULL);
    show("timer oneshot", n, ev);
    EV_SET(&ch[0], 10, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    n = kevent(kq, ch, 1, ev, 8, &zero);
    printf("oneshot deleted: n=%d flags=%#x data=%ld\n", n, n ? ev[0].flags : 0,
           n ? (long)ev[0].data : 0);
    EV_SET(&ch[0], 11, EVFILT_TIMER, EV_ADD, NOTE_USECONDS | NOTE_CRITICAL, 5000, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    usleep(30000);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("repeating: n=%d count>=5=%d flags=%#x\n", n, n && ev[0].data >= 5, n ? ev[0].flags : 0);
    EV_SET(&ch[0], 11, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    EV_SET(&ch[0], 12, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, -1, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("negative fires once", n, ev);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("negative again: n=%d\n", n);
    EV_SET(&ch[0], 12, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);

    // User events and fflags operations.
    EV_SET(&ch[0], 2, EVFILT_USER, EV_ENABLE, NOTE_FFCOPY | 0x11, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("user untriggered: n=%d\n", n);
    EV_SET(&ch[0], 2, EVFILT_USER, 0, NOTE_TRIGGER | NOTE_FFOR | 0x100, 42, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("user triggered", n, ev);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("user level again: n=%d\n", n);

    // EV_DISPATCH disables after delivery; EV_ENABLE rearms.
    EV_SET(&ch[0], 3, EVFILT_USER, EV_ADD | EV_DISPATCH, NOTE_TRIGGER, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("dispatch first: n=%d id=%lu\n", n, n ? (unsigned long)ev[n - 1].ident : 0);
    EV_SET(&ch[0], 2, EVFILT_USER, EV_DELETE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("dispatch disabled: n=%d\n", n);
    EV_SET(&ch[0], 3, EVFILT_USER, EV_ENABLE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    printf("dispatch rearmed: n=%d\n", n);
    EV_SET(&ch[0], 3, EVFILT_USER, EV_DELETE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);

    // Udata-specific knotes coexist.
    EV_SET(&ch[0], 4, EVFILT_USER, EV_ADD | EV_UDATA_SPECIFIC, NOTE_TRIGGER, 0, (void *)100);
    EV_SET(&ch[1], 4, EVFILT_USER, EV_ADD | EV_UDATA_SPECIFIC, NOTE_TRIGGER, 0, (void *)200);
    kevent(kq, ch, 2, NULL, 0, &zero);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("udata specific", n, ev);
    EV_SET(&ch[0], 4, EVFILT_USER, EV_DELETE | EV_UDATA_SPECIFIC, 0, 0, (void *)100);
    EV_SET(&ch[1], 4, EVFILT_USER, EV_DELETE | EV_UDATA_SPECIFIC, 0, 0, (void *)200);
    EV_SET(&ch[2], 4, EVFILT_USER, EV_DELETE | EV_UDATA_SPECIFIC, 0, 0, (void *)300);
    n = kevent(kq, ch, 3, ev, 8, &zero);
    show("udata deletes", n, ev);

    // Signals are counted even when ignored.
    signal(SIGUSR1, SIG_IGN);
    EV_SET(&ch[0], SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    kill(getpid(), SIGUSR1);
    kill(getpid(), SIGUSR1);
    raise(SIGUSR1);
    n = kevent(kq, NULL, 0, ev, 8, &zero);
    show("signals", n, ev);

    // A kqueue used through kevent() cannot be used through kevent64().
    struct kevent64_s k64[2], o64[4];
    errno = 0;
    printf("kevent64 on a kevent kqueue: %d errno=%d\n", kevent64(kq, NULL, 0, o64, 4, 0, &zero),
           errno);

    // Mach ports: report a message, then receive it through the knote.
    int kq64 = kqueue();
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    EV_SET64(&k64[0], port, EVFILT_MACHPORT, EV_ADD, 0, 0, 5, 0, 0);
    int n64 = kevent64(kq64, k64, 1, o64, 4, 0, &zero);
    printf("machport empty: n=%d\n", n64);
    mach_msg_header_t h = {
        .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
        .msgh_size = sizeof h,
        .msgh_remote_port = port,
        .msgh_id = 4242,
    };
    mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    n64 = kevent64(kq64, NULL, 0, o64, 4, 0, &zero);
    printf("machport ready: n=%d data_is_port=%d fflags=%#x\n", n64,
           n64 ? o64[0].data == port : 0, n64 ? o64[0].fflags : 0);
    // Changing the receive mode of an existing knote is refused.
    EV_SET64(&k64[0], port, EVFILT_MACHPORT, EV_ADD, MACH_RCV_MSG, 0, 5, 0, 0);
    n64 = kevent64(kq64, k64, 1, o64, 4, 0, &zero);
    printf("machport mode change: n=%d flags=%#x data=%lld\n", n64, n64 ? o64[0].flags : 0,
           n64 ? (long long)o64[0].data : 0);
    // A knote that receives into its buffer.
    struct {
        mach_msg_header_t h;
        char trailer[64];
    } rcv;
    memset(&rcv, 0, sizeof rcv);
    EV_SET64(&k64[0], port, EVFILT_MACHPORT, EV_DELETE, 0, 0, 5, 0, 0);
    kevent64(kq64, k64, 1, NULL, 0, 0, &zero);
    EV_SET64(&k64[0], port, EVFILT_MACHPORT, EV_ADD | EV_DISPATCH,
             MACH_RCV_MSG | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO), 0, 6,
             (uint64_t)(uintptr_t)&rcv, sizeof rcv);
    n64 = kevent64(kq64, k64, 1, o64, 4, 0, &zero);
    printf("machport received: n=%d flags=%#x fflags=%#x id=%d total=%llu ext0_ok=%d\n", n64,
           n64 ? o64[0].flags : 0, n64 ? o64[0].fflags : 0, rcv.h.msgh_id,
           n64 ? (unsigned long long)o64[0].ext[1] : 0,
           n64 ? o64[0].ext[0] == (uint64_t)(uintptr_t)&rcv : 0);
    // A second message waits: the knote is disabled (EV_DISPATCH).
    mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    n64 = kevent64(kq64, NULL, 0, o64, 4, 0, &zero);
    printf("machport dispatched: n=%d\n", n64);
    EV_SET64(&k64[0], port, EVFILT_MACHPORT, EV_ENABLE,
             MACH_RCV_MSG | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO), 0, 6,
             (uint64_t)(uintptr_t)&rcv, sizeof rcv);
    n64 = kevent64(kq64, k64, 1, o64, 4, 0, &zero);
    printf("machport rearmed: n=%d fflags=%#x\n", n64, n64 ? o64[0].fflags : 0);
    mach_port_status_t st;
    mach_msg_type_number_t cnt = MACH_PORT_RECEIVE_STATUS_COUNT;
    mach_port_get_attributes(mach_task_self(), port, MACH_PORT_RECEIVE_STATUS,
                             (mach_port_info_t)&st, &cnt);
    printf("machport queue after: %u seqno=%u\n", st.mps_msgcount, st.mps_seqno);

    // A kqueue in a kqueue.
    int outer = kqueue();
    EV_SET(&ch[0], kq, EVFILT_READ, EV_ADD, 0, 0, NULL);
    n = kevent(outer, ch, 1, ev, 8, &zero);
    printf("nested idle: n=%d\n", n);
    EV_SET(&ch[0], 5, EVFILT_USER, EV_ADD, NOTE_TRIGGER, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, &zero);
    n = kevent(outer, NULL, 0, ev, 8, &zero);
    printf("nested ready: n=%d data=%ld\n", n, n ? (long)ev[0].data : 0);
    EV_SET(&ch[0], kq, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    n = kevent(outer, ch, 1, ev, 8, &zero);
    printf("nested write: n=%d flags=%#x data=%ld\n", n, n ? ev[0].flags : 0,
           n ? (long)ev[0].data : 0);

    // kevent_qos.
    struct kev_qos q[2];
    memset(q, 0, sizeof q);
    q[0].ident = 6;
    q[0].filter = EVFILT_USER;
    q[0].flags = EV_ADD | EV_CLEAR;
    q[0].fflags = NOTE_TRIGGER;
    q[0].udata = 77;
    q[0].ext[3] = 9;
    struct kev_qos qo[2];
    int kqq = kqueue();
    int nq = kevent_qos(kqq, q, 1, qo, 2, NULL, NULL, KEVENT_FLAG_IMMEDIATE_);
    printf("kevent_qos: n=%d", nq);
    for (int i = 0; i < nq; i++) {
        printf(" [id=%llu fl=%#x u=%llu ext3=%llu]", qo[i].ident, qo[i].flags, qo[i].udata,
               qo[i].ext[3]);
    }
    printf("\n");
    errno = 0;
    printf("kevent after kevent_qos: %d errno=%d\n", kevent(kqq, NULL, 0, ev, 8, &zero), errno);
    errno = 0;
    printf("kevent64 after kevent_qos: %d errno=%d\n", kevent64(kqq, NULL, 0, o64, 4, 0, &zero),
           errno);

    // A timeout, and an interrupted wait.
    int kq2 = kqueue();
    struct timespec ts = {0, 20 * 1000 * 1000};
    n = kevent(kq2, NULL, 0, ev, 8, &ts);
    printf("timeout: n=%d\n", n);
    signal(SIGALRM, on_alrm);
    struct itimerval it = {{0, 0}, {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    errno = 0;
    n = kevent(kq2, NULL, 0, ev, 8, NULL);
    printf("interrupted: n=%d errno=%d\n", n, errno);
    return 0;
}
