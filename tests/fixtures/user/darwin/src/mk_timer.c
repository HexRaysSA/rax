// Mach timers: mk_timer_create's receive right (the kernel's own send
// right, the queue limit), arming (the expiration message, its header and
// trailer, a deadline already past, re-arming, one message pending at a
// time), cancelling (the armed deadline with the kernel's coalescing slop,
// the copy-out), critical, continuous, and leeway timers, delivery through a
// port set and a kqueue, destruction, and the errors of each call.
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <time.h>
#include <unistd.h>

extern mach_port_name_t mk_timer_create(void);
extern kern_return_t mk_timer_destroy(mach_port_name_t name);
extern kern_return_t mk_timer_arm(mach_port_name_t name, uint64_t expire_time);
extern kern_return_t mk_timer_cancel(mach_port_name_t name, uint64_t *result_time);
extern kern_return_t mk_timer_arm_leeway(mach_port_name_t name, uint64_t flags, uint64_t expire_time,
                                         uint64_t leeway);
#define MK_TIMER_CRITICAL 1
#define MK_TIMER_CONTINUOUS 2

typedef struct {
    mach_msg_header_t h;
    uint64_t unused[3];
    mach_msg_audit_trailer_t t;
} expire_msg;

static mach_timebase_info_data_t tb;

static uint64_t ms(double m) { return (uint64_t)(m * 1e6 * tb.denom / tb.numer); }
static long long us(int64_t ticks) {
    double ns = (double)ticks * tb.numer / tb.denom;
    return (long long)(ns / 1000 + (ns < 0 ? -0.5 : 0.5));
}

static kern_return_t recv(mach_port_t p, expire_msg *m, mach_msg_timeout_t timeout) {
    memset(m, 0xa5, sizeof *m);
    return mach_msg(&m->h,
                    MACH_RCV_MSG | MACH_RCV_TIMEOUT |
                        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                    0, sizeof *m, p, timeout, MACH_PORT_NULL);
}

static mach_port_status_t status(mach_port_t p) {
    mach_port_status_t st;
    mach_msg_type_number_t c = MACH_PORT_RECEIVE_STATUS_COUNT;
    mach_port_get_attributes(mach_task_self(), p, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&st, &c);
    return st;
}

static void drain(mach_port_t p) {
    expire_msg m;
    while (recv(p, &m, 0) == KERN_SUCCESS) {
    }
}

static void sleep_ms(double m) { mach_wait_until(mach_absolute_time() + ms(m)); }

static void creation(mach_port_t t) {
    mach_port_type_t ty = 0;
    mach_port_urefs_t refs = 9;
    mach_port_type(mach_task_self(), t, &ty);
    mach_port_get_refs(mach_task_self(), t, MACH_PORT_RIGHT_SEND, &refs);
    mach_port_status_t st = status(t);
    printf("create: name %s, type %#x, send refs %u, srights %u, mscount %u, qlimit %u, msgs %u\n",
           t ? "set" : "null", ty, refs, st.mps_srights, st.mps_mscount, st.mps_qlimit,
           st.mps_msgcount);
    natural_t kt = 0;
    mach_vm_address_t ka;
    kern_return_t kr = mach_port_kobject(mach_task_self(), t, &kt, &ka);
    printf("kobject: %d type %u\n", kr, kt);
}

static void expiry(mach_port_t t) {
    uint64_t res = 7;
    printf("cancel unarmed: %d result %llu\n", mk_timer_cancel(t, &res), res);
    uint64_t dl = mach_absolute_time() + ms(200);
    printf("arm 200 ms: %d\n", mk_timer_arm(t, dl));
    res = 7;
    kern_return_t kr = mk_timer_cancel(t, &res);
    printf("cancel armed: %d, deadline + %lld us\n", kr, us((int64_t)(res - dl)));
    res = 7;
    printf("cancel again: %d result %llu\n", mk_timer_cancel(t, &res), res);
    expire_msg m;
    printf("receive after cancel: %#x\n", recv(t, &m, 300));

    dl = mach_absolute_time() + ms(100);
    mk_timer_arm(t, dl);
    kr = recv(t, &m, 2000);
    int late = mach_absolute_time() >= dl;
    printf("expired: %#x bits %#x size %u remote %u local %s voucher %u id %d body %llx %llx %llx, "
           "not early %d\n",
           kr, m.h.msgh_bits, m.h.msgh_size, m.h.msgh_remote_port,
           m.h.msgh_local_port == t ? "timer" : "other", m.h.msgh_voucher_port, m.h.msgh_id,
           m.unused[0], m.unused[1], m.unused[2], late);
    printf("trailer: type %u size %u seqno %u sender %u/%u audit pid %u\n", m.t.msgh_trailer_type,
           m.t.msgh_trailer_size, m.t.msgh_seqno, m.t.msgh_sender.val[0], m.t.msgh_sender.val[1],
           m.t.msgh_audit.val[5]);
    res = 7;
    printf("cancel after expiry: %d result %llu\n", mk_timer_cancel(t, &res), res);

    mk_timer_arm(t, 0);
    printf("deadline 0: %#x\n", recv(t, &m, 2000));
    mk_timer_arm(t, mach_absolute_time() - ms(1));
    printf("deadline past: %#x\n", recv(t, &m, 2000));

    mk_timer_arm(t, 0);
    sleep_ms(30);
    mk_timer_arm(t, 0);
    sleep_ms(30);
    printf("two expirations unreceived: %u queued\n", status(t).mps_msgcount);
    drain(t);
    mk_timer_arm(t, mach_absolute_time() + ms(10));
    mk_timer_arm(t, mach_absolute_time() + ms(40));
    sleep_ms(20);
    printf("re-armed before expiry, at 20 ms: %u queued\n", status(t).mps_msgcount);
    sleep_ms(60);
    printf("at 80 ms: %u queued\n", status(t).mps_msgcount);
    drain(t);
    printf("seqno after 5 receives: %u\n", status(t).mps_seqno);
}

static void flavors(mach_port_t t) {
    uint64_t res = 0;
    uint64_t dl = mach_absolute_time() + ms(500);
    mk_timer_arm_leeway(t, MK_TIMER_CRITICAL, dl, 0);
    mk_timer_cancel(t, &res);
    printf("critical: deadline + %lld us\n", us((int64_t)(res - dl)));
    dl = mach_absolute_time() + ms(500);
    mk_timer_arm_leeway(t, 0, dl, ms(50));
    mk_timer_cancel(t, &res);
    printf("leeway 50 ms: deadline + %lld us\n", us((int64_t)(res - dl)));
    dl = mach_absolute_time() + ms(500);
    mk_timer_arm_leeway(t, 0, dl, ms(1));
    mk_timer_cancel(t, &res);
    printf("leeway 1 ms: deadline + %lld us\n", us((int64_t)(res - dl)));
    dl = mach_absolute_time() + ms(500);
    mk_timer_arm_leeway(t, MK_TIMER_CRITICAL, dl, ms(2));
    mk_timer_cancel(t, &res);
    printf("critical, leeway 2 ms: deadline + %lld us\n", us((int64_t)(res - dl)));
    printf("far deadline: %d\n", mk_timer_arm(t, ~0ULL - 5));
    mk_timer_cancel(t, NULL);
    uint64_t c = mach_continuous_time();
    printf("continuous: %d", mk_timer_arm_leeway(t, MK_TIMER_CONTINUOUS, c + ms(30), 0));
    expire_msg m;
    printf(" -> %#x\n", recv(t, &m, 2000));
    printf("unknown flags: %d", mk_timer_arm_leeway(t, 0xf0, 0, 5));
    printf(" -> %#x\n", recv(t, &m, 2000));
}

static void delivery(mach_port_t t) {
    mach_port_t set;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &set);
    mach_port_insert_member(mach_task_self(), t, set);
    mk_timer_arm(t, mach_absolute_time() + ms(20));
    expire_msg m;
    kern_return_t kr = recv(set, &m, 2000);
    printf("through a port set: %#x local %s\n", kr, m.h.msgh_local_port == t ? "timer" : "other");
    mach_port_extract_member(mach_task_self(), t, set);
    mach_port_mod_refs(mach_task_self(), set, MACH_PORT_RIGHT_PORT_SET, -1);

    int kq = kqueue();
    struct kevent64_s ev;
    EV_SET64(&ev, t, EVFILT_MACHPORT, EV_ADD, 0, 0, 0, 0, 0);
    kevent64(kq, &ev, 1, NULL, 0, 0, NULL);
    mk_timer_arm(t, mach_absolute_time() + ms(20));
    struct timespec ts = {2, 0};
    int n = kevent64(kq, NULL, 0, &ev, 1, 0, &ts);
    printf("through a kqueue: %d event, data %s\n", n, (mach_port_t)ev.data == t ? "timer" : "other");
    drain(t);
    close(kq);

    mach_port_insert_right(mach_task_self(), t, t, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_status_t st = status(t);
    printf("with a send right: srights %u mscount %u\n", st.mps_srights, st.mps_mscount);
    struct {
        mach_msg_header_t h;
    } um = {{MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0), sizeof um, t, 0, 0, 77}};
    kr = mach_msg(&um.h, MACH_SEND_MSG, sizeof um, 0, 0, 0, 0);
    printf("user message to the timer: %#x", kr);
    kr = recv(t, &m, 1000);
    printf(" -> %#x id %d\n", kr, m.h.msgh_id);
    mach_port_mod_refs(mach_task_self(), t, MACH_PORT_RIGHT_SEND, -1);
}

static void errors(mach_port_t t) {
    printf("cancel to a bad address, unarmed: %d\n", mk_timer_cancel(t, (uint64_t *)8));
    mk_timer_arm(t, mach_absolute_time() + ms(100));
    printf("cancel to a bad address, armed: %d", mk_timer_cancel(t, (uint64_t *)8));
    expire_msg m;
    printf(" -> %#x (cancelled)\n", recv(t, &m, 300));
    printf("cancel without a result: %d\n", mk_timer_cancel(t, NULL));

    mach_port_t p, dead, set;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_DEAD_NAME, &dead);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &set);
    mach_port_t self = mach_task_self();
    printf("plain port: arm %d cancel %d destroy %d\n", mk_timer_arm(p, 0), mk_timer_cancel(p, 0),
           mk_timer_destroy(p));
    printf("send right: arm %d cancel %d destroy %d\n", mk_timer_arm(self, 0),
           mk_timer_cancel(self, 0), mk_timer_destroy(self));
    printf("dead name: arm %d cancel %d destroy %d\n", mk_timer_arm(dead, 0),
           mk_timer_cancel(dead, 0), mk_timer_destroy(dead));
    printf("port set: arm %d cancel %d destroy %d\n", mk_timer_arm(set, 0), mk_timer_cancel(set, 0),
           mk_timer_destroy(set));
    printf("unused name: arm %d cancel %d destroy %d\n", mk_timer_arm(0x12345603, 0),
           mk_timer_cancel(0x12345603, 0), mk_timer_destroy(0x12345603));
    printf("null: arm %d cancel %d destroy %d\n", mk_timer_arm(MACH_PORT_NULL, 0),
           mk_timer_cancel(MACH_PORT_NULL, 0), mk_timer_destroy(MACH_PORT_NULL));
    printf("dead: arm %d cancel %d destroy %d\n", mk_timer_arm(MACH_PORT_DEAD, 0),
           mk_timer_cancel(MACH_PORT_DEAD, 0), mk_timer_destroy(MACH_PORT_DEAD));
}

static void destruction(mach_port_t t) {
    mk_timer_arm(t, mach_absolute_time() + ms(20));
    mach_port_insert_right(mach_task_self(), t, t, MACH_MSG_TYPE_MAKE_SEND);
    printf("destroy (armed, with a send right): %d", mk_timer_destroy(t));
    mach_port_type_t ty;
    printf(", then type %d, destroy again %d\n", mach_port_type(mach_task_self(), t, &ty),
           mk_timer_destroy(t));
    mach_port_t a = mk_timer_create();
    printf("mod_refs(receive, -1): %d, then arm %d\n",
           mach_port_mod_refs(mach_task_self(), a, MACH_PORT_RIGHT_RECEIVE, -1), mk_timer_arm(a, 0));
    mach_port_t b = mk_timer_create();
    mk_timer_arm(b, 0);
    sleep_ms(30);
    printf("mach_port_destroy with a message queued: %d\n", mach_port_destroy(mach_task_self(), b));
    mach_port_t c = mk_timer_create(), d = mk_timer_create();
    printf("two more timers: distinct %d\n", c != d && c && d);
    mk_timer_arm(c, mach_absolute_time() + ms(40));
    mk_timer_arm(d, mach_absolute_time() + ms(20));
    expire_msg m;
    kern_return_t kr = recv(d, &m, 2000);
    printf("second armed later fires first: %#x, first still pending %u\n", kr, status(c).mps_msgcount);
    kr = recv(c, &m, 2000);
    printf("then the first: %#x\n", kr);
    mk_timer_destroy(c);
    mk_timer_destroy(d);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_timebase_info(&tb);
    mach_port_t t = mk_timer_create();
    creation(t);
    expiry(t);
    flavors(t);
    delivery(t);
    errors(t);
    destruction(t);
    return 0;
}
