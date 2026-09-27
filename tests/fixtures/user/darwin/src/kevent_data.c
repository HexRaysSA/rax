// Mach messages received through EVFILT_MACHPORT knotes into the data area
// of kevent_qos: laid out from the area's start, or (KEVENT_FLAG_STACK_DATA)
// from its end down; the message, its trailer, and its auxiliary data
// (sent with a mach_msg2 vector) in one piece; the sizes the event
// reports; a message too large for what remains; and a knote with its own
// buffer. Offsets are printed relative to the area.
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

// Private SPI (bsd/sys/event_private.h, osfmk/mach/message.h).
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
#define KEVENT_FLAG_STACK_DATA_ 0x8

typedef struct {
    uint64_t data;
    uint64_t rcv_addr;
    uint32_t send_size;
    uint32_t rcv_size;
} msg_vector;
extern mach_msg_return_t mach_msg2_internal(void *data, uint64_t option64, uint64_t bits_and_send_size,
                                            uint64_t remote_and_local, uint64_t voucher_and_id,
                                            uint64_t desc_count_and_rcv_name, uint64_t rcv_size_and_priority,
                                            uint64_t timeout);
#define MACH64_MSG_VECTOR_ 0x0000000100000000ull
#define MACH64_SEND_MQ_CALL_ 0x0000000400000000ull

static mach_port_t port;

static void send_plain(int id, int words) {
    struct {
        mach_msg_header_t h;
        uint32_t body[8];
    } m = {0};
    m.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    m.h.msgh_size = sizeof m.h + 4 * words;
    m.h.msgh_remote_port = port;
    m.h.msgh_id = id;
    for (int i = 0; i < words; i++) m.body[i] = 0x1000 + i;
    kern_return_t kr = mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0);
    if (kr) printf("send %d: %#x\n", id, kr);
}

static void send_with_aux(int id, const char *text) {
    struct {
        mach_msg_header_t h;
        uint32_t word;
    } m = {0};
    m.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    m.h.msgh_size = sizeof m;
    m.h.msgh_remote_port = port;
    m.h.msgh_id = id;
    m.word = 0xabcd;
    struct {
        uint32_t size;
        uint32_t reserved;
        char payload[32];
    } aux = {0};
    size_t n = strlen(text) + 1;
    memcpy(aux.payload, text, n);
    aux.size = (uint32_t)(8 + n);
    msg_vector v[2] = {{(uint64_t)&m, 0, sizeof m, 0}, {(uint64_t)&aux, 0, aux.size, 0}};
    uint64_t bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    kern_return_t kr = mach_msg2_internal(
        v, MACH64_MSG_VECTOR_ | MACH64_SEND_MQ_CALL_ | MACH_SEND_MSG, ((uint64_t)2 << 32) | bits,
        port, ((uint64_t)(uint32_t)id << 32), 0, 0, 0);
    if (kr) printf("send %d with aux: %#x\n", id, kr);
}

static void show(const char *what, int n, struct kev_qos *ev, const uint8_t *area, size_t before,
                 size_t after) {
    printf("%s: n=%d", what, n);
    for (int i = 0; i < n; i++) {
        struct kev_qos *e = &ev[i];
        long off = e->ext[0] ? (long)((const uint8_t *)e->ext[0] - area) : -1;
        printf(" [fflags=%#x data=%s size=%llu aux=%llu at=%ld", e->fflags,
               e->data == 0 ? "0" : e->data == (int64_t)port ? "port" : "other",
               (unsigned long long)e->ext[1], (unsigned long long)e->ext[3], off);
        if (e->fflags == 0 && e->ext[0]) {
            const mach_msg_header_t *h = (const void *)e->ext[0];
            printf(" id=%d msgh_size=%u local=%s", h->msgh_id, h->msgh_size,
                   h->msgh_local_port == port ? "port" : "other");
            if (e->ext[3]) {
                const uint8_t *aux = (const uint8_t *)e->ext[0] + e->ext[1];
                uint32_t asz;
                memcpy(&asz, aux, 4);
                printf(" auxsize=%u text=%s", asz, (const char *)aux + 8);
            }
        }
        printf("]");
    }
    printf(" left %zu of %zu\n", after, before);
}

static int arm(int kq, uint64_t buf, uint64_t size) {
    struct kev_qos k = {0};
    k.ident = port;
    k.filter = EVFILT_MACHPORT;
    k.flags = EV_ADD | EV_ENABLE;
    k.fflags = MACH_RCV_MSG | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO);
    k.ext[0] = buf;
    k.ext[1] = size;
    return kevent_qos(kq, &k, 1, NULL, 0, NULL, NULL, KEVENT_FLAG_IMMEDIATE_);
}

static void round(const char *what, int kq, unsigned flags, size_t avail) {
    static uint8_t area[1024];
    memset(area, 0x5a, sizeof area);
    struct kev_qos ev[4];
    memset(ev, 0, sizeof ev);
    size_t left = avail;
    int n = kevent_qos(kq, NULL, 0, ev, 4, area, &left, flags | KEVENT_FLAG_IMMEDIATE_);
    show(what, n, ev, area, avail, left);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    int kq = kqueue();
    printf("arm: %d\n", arm(kq, 0, 0));

    send_plain(101, 2);
    round("plain, from the start", kq, 0, 1024);
    send_plain(102, 3);
    round("plain, stack", kq, KEVENT_FLAG_STACK_DATA_, 1024);
    send_with_aux(103, "aux data");
    round("aux, from the start", kq, 0, 1024);
    send_with_aux(104, "more aux");
    round("aux, stack", kq, KEVENT_FLAG_STACK_DATA_, 1024);
    send_with_aux(105, "tight");
    round("aux, too small", kq, KEVENT_FLAG_STACK_DATA_, 40);
    round("aux, retried", kq, KEVENT_FLAG_STACK_DATA_, 1024);

    static uint8_t own[256];
    memset(own, 0x5a, sizeof own);
    printf("own buffer arm: %d\n", arm(kq, (uint64_t)own, sizeof own));
    send_with_aux(106, "own");
    struct kev_qos ev[2];
    memset(ev, 0, sizeof ev);
    int n = kevent_qos(kq, NULL, 0, ev, 2, NULL, NULL, KEVENT_FLAG_IMMEDIATE_);
    show("aux, own buffer", n, ev, own, 0, 0);
    close(kq);
    return 0;
}
