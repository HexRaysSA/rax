/* Mach ports and messages: rights, simple and complex messages, trailers,
 * receive-size handling, port sets, notifications, and guards. Port names
 * are never printed (they depend on what the process allocated before),
 * only relations between them. */
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static mach_port_t task;

static mach_port_t new_port(void) {
    mach_port_t p = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p);
    if (kr) { printf("allocate failed %#x\n", kr); exit(1); }
    return p;
}

static unsigned names_count(void) {
    mach_port_name_array_t names; mach_port_type_array_t types;
    mach_msg_type_number_t n = 0, nt = 0;
    kern_return_t kr = mach_port_names(task, &names, &n, &types, &nt);
    if (kr) { printf("mach_port_names %#x\n", kr); exit(1); }
    vm_deallocate(task, (vm_address_t)names, n * sizeof(*names));
    vm_deallocate(task, (vm_address_t)types, nt * sizeof(*types));
    return n;
}

typedef struct {
    mach_msg_header_t h;
    int data[4];
} simple_t;

static kern_return_t send_simple(mach_port_t dest, mach_msg_type_name_t d,
                                 mach_port_t reply, mach_msg_type_name_t rd, int id) {
    simple_t m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS(d, rd);
    m.h.msgh_size = sizeof m;
    m.h.msgh_remote_port = dest;
    m.h.msgh_local_port = reply;
    m.h.msgh_id = id;
    for (int i = 0; i < 4; i++) m.data[i] = id + i * i;
    return mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

typedef union {
    mach_msg_header_t h;
    char buf[1024];
} rcvbuf_t;

static kern_return_t recv(mach_port_t p, rcvbuf_t *b, mach_msg_option_t extra, mach_msg_size_t size) {
    memset(b, 0xaa, sizeof *b);
    return mach_msg(&b->h, MACH_RCV_MSG | extra, 0, size, p, 0, MACH_PORT_NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    task = mach_task_self();
    unsigned base = names_count();

    /* Rights and types. */
    mach_port_t p = new_port();
    mach_port_type_t t;
    kern_return_t kr = mach_port_type(task, p, &t);
    printf("type receive: kr=%#x type=%#x\n", kr, t);
    kr = mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND);
    printf("insert make_send: kr=%#x\n", kr);
    mach_port_type(task, p, &t);
    printf("type send+receive: %#x\n", t);
    mach_port_urefs_t refs;
    kr = mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &refs);
    printf("send refs: kr=%#x refs=%u\n", kr, refs);
    kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, 2);
    mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &refs);
    printf("mod_refs +2: kr=%#x refs=%u\n", kr, refs);
    kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -5);
    printf("mod_refs -5: kr=%#x\n", kr);
    kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -2);
    mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &refs);
    printf("mod_refs -2: kr=%#x refs=%u\n", kr, refs);
    kr = mach_port_insert_right(task, (0x3fff << 8) | 3, p, MACH_MSG_TYPE_MAKE_SEND);
    printf("insert under another name: kr=%#x\n", kr);
    kr = mach_port_get_refs(task, MACH_PORT_NULL, MACH_PORT_RIGHT_SEND, &refs);
    printf("refs of null send: kr=%#x refs=%u\n", kr, refs);
    kr = mach_port_get_refs(task, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE, &refs);
    printf("refs of null receive: kr=%#x\n", kr);
    kr = mach_port_deallocate(task, 0x12345603);
    printf("deallocate bogus: kr=%#x\n", kr);
    printf("names added: %u\n", names_count() - base);

    /* A simple message and its trailer. */
    kr = send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1000);
    printf("send simple: kr=%#x\n", kr);
    mach_port_status_t st;
    mach_msg_type_number_t cnt = MACH_PORT_RECEIVE_STATUS_COUNT;
    kr = mach_port_get_attributes(task, p, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&st, &cnt);
    printf("status: kr=%#x cnt=%u msgcount=%u seqno=%u mscount=%u qlimit=%u srights=%u\n",
           kr, cnt, st.mps_msgcount, st.mps_seqno, st.mps_mscount, st.mps_qlimit, st.mps_srights);
    rcvbuf_t b;
    kr = recv(p, &b, MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), sizeof b);
    simple_t *s = (simple_t *)&b;
    mach_msg_audit_trailer_t *tr = (mach_msg_audit_trailer_t *)((char *)&b + b.h.msgh_size);
    printf("recv: kr=%#x bits=%#x size=%u local=p:%d remote=%#x voucher=%#x id=%d data=%d,%d,%d,%d\n",
           kr, b.h.msgh_bits, b.h.msgh_size, b.h.msgh_local_port == p, b.h.msgh_remote_port,
           b.h.msgh_voucher_port, b.h.msgh_id, s->data[0], s->data[1], s->data[2], s->data[3]);
    printf("trailer: type=%u size=%u seqno=%u sender_uid_match=%d pid_match=%d\n",
           tr->msgh_trailer_type, tr->msgh_trailer_size, tr->msgh_seqno,
           tr->msgh_sender.val[0] == geteuid(), (pid_t)tr->msgh_audit.val[5] == getpid());

    /* Sequence numbers and the default trailer. */
    send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1001);
    kr = recv(p, &b, 0, sizeof b);
    mach_msg_trailer_t *t0 = (mach_msg_trailer_t *)((char *)&b + b.h.msgh_size);
    printf("recv default trailer: kr=%#x id=%d tsize=%u\n", kr, b.h.msgh_id, t0->msgh_trailer_size);
    send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1002);
    kr = recv(p, &b, MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO), sizeof b);
    mach_msg_seqno_trailer_t *t1 = (mach_msg_seqno_trailer_t *)((char *)&b + b.h.msgh_size);
    printf("recv seqno trailer: kr=%#x tsize=%u seqno=%u\n", kr, t1->msgh_trailer_size, t1->msgh_seqno);

    /* Empty queue, timeouts, and receive sizes. */
    kr = recv(p, &b, MACH_RCV_TIMEOUT, sizeof b);
    printf("recv empty with timeout 0: kr=%#x\n", kr);
    send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1003);
    kr = recv(p, &b, MACH_RCV_LARGE, 32);
    printf("recv too large (RCV_LARGE): kr=%#x size=%u\n", kr, b.h.msgh_size);
    kr = recv(p, &b, 0, sizeof b);
    printf("recv after RCV_LARGE: kr=%#x id=%d\n", kr, b.h.msgh_id);
    send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1004);
    kr = recv(p, &b, 0, 32);
    printf("recv too large (dropped): kr=%#x size=%u id=%d local=p:%d\n", kr, b.h.msgh_size,
           b.h.msgh_id, b.h.msgh_local_port == p);
    kr = recv(p, &b, MACH_RCV_TIMEOUT, sizeof b);
    printf("queue after drop: kr=%#x\n", kr);

    /* Invalid headers and destinations. */
    kr = send_simple(MACH_PORT_NULL, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1);
    printf("send to null: kr=%#x\n", kr);
    kr = send_simple(p, MACH_MSG_TYPE_MOVE_RECEIVE, MACH_PORT_NULL, 0, 1);
    printf("send with receive disposition: kr=%#x\n", kr);
    mach_port_t q = new_port();
    kr = send_simple(q, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 1);
    printf("send without a send right: kr=%#x\n", kr);

    /* A reply right and its send-once notification. */
    mach_port_t reply = new_port();
    kr = send_simple(p, MACH_MSG_TYPE_COPY_SEND, reply, MACH_MSG_TYPE_MAKE_SEND_ONCE, 1005);
    printf("send with reply: kr=%#x\n", kr);
    kr = recv(p, &b, 0, sizeof b);
    mach_port_t so = b.h.msgh_remote_port;
    mach_port_type(task, so, &t);
    printf("recv with reply: kr=%#x bits=%#x reply_named=%d type=%#x\n", kr, b.h.msgh_bits,
           so != MACH_PORT_NULL && so != reply, t);
    kr = mach_port_deallocate(task, so);
    printf("destroy send-once: kr=%#x\n", kr);
    kr = recv(reply, &b, MACH_RCV_TIMEOUT, sizeof b);
    printf("send-once notification: kr=%#x id=%d bits=%#x size=%u\n", kr, b.h.msgh_id,
           b.h.msgh_bits, b.h.msgh_size);

    /* Out-of-line memory and port descriptors. */
    struct {
        mach_msg_header_t h;
        mach_msg_body_t body;
        mach_msg_ool_descriptor_t small, big;
        mach_msg_port_descriptor_t port;
    } c;
    size_t bigsz = 3 * 65536 + 100;
    char *small = malloc(100), *big = malloc(bigsz);
    for (int i = 0; i < 100; i++) small[i] = (char)i;
    for (size_t i = 0; i < bigsz; i++) big[i] = (char)(i * 7);
    memset(&c, 0, sizeof c);
    c.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    c.h.msgh_size = sizeof c;
    c.h.msgh_remote_port = p;
    c.h.msgh_id = 2000;
    c.body.msgh_descriptor_count = 3;
    c.small = (mach_msg_ool_descriptor_t){ small, false, MACH_MSG_PHYSICAL_COPY, 0, MACH_MSG_OOL_DESCRIPTOR, 100 };
    c.big = (mach_msg_ool_descriptor_t){ big, false, MACH_MSG_VIRTUAL_COPY, 0, MACH_MSG_OOL_DESCRIPTOR, (mach_msg_size_t)bigsz };
    c.port.name = q;
    c.port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    c.port.type = MACH_MSG_PORT_DESCRIPTOR;
    kr = mach_msg(&c.h, MACH_SEND_MSG, sizeof c, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    printf("send complex: kr=%#x\n", kr);
    kr = recv(p, &b, 0, sizeof b);
    typeof(c) *rc = (void *)&b;
    int small_ok = rc->small.size == 100 && memcmp(rc->small.address, small, 100) == 0;
    int big_ok = rc->big.size == bigsz && memcmp(rc->big.address, big, bigsz) == 0;
    printf("recv complex: kr=%#x bits=%#x size=%u count=%u\n", kr, b.h.msgh_bits, b.h.msgh_size,
           rc->body.msgh_descriptor_count);
    printf("ool small: ok=%d copy=%u dealloc=%u new_address=%d\n", small_ok, rc->small.copy,
           rc->small.deallocate, rc->small.address != small);
    printf("ool big: ok=%d copy=%u dealloc=%u page_offset_kept=%d\n", big_ok, rc->big.copy,
           rc->big.deallocate, ((uintptr_t)rc->big.address & 0xfff) == ((uintptr_t)big & 0xfff));
    mach_port_get_refs(task, q, MACH_PORT_RIGHT_SEND, &refs);
    printf("port descriptor: same_name=%d disposition=%u type=%u send_refs=%u\n",
           rc->port.name == q, rc->port.disposition, rc->port.type, refs);
    vm_deallocate(task, (vm_address_t)rc->small.address, rc->small.size);
    vm_deallocate(task, (vm_address_t)rc->big.address, rc->big.size);

    /* No-senders and dead-name notifications. */
    mach_port_t notify = new_port(), prev = MACH_PORT_NULL;
    kr = mach_port_request_notification(task, q, MACH_NOTIFY_NO_SENDERS, 0, notify,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    printf("request no-senders: kr=%#x prev_null=%d\n", kr, prev == MACH_PORT_NULL);
    kr = mach_port_deallocate(task, q);
    printf("drop last send right: kr=%#x\n", kr);
    kr = recv(notify, &b, MACH_RCV_TIMEOUT, sizeof b);
    mach_no_senders_notification_t *ns = (void *)&b;
    printf("no-senders notification: kr=%#x id=%d mscount=%u local=notify:%d\n", kr, b.h.msgh_id,
           ns->not_count, b.h.msgh_local_port == notify);

    mach_port_t d = new_port();
    mach_port_insert_right(task, d, d, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_t d2 = MACH_PORT_NULL;
    /* A second name for a send right to d: move it through a message. */
    kr = mach_port_request_notification(task, d, MACH_NOTIFY_DEAD_NAME, 0, notify,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    printf("request dead-name on send+receive: kr=%#x\n", kr);
    (void)d2;
    mach_port_t e = new_port();
    struct { mach_msg_header_t h; mach_msg_body_t body; mach_msg_port_descriptor_t port; } pm;
    memset(&pm, 0, sizeof pm);
    pm.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND_ONCE, 0) | MACH_MSGH_BITS_COMPLEX;
    pm.h.msgh_size = sizeof pm;
    pm.h.msgh_remote_port = e;
    pm.body.msgh_descriptor_count = 1;
    pm.port.name = e;
    pm.port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    pm.port.type = MACH_MSG_PORT_DESCRIPTOR;
    kr = mach_msg(&pm.h, MACH_SEND_MSG, sizeof pm, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    printf("send own send right to itself: kr=%#x\n", kr);
    kr = mach_port_mod_refs(task, e, MACH_PORT_RIGHT_RECEIVE, -1);
    printf("destroy receive with queued message: kr=%#x\n", kr);
    kr = mach_port_type(task, e, &t);
    printf("name after destroy: kr=%#x\n", kr);

    mach_port_t f = new_port();
    mach_port_insert_right(task, f, f, MACH_MSG_TYPE_MAKE_SEND);
    kr = mach_port_request_notification(task, f, MACH_NOTIFY_DEAD_NAME, 0, notify,
                                        MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
    printf("request dead-name: kr=%#x\n", kr);
    /* Give the receive right away: a message carries it, then the receive
     * right dies with the message's destruction. */
    mach_port_t carrier = new_port();
    memset(&pm, 0, sizeof pm);
    pm.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND_ONCE, 0) | MACH_MSGH_BITS_COMPLEX;
    pm.h.msgh_size = sizeof pm;
    pm.h.msgh_remote_port = carrier;
    pm.body.msgh_descriptor_count = 1;
    pm.port.name = f;
    pm.port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    pm.port.type = MACH_MSG_PORT_DESCRIPTOR;
    kr = mach_msg(&pm.h, MACH_SEND_MSG, sizeof pm, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    printf("send receive right: kr=%#x\n", kr);
    mach_port_type(task, f, &t);
    printf("after moving receive: type=%#x\n", t);
    kr = mach_port_mod_refs(task, carrier, MACH_PORT_RIGHT_RECEIVE, -1);
    printf("destroy carrier: kr=%#x\n", kr);
    kr = mach_port_type(task, f, &t);
    mach_port_get_refs(task, f, MACH_PORT_RIGHT_DEAD_NAME, &refs);
    printf("dead name: kr=%#x type=%#x urefs=%u\n", kr, t, refs);
    kr = recv(notify, &b, MACH_RCV_TIMEOUT, sizeof b);
    mach_dead_name_notification_t *dn = (void *)&b;
    printf("dead-name notification: kr=%#x id=%d names_f=%d\n", kr, b.h.msgh_id, dn->not_port == f);
    mach_port_mod_refs(task, f, MACH_PORT_RIGHT_DEAD_NAME, -2);
    kr = mach_port_type(task, f, &t);
    printf("dead name released: kr=%#x\n", kr);
    kr = recv(notify, &b, MACH_RCV_TIMEOUT, sizeof b);
    printf("notify queue: kr=%#x id=%d\n", kr, kr ? 0 : b.h.msgh_id);

    /* Port sets. */
    mach_port_t set;
    kr = mach_port_allocate(task, MACH_PORT_RIGHT_PORT_SET, &set);
    mach_port_type(task, set, &t);
    printf("port set: kr=%#x type=%#x\n", kr, t);
    kr = mach_port_insert_member(task, p, set);
    printf("insert member: kr=%#x again=%#x\n", kr, mach_port_insert_member(task, p, set));
    send_simple(p, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 3000);
    kr = recv(set, &b, 0, sizeof b);
    printf("recv on set: kr=%#x id=%d local=p:%d\n", kr, b.h.msgh_id, b.h.msgh_local_port == p);
    mach_port_name_array_t members; mach_msg_type_number_t mcount = 0;
    kr = mach_port_get_set_status(task, set, &members, &mcount);
    printf("set status: kr=%#x count=%u first=p:%d\n", kr, mcount, mcount && members[0] == p);
    kr = mach_port_extract_member(task, p, set);
    printf("extract member: kr=%#x again=%#x\n", kr, mach_port_extract_member(task, p, set));
    kr = mach_port_destroy(task, set);
    printf("destroy set: kr=%#x\n", kr);

    /* Construct, guards, and context. */
    mach_port_options_t opts = { .flags = MPO_CONTEXT_AS_GUARD | MPO_INSERT_SEND_RIGHT | MPO_QLIMIT,
                                 .mpl = { .mpl_qlimit = 3 } };
    mach_port_t g;
    kr = mach_port_construct(task, &opts, 0x1234, &g);
    mach_port_type(task, g, &t);
    cnt = MACH_PORT_LIMITS_INFO_COUNT;
    mach_port_limits_t lim;
    mach_port_get_attributes(task, g, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&lim, &cnt);
    printf("construct: kr=%#x type=%#x qlimit=%u\n", kr, t, lim.mpl_qlimit);
    for (int i = 0; i < 3; i++) send_simple(g, MACH_MSG_TYPE_COPY_SEND, MACH_PORT_NULL, 0, 4000 + i);
    simple_t full;
    memset(&full, 0, sizeof full);
    full.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    full.h.msgh_size = sizeof full;
    full.h.msgh_remote_port = g;
    kr = mach_msg(&full.h, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof full, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    printf("send to full queue with timeout 0: kr=%#x\n", kr);
    /* (A wrong guard raises a fatal EXC_GUARD, so it is not exercised.) */
    kr = mach_port_destruct(task, g, -1, 0x1234);
    printf("destruct: kr=%#x\n", kr);
    kr = mach_port_type(task, g, &t);
    printf("after destruct: kr=%#x\n", kr);

    mach_port_t ctxp = new_port();
    kr = mach_port_set_context(task, ctxp, 0xabcdef);
    mach_port_context_t ctxv = 0;
    kr |= mach_port_get_context(task, ctxp, &ctxv);
    printf("context: kr=%#x value=%#lx\n", kr, (unsigned long)ctxv);
    kr = mach_port_guard(task, ctxp, 0x55, 0);
    printf("guard with a context set: kr=%#x\n", kr);
    mach_port_set_context(task, ctxp, 0);
    kr = mach_port_guard(task, ctxp, 0x55, 0);
    printf("guard: kr=%#x again=%#x\n", kr, mach_port_guard(task, ctxp, 0x55, 0));
    kr = mach_port_get_context(task, ctxp, &ctxv);
    printf("context of guarded: kr=%#x value=%#lx\n", kr, (unsigned long)ctxv);
    kr = mach_port_unguard(task, ctxp, 0x55);
    printf("unguard: kr=%#x\n", kr);

    /* Destroying a name with rights. */
    kr = mach_port_destroy(task, ctxp);
    printf("destroy: kr=%#x after=%#x\n", kr, mach_port_type(task, ctxp, &t));
    kr = mach_port_allocate(task, 7, &t);
    printf("allocate bad right: kr=%#x\n", kr);
    return 0;
}
