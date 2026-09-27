// Mach exception delivery to handler threads of the process: the request
// each behavior sends (its ID, size, header bits, descriptors, codes, and
// thread state), a reply that resumes the thread (with the state it
// returns) or refuses the exception (the next level, then the signal),
// the thread's handler before the task's, the codes each fault raises,
// and port guard violations delivered as the task's guard behavior asks.
// Rosetta departs from the kernel where a handler fails to reply
// properly, for dead or stateless handlers, for the brk ranges, and for
// guard exceptions: those run on arm64 only.
#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void out(const char *fmt, ...) {
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    write(1, b, (size_t)n);
}

// The faults. Each returns in x0 / rax; a handler that skips the
// faulting instruction sets that register to 0x5a5a.
#if defined(__arm64__)
#define THREAD_FLAVOR ARM_THREAD_STATE64
#define UNIFIED_FLAVOR ARM_THREAD_STATE
#define EXC_STATE_FLAVOR ARM_EXCEPTION_STATE64
__asm__(".text\n.p2align 2\n"
        ".globl _f_load\n_f_load:\n ldr w0, [x0]\n ret\n"
        ".globl _f_store\n_f_store:\n str w1, [x0]\n mov x0, #7\n ret\n"
        ".globl _f_brk\n_f_brk:\n brk #0\n mov x0, #7\n ret\n"
        ".globl _f_udf\n_f_udf:\n .long 0x0000dead\n mov x0, #7\n ret\n"
        ".globl _f_div\n_f_div:\n sdiv x0, x0, x1\n ret\n"
        ".globl _f_badtrap\n_f_badtrap:\n mov x16, #-200\n svc #0x80\n mov x0, #7\n ret\n"
        ".globl _f_brkb000\n_f_brkb000:\n brk #0xb000\n mov x0, #7\n ret\n"
        ".globl _f_brkc471\n_f_brkc471:\n brk #0xc471\n mov x0, #7\n ret\n");
enum { LEN_LOAD = 4, LEN_STORE = 4, LEN_BRK = 4, LEN_UDF = 4, LEN_DIV = 4 };
#else
#define THREAD_FLAVOR x86_THREAD_STATE64
#define UNIFIED_FLAVOR x86_THREAD_STATE
#define EXC_STATE_FLAVOR x86_EXCEPTION_STATE64
__asm__(".text\n"
        ".globl _f_load\n_f_load:\n movl (%rdi), %eax\n ret\n"
        ".globl _f_store\n_f_store:\n movl %esi, (%rdi)\n movl $7, %eax\n ret\n"
        ".globl _f_brk\n_f_brk:\n int3\n movl $7, %eax\n ret\n"
        ".globl _f_udf\n_f_udf:\n ud2\n movl $7, %eax\n ret\n"
        ".globl _f_div\n_f_div:\n xorl %edx, %edx\n movl $1, %eax\n divl %esi\n movl $7, %eax\n ret\n"
        ".globl _f_badtrap\n_f_badtrap:\n movl $0x10000c8, %eax\n syscall\n movl $7, %eax\n ret\n"
        ".globl _f_brkb000\n_f_brkb000:\n int3\n ret\n"
        ".globl _f_brkc471\n_f_brkc471:\n int3\n ret\n");
// The breakpoint's state is already past the int3.
enum { LEN_LOAD = 2, LEN_STORE = 2, LEN_BRK = 0, LEN_UDF = 2, LEN_DIV = 2 };
#endif
extern long f_load(void *p);
extern long f_store(void *p, int v);
extern long f_brk(void);
extern long f_udf(void);
extern long f_div(long a, long zero);
extern long f_badtrap(void);
extern long f_brkb000(void);
extern long f_brkc471(void);

enum fault { LOAD_NULL, LOAD_PROTNONE, STORE_RO, BRK, UDF, DIV, BADTRAP, BRKB000, BRKC471 };

enum reply { SKIP, NOCHANGE, FAIL, DESTROY, BADCNT, SETSTATE, WRONGID, NOTSUP, INVARG, NOREPLY, DEFER };
static const char *reply_name[] = {"skip",   "unchanged", "KERN_FAILURE",  "destroy the reply right",
                                   "count 0", "set state", "wrong ID",     "KERN_NOT_SUPPORTED",
                                   "KERN_INVALID_ARGUMENT", "MIG_NO_REPLY", "skip after a while"};

// The handler's stop message.
#define STOP_ID 999

struct level {
    const char *tag;
    mach_port_t port;
    int n;
    enum reply replies[2];
    pthread_t thread;
};

static mach_port_t faulter, guard_target;
static uint64_t faulter_id;
static uintptr_t fault_fn, fault_addr;
static long fault_len;
static void *protnone, *readonly;

static const char *rel(uint64_t v) {
    static char b[4][48];
    static int i;
    char *s = b[i++ & 3];
    if (v >= fault_fn && v < fault_fn + 64)
        snprintf(s, 48, "FN+%llu", (unsigned long long)(v - fault_fn));
    else if (fault_addr && v == fault_addr)
        snprintf(s, 48, "ADDR");
    else if (fault_addr && (uint32_t)v == (uint32_t)fault_addr)
        snprintf(s, 48, "ADDR (low 32 bits)");
    else
        snprintf(s, 48, "%#llx", (unsigned long long)v);
    return s;
}

static void show_state(int flavor, uint32_t n, uint32_t *s) {
    out("    state flavor=%d count=%u", flavor, n);
#if defined(__arm64__)
    if (flavor == ARM_THREAD_STATE && n >= 70) {
        out(" header=%u,%u", s[0], s[1]);
        s += 2;
        flavor = ARM_THREAD_STATE64;
    }
    if (flavor == ARM_THREAD_STATE64 && n >= 68)
        out(" pc=%s flags=%#x", rel(*(uint64_t *)(s + 64)), s[67]);
    if (flavor == ARM_EXCEPTION_STATE64 && n >= 4)
        out(" far=%s ec=%#x exception=%u", rel(*(uint64_t *)s), s[2] >> 26, s[3]);
#else
    if (flavor == x86_THREAD_STATE && n >= 44) {
        out(" header=%u,%u", s[0], s[1]);
        s += 2;
        flavor = x86_THREAD_STATE64;
    }
    if (flavor == x86_THREAD_STATE64 && n >= 42) out(" rip=%s", rel(*(uint64_t *)(s + 32)));
#endif
    out("\n");
}

// Skips the faulting instruction and sets the return register.
static void skip(int flavor, uint32_t n, uint32_t *s) {
#if defined(__arm64__)
    if (flavor == ARM_THREAD_STATE && n >= 70) s += 2;
    else if (flavor != ARM_THREAD_STATE64 || n < 68) return;
    *(uint64_t *)(s + 64) += fault_len;
    *(uint64_t *)s = 0x5a5a;
#else
    if (flavor == x86_THREAD_STATE && n >= 44) s += 2;
    else if (flavor != x86_THREAD_STATE64 || n < 42) return;
    *(uint64_t *)(s + 32) += fault_len;
    *(uint64_t *)s = 0x5a5a;
#endif
}

static void send_reply(mach_msg_header_t *req, kern_return_t ret, int with_state, int flavor, uint32_t n,
                       const uint32_t *s, int id) {
    struct {
        mach_msg_header_t h;
        NDR_record_t ndr;
        kern_return_t ret;
        int flavor;
        mach_msg_type_number_t n;
        uint32_t s[1296];
    } r;
    memset(&r, 0, 44);
    r.h.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->msgh_bits), 0);
    r.h.msgh_remote_port = req->msgh_remote_port;
    r.h.msgh_id = id;
    r.ndr = NDR_record;
    r.ret = ret;
    mach_msg_size_t size = 36;
    if (with_state && ret == KERN_SUCCESS) {
        r.flavor = flavor;
        r.n = n;
        memcpy(r.s, s, n * 4);
        size = 44 + n * 4;
    }
    r.h.msgh_size = size;
    kern_return_t kr = mach_msg(&r.h, MACH_SEND_MSG, size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (kr) out("    reply: %#x\n", kr);
}

static void *handler(void *arg) {
    struct level *lv = arg;
    for (int k = 0;; k++) {
        union {
            mach_msg_header_t h;
            char b[8192];
        } m;
        kern_return_t kr = mach_msg(&m.h, MACH_RCV_MSG, 0, sizeof m, lv->port, 0, MACH_PORT_NULL);
        if (kr) {
            out("[%s] receive: %#x\n", lv->tag, kr);
            return NULL;
        }
        mach_msg_header_t *h = &m.h;
        if (h->msgh_id == STOP_ID) return NULL;
        int id = h->msgh_id;
        out("[%s] id=%d size=%u bits=%#x reply=%s local=%s\n", lv->tag, id, h->msgh_size, h->msgh_bits,
            h->msgh_remote_port ? "set" : "null", h->msgh_local_port == lv->port ? "handler" : "other");
        char *b = m.b;
        int off = 24;
        mach_port_t thread = MACH_PORT_NULL;
        if (h->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            uint32_t nd = *(uint32_t *)(b + 24);
            mach_msg_port_descriptor_t *d = (void *)(b + 28);
            out("    descriptors=%u:", nd);
            for (uint32_t i = 0; i < nd && i < 2; i++) {
                const char *what = d[i].name == faulter ? "the thread"
                                   : d[i].name == mach_task_self() ? "the task"
                                                                   : "other";
                out(" %s (disposition %u, type %u)", what, d[i].disposition, d[i].type);
            }
            out("\n");
            thread = d[0].name;
            off = 28 + 12 * (int)nd;
        }
        off += 8; // NDR
        if (id == 2408 || id == 2410) {
            // The protected behaviors: the thread's ID and a token of the
            // task.
            mach_port_t task = MACH_PORT_NULL;
            kern_return_t tk = task_identity_token_get_task_port(thread, TASK_FLAVOR_CONTROL, &task);
            out("    thread ID matches %d, the token's task: kr=%d the task %d\n", *(uint64_t *)(b + off) == faulter_id,
                tk, task == mach_task_self());
            off += 8;
        }
        int wide = id >= 2405;
        int exc = *(int *)(b + off);
        uint32_t ncodes = *(uint32_t *)(b + off + 4);
        off += 8;
        out("    exception=%d codes=%u:", exc, ncodes);
        if (exc == EXC_GUARD && wide && ncodes == 2) {
            // Type, flavor, and target (the port name) of the guard.
            uint64_t c = *(uint64_t *)(b + off);
            out(" type %llu flavor %#llx target %s, %#llx", (unsigned long long)(c >> 61),
                (unsigned long long)((c >> 32) & 0x1fffffff),
                (uint32_t)c == guard_target ? "the port" : (uint32_t)c ? "other" : "0",
                (unsigned long long)*(uint64_t *)(b + off + 8));
            ncodes = 0;
        }
        for (uint32_t i = 0; i < ncodes && i < 2; i++) {
            int64_t c = wide ? *(int64_t *)(b + off + 8 * i) : *(int32_t *)(b + off + 4 * i);
            if (i == 0)
                out(" %#llx", (unsigned long long)c);
            else
                out(" %s", rel((uint64_t)c));
        }
        out("\n");
        off += (int)*(uint32_t *)(b + off - 4) * (wide ? 8 : 4);
        int stateful = id == 2402 || id == 2403 || id == 2406 || id == 2407 || id == 2410;
        int flavor = 0;
        uint32_t n = 0, *s = NULL;
        if (stateful) {
            flavor = *(int *)(b + off);
            n = *(uint32_t *)(b + off + 4);
            s = (uint32_t *)(b + off + 8);
            show_state(flavor, n, s);
        }
        enum reply r = k < lv->n ? lv->replies[k] : FAIL;
        out("    -> %s\n", reply_name[r]);
        switch (r) {
        case DEFER: {
            usleep(100000);
            thread_basic_info_data_t bi;
            mach_msg_type_number_t bn = THREAD_BASIC_INFO_COUNT;
            kr = thread_info(faulter, THREAD_BASIC_INFO, (thread_info_t)&bi, &bn);
            out("    the thread meanwhile: kr=%d run_state=%d suspend_count=%d\n", kr, bi.run_state,
                bi.suspend_count);
        }
            // fallthrough
        case SKIP:
            if (stateful) {
                skip(flavor, n, s);
            } else {
                mprotect(protnone, 16384, PROT_READ | PROT_WRITE);
            }
            send_reply(h, KERN_SUCCESS, stateful, flavor, n, s, id + 100);
            break;
        case NOCHANGE: send_reply(h, KERN_SUCCESS, stateful, flavor, n, s, id + 100); break;
        case FAIL: send_reply(h, KERN_FAILURE, stateful, flavor, n, s, id + 100); break;
        case NOTSUP: send_reply(h, KERN_NOT_SUPPORTED, stateful, flavor, n, s, id + 100); break;
        case INVARG: send_reply(h, KERN_INVALID_ARGUMENT, stateful, flavor, n, s, id + 100); break;
        case NOREPLY: send_reply(h, MIG_NO_REPLY, stateful, flavor, n, s, id + 100); break;
        case BADCNT: send_reply(h, KERN_SUCCESS, 1, flavor, 0, s, id + 100); break;
        case WRONGID: send_reply(h, KERN_SUCCESS, stateful, flavor, n, s, id + 101); break;
        case DESTROY:
            out("    deallocate: %d\n", mach_port_deallocate(mach_task_self(), h->msgh_remote_port));
            break;
        case SETSTATE: {
#if defined(__arm64__)
            arm_thread_state64_t ts;
            mach_msg_type_number_t tn = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts, &tn);
            out("    thread_get_state: %d pc=%s\n", kr, rel(__darwin_arm_thread_state64_get_pc(ts)));
            __darwin_arm_thread_state64_set_pc_fptr(ts, (void *)(__darwin_arm_thread_state64_get_pc(ts) + fault_len));
            ts.__x[0] = 0x5a5a;
            kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts, tn);
#else
            x86_thread_state64_t ts;
            mach_msg_type_number_t tn = x86_THREAD_STATE64_COUNT;
            kr = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&ts, &tn);
            out("    thread_get_state: %d rip=%s\n", kr, rel(ts.__rip));
            ts.__rip += fault_len;
            ts.__rax = 0x5a5a;
            kr = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&ts, tn);
#endif
            out("    thread_set_state: %d\n", kr);
            send_reply(h, KERN_SUCCESS, 0, 0, 0, NULL, id + 100);
            break;
        }
        }
    }
}

static sigjmp_buf jb;

static void on_signal(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    out("signal %d code %d addr %s\n", sig, si->si_code, rel((uint64_t)(uintptr_t)si->si_addr));
    siglongjmp(jb, 1);
}

static mach_port_t new_port(void) {
    mach_port_t p = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
}

#define CODES MACH_EXCEPTION_CODES
#define FAULTS (EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT)

static struct level levels[2];
static int nlevels;

// A handler for the thread (or the task) of the exceptions of `mask`.
static void handle(int thread_level, exception_mask_t mask, int behavior, int flavor, int n, enum reply r0,
                   enum reply r1) {
    struct level *lv = &levels[nlevels++];
    lv->tag = thread_level ? "thread" : "task";
    lv->port = new_port();
    lv->n = n;
    lv->replies[0] = r0;
    lv->replies[1] = r1;
    kern_return_t kr = thread_level
                           ? thread_set_exception_ports(mach_thread_self(), mask, lv->port, behavior, flavor)
                           : task_set_exception_ports(mach_task_self(), mask, lv->port, behavior, flavor);
    if (kr) out("set %s: %d\n", lv->tag, kr);
    pthread_create(&lv->thread, NULL, handler, lv);
}

// Removes the handlers and stops their threads.
static void unhandle(void) {
    thread_set_exception_ports(mach_thread_self(), EXC_MASK_ALL, MACH_PORT_NULL, 0, 0);
    task_set_exception_ports(mach_task_self(), FAULTS | EXC_MASK_SYSCALL, MACH_PORT_NULL, 0, 0);
    for (int i = 0; i < nlevels; i++) {
        mach_msg_header_t h = {0};
        h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        h.msgh_size = sizeof h;
        h.msgh_remote_port = levels[i].port;
        h.msgh_id = STOP_ID;
        mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
        pthread_join(levels[i].thread, NULL);
        mach_port_mod_refs(mach_task_self(), levels[i].port, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(mach_task_self(), levels[i].port);
    }
    nlevels = 0;
}

static void fire(enum fault f) {
    faulter = mach_thread_self();
    thread_identifier_info_data_t ti;
    mach_msg_type_number_t tn = THREAD_IDENTIFIER_INFO_COUNT;
    thread_info(faulter, THREAD_IDENTIFIER_INFO, (thread_info_t)&ti, &tn);
    faulter_id = ti.thread_id;
    long v = -1;
    fault_addr = 0;
    if (sigsetjmp(jb, 1) == 0) {
        switch (f) {
        case LOAD_NULL:
            fault_fn = (uintptr_t)f_load, fault_len = LEN_LOAD;
            v = f_load(NULL);
            break;
        case LOAD_PROTNONE:
            fault_fn = (uintptr_t)f_load, fault_len = LEN_LOAD, fault_addr = (uintptr_t)protnone + 8;
            v = f_load((char *)protnone + 8);
            break;
        case STORE_RO:
            fault_fn = (uintptr_t)f_store, fault_len = LEN_STORE, fault_addr = (uintptr_t)readonly + 16;
            v = f_store((char *)readonly + 16, 1);
            break;
        case BRK:
            fault_fn = (uintptr_t)f_brk, fault_len = LEN_BRK;
            v = f_brk();
            break;
        case UDF:
            fault_fn = (uintptr_t)f_udf, fault_len = LEN_UDF;
            v = f_udf();
            break;
        case DIV:
            fault_fn = (uintptr_t)f_div, fault_len = LEN_DIV;
            v = f_div(1, 0);
            break;
        case BADTRAP:
            fault_fn = (uintptr_t)f_badtrap, fault_len = 0;
            v = f_badtrap();
            break;
        case BRKB000:
            fault_fn = (uintptr_t)f_brkb000, fault_len = LEN_BRK;
            v = f_brkb000();
            break;
        case BRKC471:
            fault_fn = (uintptr_t)f_brkc471, fault_len = LEN_BRK;
            v = f_brkc471();
            break;
        }
        out("returned %#lx\n", v);
    }
    mprotect(protnone, 16384, PROT_NONE);
}

// One handler of the task's faults with one reply, and a fault.
static void one(const char *what, int behavior, int flavor, enum fault f, enum reply r) {
    out("\n%s\n", what);
    handle(0, FAULTS, behavior, flavor, 1, r, r);
    fire(f);
    unhandle();
}

#if defined(__arm64__)
extern kern_return_t task_set_exc_guard_behavior(task_t, uint32_t);
extern kern_return_t task_get_exc_guard_behavior(task_t, uint32_t *);

// TASK_EXC_GUARD_MP_*.
#define MP_DELIVER 0x10
#define MP_ONCE 0x20
#define MP_FATAL 0x80

// A port guard violation in a child with its own handler of EXC_GUARD:
// destroying a guarded receive right (fatal), or deallocating a name
// that does not exist twice (delivered as the task's guard behavior
// asks).
static void guard_child(const char *what, uint32_t behavior, int destroy) {
    out("\n%s\n", what);
    pid_t pid = fork();
    if (pid == 0) {
        faulter = mach_thread_self();
        task_set_exc_guard_behavior(mach_task_self(), behavior);
        handle(0, EXC_MASK_GUARD, EXCEPTION_DEFAULT | CODES, 0, 2, NOCHANGE, NOCHANGE);
        if (destroy) {
            mach_port_options_t o = {.flags = MPO_CONTEXT_AS_GUARD | MPO_STRICT};
            mach_port_construct(mach_task_self(), &o, 0x1234, &guard_target);
            out("destroy: %d\n", mach_port_mod_refs(mach_task_self(), guard_target, MACH_PORT_RIGHT_RECEIVE, -1));
        } else {
            guard_target = 0x12345603;
            out("deallocate: %d\n", mach_port_deallocate(mach_task_self(), guard_target));
            out("deallocate: %d\n", mach_port_deallocate(mach_task_self(), guard_target));
            uint32_t now = 0;
            task_get_exc_guard_behavior(mach_task_self(), &now);
            out("guard behavior now %#x\n", now);
        }
        unhandle();
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    out("child: exited %d status %d signaled %d signal %d\n", WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : 0,
        WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO;
    int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGSYS};
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, NULL);
    protnone = mmap(NULL, 16384, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    readonly = mmap(NULL, 16384, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    const int T = THREAD_FLAVOR;

    // Task identity tokens: a new one each time, the task's ports by
    // flavor, and the targets they need.
    {
        task_id_token_t t = MACH_PORT_NULL, t2 = MACH_PORT_NULL;
        out("identity token: %d\n", task_create_identity_token(mach_task_self(), &t));
        out("another: %d, the same %d\n", task_create_identity_token(mach_task_self(), &t2), t == t2);
        natural_t type = 0;
        mach_vm_address_t addr = 0;
        mach_port_type_t pt = 0;
        out("kobject: %d type %u\n", mach_port_kobject(mach_task_self(), t, &type, &addr), type);
        out("port type: %d %#x\n", mach_port_type(mach_task_self(), t, &pt), pt);
        for (int f = 0; f <= 4; f++) {
            mach_port_t p = MACH_PORT_NULL;
            kern_return_t kr = task_identity_token_get_task_port(t, f, &p);
            type = 0;
            if (p) mach_port_kobject(mach_task_self(), p, &type, &addr);
            out("flavor %d: %d %s kobject %u\n", f, kr, !p ? "null" : p == mach_task_self() ? "the task" : "other",
                type);
        }
        mach_port_t rd = MACH_PORT_NULL, p = MACH_PORT_NULL;
        task_get_special_port(mach_task_self(), TASK_READ_PORT, &rd);
        out("token of the read port: %d\n", task_create_identity_token(rd, &t2));
        out("token of a thread port: %d\n", task_create_identity_token(mach_thread_self(), &t2));
        out("task port of the task port: %d\n", task_identity_token_get_task_port(mach_task_self(), 0, &p));
        out("task port of null: %#x\n", task_identity_token_get_task_port(MACH_PORT_NULL, 0, &p));
        mach_port_deallocate(mach_task_self(), t);
        mach_port_deallocate(mach_task_self(), t2);
    }

    // The behaviors' requests; the state a reply returns resumes the thread.
    one("state, 64-bit codes: null load", EXCEPTION_STATE | CODES, T, LOAD_NULL, SKIP);
    one("state: null load", EXCEPTION_STATE, T, LOAD_NULL, SKIP);
    one("state and identity, 64-bit codes: null load", EXCEPTION_STATE_IDENTITY | CODES, T, LOAD_NULL, SKIP);
    one("state and identity: null load", EXCEPTION_STATE_IDENTITY, T, LOAD_NULL, SKIP);
    one("default, 64-bit codes: inaccessible page, made accessible", EXCEPTION_DEFAULT | CODES, 0, LOAD_PROTNONE,
        SKIP);
    one("default: inaccessible page, made accessible", EXCEPTION_DEFAULT, 0, LOAD_PROTNONE, SKIP);
    one("default: the handler sets the thread's state", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, SETSTATE);
    one("unified thread state: null load", EXCEPTION_STATE | CODES, UNIFIED_FLAVOR, LOAD_NULL, SKIP);

    // The faults' codes.
    one("store to a read-only page", EXCEPTION_STATE | CODES, T, STORE_RO, SKIP);
    one("breakpoint", EXCEPTION_STATE | CODES, T, BRK, SKIP);
    one("undefined instruction", EXCEPTION_STATE | CODES, T, UDF, SKIP);
    one("division by zero", EXCEPTION_STATE | CODES, T, DIV, SKIP);
    out("\ninvalid Mach trap\n");
    handle(0, EXC_MASK_SYSCALL, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    fire(BADTRAP);
    unhandle();
    out("\ninvalid Mach trap, default behavior, resumed\n");
    handle(0, EXC_MASK_SYSCALL, EXCEPTION_DEFAULT | CODES, 0, 1, NOCHANGE, NOCHANGE);
    fire(BADTRAP);
    unhandle();

    // Refusals: the signal.
    one("refused: null load", EXCEPTION_STATE | CODES, T, LOAD_NULL, FAIL);
    one("refused: inaccessible page", EXCEPTION_STATE | CODES, T, LOAD_PROTNONE, FAIL);
    one("refused: store to a read-only page", EXCEPTION_STATE | CODES, T, STORE_RO, FAIL);
    one("refused: breakpoint", EXCEPTION_STATE | CODES, T, BRK, FAIL);
    one("refused: undefined instruction", EXCEPTION_STATE | CODES, T, UDF, FAIL);
    one("refused: division by zero", EXCEPTION_STATE | CODES, T, DIV, FAIL);
    one("not supported: null load", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, NOTSUP);
    one("invalid argument: null load", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, INVARG);
    one("MIG_NO_REPLY as the result: null load", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, NOREPLY);
    out("\nrefused: invalid Mach trap\n");
    handle(0, EXC_MASK_SYSCALL, EXCEPTION_STATE | CODES, T, 1, FAIL, FAIL);
    fire(BADTRAP);
    unhandle();

    // Levels: the thread's handler first; the task's when it refuses.
    out("\nthread refuses, task skips\n");
    handle(1, FAULTS, EXCEPTION_STATE | CODES, T, 1, FAIL, FAIL);
    handle(0, FAULTS, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    fire(LOAD_NULL);
    unhandle();
    out("\nthread skips\n");
    handle(1, FAULTS, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    handle(0, FAULTS, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    fire(LOAD_NULL);
    unhandle();
    out("\ndefault, unchanged, then refused: the fault repeats\n");
    handle(0, FAULTS, EXCEPTION_DEFAULT | CODES, 0, 2, NOCHANGE, FAIL);
    fire(LOAD_NULL);
    unhandle();
    out("\na handler of breakpoints only: null load\n");
    handle(0, EXC_MASK_BREAKPOINT, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    fire(LOAD_NULL);
    unhandle();

#if defined(__arm64__)
    // Rosetta delivers these again to the same handler or aborts.
    out("\nexception state, unchanged, then refused\n");
    handle(0, FAULTS, EXCEPTION_STATE | CODES, EXC_STATE_FLAVOR, 2, NOCHANGE, FAIL);
    fire(LOAD_NULL);
    unhandle();
    one("reply right destroyed: null load", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, DESTROY);
    out("\nthread's reply right destroyed, task skips\n");
    handle(1, FAULTS, EXCEPTION_DEFAULT | CODES, 0, 1, DESTROY, DESTROY);
    handle(0, FAULTS, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
    fire(LOAD_NULL);
    unhandle();
    one("state count 0: null load", EXCEPTION_STATE | CODES, T, LOAD_NULL, BADCNT);
    one("reply with the wrong ID: null load", EXCEPTION_DEFAULT | CODES, 0, LOAD_NULL, WRONGID);
    one("flavor 0: null load", EXCEPTION_STATE | CODES, 0, LOAD_NULL, SKIP);
    one("the handler replies later", EXCEPTION_STATE | CODES, T, LOAD_NULL, DEFER);
    one("breakpoint 0xc471", EXCEPTION_STATE | CODES, T, BRKC471, SKIP);
    // Rosetta refuses the protected behaviors.
    one("identity protected: inaccessible page, made accessible", EXCEPTION_IDENTITY_PROTECTED | CODES, 0,
        LOAD_PROTNONE, SKIP);
    one("state and identity protected: null load", EXCEPTION_STATE_IDENTITY_PROTECTED | CODES, T, LOAD_NULL, SKIP);
    one("state and identity protected, refused: null load", EXCEPTION_STATE_IDENTITY_PROTECTED | CODES, T,
        LOAD_NULL, FAIL);
    out("\ndead handler: null load\n");
    {
        mach_port_t p = new_port();
        task_set_exception_ports(mach_task_self(), FAULTS, p, EXCEPTION_DEFAULT | CODES, 0);
        mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
        fire(LOAD_NULL);
        task_set_exception_ports(mach_task_self(), FAULTS, MACH_PORT_NULL, 0, 0);
        mach_port_deallocate(mach_task_self(), p);
    }
    out("\nbreakpoint 0xb000 in a child\n");
    pid_t pid = fork();
    if (pid == 0) {
        handle(0, FAULTS, EXCEPTION_STATE | CODES, T, 1, SKIP, SKIP);
        fire(BRKB000);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    out("child: signaled %d signal %d\n", WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0);

    // Guard exceptions (Rosetta kills the process while it delivers them).
    guard_child("guarded receive right destroyed", 0, 1);
    guard_child("invalid name, guard exceptions not delivered", 0, 0);
    guard_child("invalid name, guard exceptions delivered", MP_DELIVER, 0);
    guard_child("invalid name, guard exceptions delivered once", MP_DELIVER | MP_ONCE, 0);
    guard_child("invalid name, guard exceptions delivered and fatal", MP_DELIVER | MP_FATAL, 0);
    guard_child("invalid name, guard exceptions fatal but not delivered", MP_FATAL, 0);
#endif
    out("\ndone\n");
    return 0;
}
