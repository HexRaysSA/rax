/* System-call stops and single-stepping (kernel/entry/syscall-common.c,
 * kernel/ptrace.c, and each architecture's entry path) between a parent and
 * its child: PTRACE_SYSCALL's entry and exit stops with
 * PTRACE_O_TRACESYSGOOD, their messages, the architecture's entry view (the
 * result register at entry, AArch64's x7 showing the direction), and
 * PTRACE_GET_SYSCALL_INFO (sizes, a short buffer, a fault); a call's number
 * changed at entry, a call skipped (-1) with its result set at exit, an
 * error set at exit, and PTRACE_SET_SYSCALL_INFO's checks; a signal left at
 * an entry stop, sent from the kernel once the call is made; a stop without
 * TRACESYSGOOD; PTRACE_SYSEMU (entry stops only, the call not made even when
 * resumed with PTRACE_CONT); single steps (TRAP_TRACE at the next
 * instruction, a stepped system call's report, the stop entering a
 * handler); and execve under PTRACE_SYSCALL (its entry, the event stop, its
 * exit). Every value that differs between architectures (the entry view,
 * the step report's code, RISC-V lacking PTRACE_SYSEMU and stepping) is
 * checked here, not printed. */
#define _GNU_SOURCE
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "check.h"

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif
#define PTRACE_SET_SYSCALL_INFO 0x4212

#if defined(__x86_64__)
#define REGS_SIZE 216
#define PC_OF(r) ((r)[16])
#define AUDIT_ARCH_SELF 0xc000003eu
#define CAN_STEP 1
#define CAN_SYSEMU 1
/* send_sigtrap(regs, 0, TRAP_BRKPT) */
#define STEP_REPORT_CODE TRAP_BRKPT
#elif defined(__aarch64__)
#define REGS_SIZE 272
#define PC_OF(r) ((r)[32])
#define AUDIT_ARCH_SELF 0xc00000b7u
#define CAN_STEP 1
#define CAN_SYSEMU 1
/* The generic user_single_step_report: SI_USER from no one. */
#define STEP_REPORT_CODE SI_USER
#elif defined(__riscv)
#define REGS_SIZE 256
#define PC_OF(r) ((r)[0])
#define AUDIT_ARCH_SELF 0xc00000f3u
#define CAN_STEP 0
#define CAN_SYSEMU 0
#define STEP_REPORT_CODE 0
#endif

#define BAD ((void *)16)
#define SYSGOOD (SIGTRAP | 0x80)

struct info {
    uint8_t op, reserved;
    uint16_t flags;
    uint32_t arch;
    uint64_t ip, sp;
    union {
        struct {
            uint64_t nr, args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        uint8_t raw[64];
    };
};

static long pt(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static long get_info(pid_t c, struct info *i) {
    memset(i, 0, sizeof *i);
    return pt(PTRACE_GET_SYSCALL_INFO, c, (void *)sizeof *i, i);
}

static long set_info(pid_t c, struct info *i) {
    return pt(PTRACE_SET_SYSCALL_INFO, c, (void *)sizeof *i, i);
}

static unsigned long event_msg(pid_t c) {
    unsigned long m = ~0ul;
    pt(PTRACE_GETEVENTMSG, c, 0, &m);
    return m;
}

static int regs(pid_t c, uint64_t *r) {
    struct iovec iov = {r, REGS_SIZE};
    return pt(PTRACE_GETREGSET, c, (void *)NT_PRSTATUS, &iov) == 0 && iov.iov_len == REGS_SIZE;
}

/* The architecture's view of a call at its entry (1) or exit (0) stop:
 * x86-64's rax and RISC-V's a0 are -ENOSYS at entry and the result at
 * exit; AArch64 keeps x0 at entry and holds the direction in x7. */
static int entry_view(pid_t c, int entry, long result) {
    uint64_t r[40];
    if (!regs(c, r))
        return 0;
#if defined(__aarch64__)
    return r[7] == (entry ? 0 : 1) && (entry || r[0] == (uint64_t)result);
#else
    return r[10] == (uint64_t)(entry ? -ENOSYS : result);
#endif
}

static volatile int handled;
static void on_usr1(int s) { (void)s; handled++; }

static int wait_stop(pid_t c) {
    int st = 0;
    if (waitpid(c, &st, 0) != c)
        return -1;
    return WIFSTOPPED(st) ? st >> 8 : -2;
}

/* The child: marked calls (the first argument names each one to the
 * tracer), each result checked here. */
static int traced_calls(void) {
    signal(SIGUSR1, on_usr1);
    pt(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    pid_t me = syscall(SYS_getpid, 0);
    int ok = syscall(SYS_getpid, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6) == me;
    /* getppid becomes getpid. */
    ok &= syscall(SYS_getppid, 0xb1) == me;
    /* Skipped; its result set at the exit stop. */
    ok &= syscall(SYS_getuid, 0xc1) == 1234;
    /* An error set at the exit stop. */
    errno = 0;
    ok &= syscall(SYS_getgid, 0xd1) == -1 && errno == EPERM;
    /* A signal left at the entry stop: the call first, then the handler. */
    ok &= syscall(SYS_getpid, 0xe1) == me && handled == 1;
    return ok ? 0 : 1;
}

static void syscall_stops(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0)
        _exit(traced_calls());
    CHECK("stop", wait_stop(c) == SIGSTOP);
    CHECK("setoptions", pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACESYSGOOD) == 0);
    struct info i;
    long sig = 0, marker = 0;
    int entry = 1, st = 0;
    for (;;) {
        pt(PTRACE_SYSCALL, c, 0, (void *)sig);
        sig = 0;
        if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st))
            break;
        if ((st >> 8) != SYSGOOD) {
            siginfo_t si;
            pt(PTRACE_GETSIGINFO, c, 0, &si);
            CHECK("signal-from-kernel", WSTOPSIG(st) == SIGUSR1 && si.si_code == SI_KERNEL &&
                                            marker == 0xe1 && entry);
            sig = WSTOPSIG(st);
            continue;
        }
        long size = get_info(c, &i);
        if (entry) {
            if (!(size == 80 && i.op == PTRACE_SYSCALL_INFO_ENTRY && event_msg(c) == 1)) {
                CHECK("entry-stop", 0);
                break;
            }
            marker = i.entry.args[0];
        } else if (!(size == 33 && i.op == PTRACE_SYSCALL_INFO_EXIT && event_msg(c) == 2)) {
            CHECK("exit-stop", 0);
            break;
        }
        if (entry && marker == 0xa1) {
            int args = 1;
            for (int k = 0; k < 6; k++)
                args &= i.entry.args[k] == 0xa1 + (uint64_t)k;
            CHECK("entry-info", i.arch == AUDIT_ARCH_SELF && i.entry.nr == SYS_getpid && args &&
                                    i.ip != 0 && i.sp != 0);
            CHECK("entry-view", entry_view(c, 1, 0));
            CHECK_ERR("info-fault", pt(PTRACE_GET_SYSCALL_INFO, c, (void *)sizeof i, BAD), EFAULT);
        } else if (!entry && marker == 0xa1) {
            CHECK("exit-info", i.exit.rval == c && i.exit.is_error == 0);
            CHECK("exit-view", entry_view(c, 0, c));
            unsigned char small[16];
            memset(small, 0x5a, sizeof small);
            CHECK("info-short", pt(PTRACE_GET_SYSCALL_INFO, c, (void *)8, small) == 33 &&
                                    small[8] == 0x5a && small[0] == PTRACE_SYSCALL_INFO_EXIT);
        } else if (entry && marker == 0xb1) {
            i.entry.nr = SYS_getpid;
            CHECK("change-nr", set_info(c, &i) == 0);
        } else if (entry && marker == 0xc1) {
            struct info bad = i;
            bad.entry.nr = 1ull << 32;
            CHECK_ERR("set-range", set_info(c, &bad), ERANGE);
            bad = i;
            bad.flags = 1;
            CHECK_ERR("set-flags", set_info(c, &bad), EINVAL);
            bad = i;
            bad.op = PTRACE_SYSCALL_INFO_EXIT;
            CHECK_ERR("set-op", set_info(c, &bad), EINVAL);
            CHECK_ERR("set-size", pt(PTRACE_SET_SYSCALL_INFO, c, (void *)(sizeof i - 1), &i), EINVAL);
            CHECK_ERR("set-fault", pt(PTRACE_SET_SYSCALL_INFO, c, (void *)sizeof i, BAD), EFAULT);
            i.entry.nr = (uint64_t)-1;
            CHECK("skip", set_info(c, &i) == 0);
        } else if (!entry && marker == 0xc1) {
            i.exit.rval = 1234;
            i.exit.is_error = 0;
            CHECK("skipped-result", set_info(c, &i) == 0);
        } else if (!entry && marker == 0xd1) {
            i.exit.rval = -EPERM;
            i.exit.is_error = 1;
            CHECK("set-error", set_info(c, &i) == 0);
        } else if (entry && marker == 0xe1) {
            sig = SIGUSR1;
        } else if (!entry && marker == 0xe1) {
            CHECK("call-before-signal", i.exit.rval == c);
        }
        entry = !entry;
    }
    CHECK("calls", WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* Without PTRACE_O_TRACESYSGOOD: plain SIGTRAP, and no system call in
 * PTRACE_GET_SYSCALL_INFO's view. */
static void plain_stops(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        _exit(0);
    }
    wait_stop(c);
    pt(PTRACE_SYSCALL, c, 0, 0);
    struct info i;
    siginfo_t si;
    CHECK("plain-stop", wait_stop(c) == SIGTRAP && event_msg(c) == 1 && get_info(c, &i) == 24 &&
                            i.op == PTRACE_SYSCALL_INFO_NONE &&
                            pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_code == SIGTRAP &&
                            si.si_pid == c);
    pt(PTRACE_CONT, c, 0, 0);
    int st = 0;
    CHECK("plain-exit", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* PTRACE_SYSEMU: every stop an entry, the call never made. */
static void sysemu(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        errno = 0;
        long r = syscall(SYS_getpid, 0x51);
        int ok = CAN_SYSEMU ? r == -1 && errno == ENOSYS : r == getpid();
        _exit(ok ? 0 : 1);
    }
    wait_stop(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACESYSGOOD);
    int entries = 1, marked = 0;
    struct info i;
    if (!CAN_SYSEMU) {
        CHECK("sysemu", pt(PTRACE_SYSEMU, c, 0, 0) == -1 && errno == EIO);
        pt(PTRACE_CONT, c, 0, 0);
    } else {
        for (int n = 0; n < 16 && !marked; n++) {
            pt(PTRACE_SYSEMU, c, 0, 0);
            entries &= wait_stop(c) == SYSGOOD && get_info(c, &i) == 80 && event_msg(c) == 1;
            if (!entries)
                break;
            if (i.entry.args[0] == 0x51 && i.entry.nr == SYS_getpid) {
                /* -1 makes AArch64's result ENOSYS too. */
                i.entry.nr = (uint64_t)-1;
                marked = set_info(c, &i) == 0;
            }
        }
        CHECK("sysemu", entries && marked);
        /* Resumed with PTRACE_CONT: still not made (the flags were read
         * before the stop). */
        pt(PTRACE_CONT, c, 0, 0);
    }
    int st = 0;
    CHECK("sysemu-not-made", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void handler_mark(int s) { (void)s; handled++; }

/* Single steps: a trap at each next instruction, a stepped system call's
 * report, and the stop entering a handler. */
static void single_step(void) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        signal(SIGUSR1, handler_mark);
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        raise(SIGUSR1);
        _exit(handled == 1 ? 0 : 1);
    }
    wait_stop(c);
    if (!CAN_STEP) {
        /* RISC-V cannot step: refused, the tracee still in its stop. */
        siginfo_t si;
        CHECK("step", pt(PTRACE_SINGLESTEP, c, 0, 0) == -1 && errno == EIO);
        CHECK("step-report", pt(PTRACE_SYSEMU_SINGLESTEP, c, 0, 0) == -1 && errno == EIO);
        CHECK("step-handler", pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_signo == SIGSTOP);
        pt(PTRACE_CONT, c, 0, 0);
        wait_stop(c);
        pt(PTRACE_CONT, c, 0, (void *)SIGUSR1);
    } else {
        /* From the stop in raise's tkill: instructions, then the system
         * call that restores the mask. */
        int steps = 0, traced = 1, report = 0;
        for (int n = 0; n < 4096; n++) {
            pt(PTRACE_SINGLESTEP, c, 0, 0);
            siginfo_t si;
            uint64_t r[40];
            if (wait_stop(c) != SIGTRAP || pt(PTRACE_GETSIGINFO, c, 0, &si) != 0 || !regs(c, r)) {
                traced = 0;
                break;
            }
            if (si.si_code != TRAP_TRACE) {
                report = si.si_code == STEP_REPORT_CODE;
                break;
            }
            traced &= (uint64_t)si.si_addr == PC_OF(r);
            steps++;
        }
        CHECK("step", traced && steps > 0);
        CHECK("step-report", report);
        /* To SIGUSR1's stop, then into its handler one step at a time. */
        pt(PTRACE_CONT, c, 0, 0);
        int usr1 = 0;
        for (int n = 0; n < 4 && !usr1; n++) {
            usr1 = wait_stop(c) == SIGUSR1;
            if (!usr1)
                pt(PTRACE_CONT, c, 0, 0);
        }
        siginfo_t si;
        uint64_t r[40];
        pt(PTRACE_SINGLESTEP, c, 0, (void *)SIGUSR1);
        CHECK("step-handler", usr1 && wait_stop(c) == SIGTRAP &&
                                  pt(PTRACE_GETSIGINFO, c, 0, &si) == 0 && si.si_code == SIGTRAP &&
                                  regs(c, r) && PC_OF(r) == (uint64_t)handler_mark &&
                                  event_msg(c) == 0);
        pt(PTRACE_CONT, c, 0, 0);
    }
    int st = 0;
    CHECK("step-exit", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* execve under PTRACE_SYSCALL: its entry, the event stop, then its exit. */
static void exec_order(const char *self) {
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execl(self, self, "exit", (char *)NULL);
        _exit(99);
    }
    wait_stop(c);
    pt(PTRACE_SETOPTIONS, c, 0, (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC));
    struct info i;
    int step = 0;
    for (int n = 0; n < 64 && step < 3; n++) {
        pt(PTRACE_SYSCALL, c, 0, 0);
        int s = wait_stop(c);
        long size = get_info(c, &i);
        if (step == 0 && s == SYSGOOD && i.op == PTRACE_SYSCALL_INFO_ENTRY &&
            i.entry.nr == SYS_execve)
            step = 1;
        else if (step == 1)
            step = s == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)) && size == 24 &&
                           event_msg(c) == (unsigned long)c
                       ? 2
                       : -1;
        else if (step == 2)
            step = s == SYSGOOD && i.op == PTRACE_SYSCALL_INFO_EXIT && i.exit.rval == 0 ? 3 : -1;
        if (step < 0)
            break;
    }
    CHECK("exec-order", step == 3);
    pt(PTRACE_CONT, c, 0, 0);
    int st = 0;
    CHECK("exec-exit", waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 42);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "exit") == 0)
        return 42;
    syscall_stops();
    plain_stops();
    sysemu();
    single_step();
    exec_order(argv[0]);
    FINISH();
}
