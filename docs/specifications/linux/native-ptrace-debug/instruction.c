#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

extern void probe_point(void);
__asm__(".text\n.globl probe_point\nprobe_point:\n nop\n ret\n");

static unsigned long peek(pid_t pid, int n) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, u_debugreg[n]), 0);
    if (errno) { perror("peek"); exit(2); }
    return (unsigned long)v;
}

static int poke(pid_t pid, int n, unsigned long value) {
    errno = 0;
    long ret = ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[n]), value);
    int error = errno;
    printf("{\"op\":\"poke\",\"slot\":%d,\"value\":\"%lx\",\"ret\":%ld,\"errno\":%d}\n", n, value, ret, error);
    return error;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(15);
    for (int slot = 0; slot < 4; slot++) {
        pid_t pid = fork();
        if (pid < 0) return 2;
        if (!pid) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(2);
            raise(SIGSTOP);
            probe_point();
            _exit(0);
        }
        int status;
        if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) return 3;
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL)) return 4;
        printf("{\"case\":%d,\"initial_dr6\":\"%lx\",\"initial_dr7\":\"%lx\"}\n",slot,peek(pid,6),peek(pid,7));
        if (poke(pid,4,0) != EIO || poke(pid,5,0) != EIO) return 5;
        if (poke(pid,6,0) || peek(pid,6) != 0) return 6;
        if (poke(pid,6,0x4001) || peek(pid,6) != 0x4001) return 7;
        // Address writes create a disabled length-one write breakpoint.
        if (poke(pid,slot,(unsigned long)probe_point)) return 8;
        unsigned long control = (unsigned long)(1 + (slot & 1)) << (slot * 2);
        if (poke(pid,7,control)) return 9;
        if (poke(pid,7,control | (4UL << (16 + slot * 4))) != EINVAL) return 10;
        if (peek(pid,7) != control) return 11;
        if (slot == 0) {
            unsigned long requested = 0xffffffff0000fc01UL;
            if (poke(pid,7,requested) || peek(pid,7) != requested) return 12;
            if (poke(pid,1,~0UL - 4095) != EINVAL) return 13;
        }
        if (ptrace(PTRACE_CONT,pid,0,0)) return 14;
        if (waitpid(pid,&status,0) != pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) return 15;
        struct user_regs_struct regs;
        siginfo_t info;
        if (ptrace(PTRACE_GETREGS,pid,0,&regs) || ptrace(PTRACE_GETSIGINFO,pid,0,&info)) return 16;
        unsigned long dr6 = peek(pid,6);
        printf("{\"case\":%d,\"trap\":%d,\"si_code\":%d,\"pc\":\"%llx\",\"expected_pc\":\"%lx\",\"rflags\":\"%llx\",\"dr6\":\"%lx\",\"dr7\":\"%lx\"}\n",slot,info.si_signo,info.si_code,regs.rip,(unsigned long)probe_point,regs.eflags,dr6,peek(pid,7));
        if (regs.rip != (unsigned long)probe_point || !(regs.eflags & (1UL << 16)) || dr6 != (0xffff0ff0UL | (1UL << slot))) return 17;
        if (ptrace(PTRACE_CONT,pid,0,0)) return 18;
        if (waitpid(pid,&status,0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 19;
        printf("{\"case\":%d,\"child_exit\":0}\n",slot);
    }
    return 0;
}
