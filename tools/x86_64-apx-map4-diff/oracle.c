#define _GNU_SOURCE

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIRE_MAGIC 0x34585041u /* 'A','P','X','4' little-endian */
#define GPR_REGS 32
#define SCRATCH_BYTES 256
#define STACK_BYTES 256

#ifndef APX_MAP4_DIFF_CASES_INC
#error "APX_MAP4_DIFF_CASES_INC must name the generated case switch include"
#endif

#ifndef APX_MAP4_DIFF_DECLS_INC
#error "APX_MAP4_DIFF_DECLS_INC must name the generated case declaration include"
#endif

struct in_case {
    uint32_t id;
    uint32_t mode;
    uint64_t gpr[GPR_REGS];
    uint64_t rflags;
    uint8_t scratch[SCRATCH_BYTES];
    uint8_t stack[STACK_BYTES];
};

struct out_case {
    uint32_t id;
    uint32_t valid;
    uint32_t signal;
    uint32_t reserved;
    uint64_t gpr[GPR_REGS];
    uint64_t rflags;
    uint8_t scratch[SCRATCH_BYTES];
    uint8_t stack[STACK_BYTES];
};

extern uint64_t apx_host_rsp;
extern uint64_t apx_tmp_rax;
extern uint64_t apx_tmp_rsp;
extern uint64_t apx_tmp_rflags;
extern uint64_t apx_tmp_stack_rsp;
extern const struct in_case *apx_in_ptr;
extern struct out_case *apx_out_ptr;

typedef void (*case_fn_t)(const struct in_case *in, struct out_case *out);

#include APX_MAP4_DIFF_DECLS_INC

static sigjmp_buf signal_jmp;
static volatile sig_atomic_t signal_active;
static volatile sig_atomic_t caught_signal;
static unsigned char signal_stack[64 * 1024];

static void signal_handler(int signo) {
    if (signal_active) {
        caught_signal = signo;
        siglongjmp(signal_jmp, 1);
    }
    _Exit(111);
}

static int install_handler(int signo) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    return sigaction(signo, &sa, NULL);
}

static case_fn_t lookup_case(uint32_t id) {
    switch (id) {
#include APX_MAP4_DIFF_CASES_INC
    default:
        return NULL;
    }
}

static void execute_case(const struct in_case *in, struct out_case *out) {
    case_fn_t fn = lookup_case(in->id);

    out->id = in->id;
    out->valid = fn != NULL;
    out->signal = 0;
    out->reserved = 0;
    memset(out->gpr, 0, sizeof(out->gpr));
    out->rflags = 0;
    memcpy(out->scratch, in->scratch, sizeof(out->scratch));
    memcpy(out->stack, in->stack, sizeof(out->stack));

    if (fn == NULL) {
        return;
    }

    caught_signal = 0;
    if (sigsetjmp(signal_jmp, 1) == 0) {
        signal_active = 1;
        fn(in, out);
        signal_active = 0;
    } else {
        signal_active = 0;
        out->valid = 0;
        out->signal = (uint32_t)caught_signal;
        memcpy(out->gpr, in->gpr, sizeof(out->gpr));
        out->rflags = in->rflags;
        memcpy(out->scratch, in->scratch, sizeof(out->scratch));
        memcpy(out->stack, in->stack, sizeof(out->stack));
    }
}

int main(void) {
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = signal_stack;
    ss.ss_size = sizeof(signal_stack);
    if (sigaltstack(&ss, NULL) != 0) {
        return 1;
    }

    if (install_handler(SIGILL) != 0 || install_handler(SIGSEGV) != 0 ||
        install_handler(SIGBUS) != 0 || install_handler(SIGFPE) != 0) {
        return 2;
    }

    uint32_t header[2];
    if (fread(header, sizeof(header), 1, stdin) != 1) {
        return 3;
    }
    if (header[0] != WIRE_MAGIC) {
        return 4;
    }

    if (fwrite(header, sizeof(header), 1, stdout) != 1) {
        return 5;
    }

    for (uint32_t i = 0; i < header[1]; i++) {
        struct in_case in;
        struct out_case out;
        if (fread(&in, sizeof(in), 1, stdin) != 1) {
            return 6;
        }
        execute_case(&in, &out);
        if (fwrite(&out, sizeof(out), 1, stdout) != 1) {
            return 7;
        }
    }

    return 0;
}
