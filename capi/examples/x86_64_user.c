/*
 * x86_64_user.c — process-level emulation: the host plays the kernel.
 *
 * With RAX_MODE_USER the engine runs ring-3 code and hands every SYSCALL to a
 * hook. This one implements write(2) and exit(2) of the Linux x86-64 ABI
 * (number in RAX, arguments in RDI/RSI/RDX, result in RAX). Region
 * permissions are enforced: the code page is read+execute and the message
 * lives in a read-only page, so a store into it faults precisely.
 */
#include "rax.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define CHECK(e) do { rax_status _s = (e); if (_s != RAX_OK) { \
    fprintf(stderr, "%s: %s\n", #e, rax_strerror(_s)); return 1; } } while (0)

#define CODE 0x400000u
#define DATA 0x401000u

struct process {
    char output[64];
    size_t output_len;
    int exit_code;
    int exited;
};

static void on_syscall(rax_engine *e, uint64_t pc, uint32_t insn, uint32_t imm, void *user) {
    struct process *p = (struct process *)user;
    uint64_t nr = 0, a0 = 0, a1 = 0, a2 = 0, ret = (uint64_t)-38; /* -ENOSYS */
    (void)pc; (void)insn; (void)imm;
    rax_reg_read_u64(e, RAX_X86_REG_RAX, &nr);
    rax_reg_read_u64(e, RAX_X86_REG_RDI, &a0);
    rax_reg_read_u64(e, RAX_X86_REG_RSI, &a1);
    rax_reg_read_u64(e, RAX_X86_REG_RDX, &a2);
    if (nr == 1 && a0 == 1) { /* write(1, buf, len) */
        size_t n = (size_t)a2;
        if (n > sizeof p->output - p->output_len) n = sizeof p->output - p->output_len;
        /* A user-mode virtual read checks the guest's read permission. */
        if (rax_mem_read_virt(e, a1, p->output + p->output_len, n) == RAX_OK) {
            p->output_len += n;
            ret = n;
        } else {
            ret = (uint64_t)-14; /* -EFAULT */
        }
    } else if (nr == 60) { /* exit(code) */
        p->exit_code = (int)a0;
        p->exited = 1;
        rax_emu_stop(e);
        return;
    }
    rax_reg_write_u64(e, RAX_X86_REG_RAX, ret);
}

int main(void) {
    static const char msg[] = "hello from ring 3\n";
    /* mov edi,1 ; mov esi,DATA ; mov edx,len ; mov eax,1 ; syscall
     * mov edi,eax ; mov eax,60 ; syscall            (exit(bytes written)) */
    const unsigned char code[] = {
        0xBF, 0x01, 0x00, 0x00, 0x00,
        0xBE, 0x00, 0x10, 0x40, 0x00,
        0xBA, (unsigned char)(sizeof msg - 1), 0x00, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x89, 0xC7,
        0xB8, 0x3C, 0x00, 0x00, 0x00,
        0x0F, 0x05,
    };
    /* mov byte [DATA], 0 : a store into the read-only page. */
    const unsigned char store[] = {0xC6, 0x04, 0x25, 0x00, 0x10, 0x40, 0x00, 0x00};

    rax_engine_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.size = sizeof cfg;
    cfg.arch = RAX_ARCH_X86;
    cfg.mode = RAX_MODE_64 | RAX_MODE_USER;
    cfg.mem_base = CODE;
    cfg.mem_size = 0x1000;
    cfg.mem_perms = RAX_PROT_READ | RAX_PROT_EXEC;

    rax_engine *e = NULL;
    CHECK(rax_engine_open_config(&cfg, &e));
    CHECK(rax_mem_map(e, DATA, 0x1000, RAX_PROT_READ));
    /* Host (physical) writes ignore permissions: load the image. */
    CHECK(rax_mem_write(e, CODE, code, sizeof code));
    CHECK(rax_mem_write(e, DATA, msg, sizeof msg - 1));

    struct process proc;
    memset(&proc, 0, sizeof proc);
    CHECK(rax_hook_add_syscall(e, on_syscall, &proc, NULL));
    CHECK(rax_emu_start(e, CODE, RAX_NO_ADDR, 0, 0));

    rax_exit x;
    CHECK(rax_emu_last_exit(e, &x));
    printf("guest wrote: %.*s", (int)proc.output_len, proc.output);
    printf("guest exited with %d after %" PRIu64 " instructions\n", proc.exit_code, x.value);
    if (!proc.exited || proc.exit_code != (int)(sizeof msg - 1) ||
        proc.output_len != sizeof msg - 1 || memcmp(proc.output, msg, proc.output_len) != 0 ||
        x.reason != RAX_STOP_STOPPED || x.value != 8) {
        fprintf(stderr, "unexpected process result\n");
        rax_engine_close(e);
        return 1;
    }

    /* Code may not write the read-only page: the store faults, precisely. */
    CHECK(rax_mem_write(e, CODE, store, sizeof store));
    rax_status st = rax_emu_start(e, CODE, RAX_NO_ADDR, 0, 0);
    rax_fault_info fault;
    memset(&fault, 0, sizeof fault);
    fault.struct_size = sizeof fault;
    fault.version = RAX_FAULT_INFO_VERSION;
    CHECK(rax_emu_last_fault(e, &fault));
    printf("store: %s, fault kind=%u access=%u address=0x%" PRIx64 "\n", rax_strerror(st),
           fault.kind, fault.access, fault.address);
    rax_engine_close(e);
    if (st != RAX_ERR_FAULT || fault.kind != RAX_FAULT_PERMISSION ||
        fault.access != RAX_FAULT_ACCESS_WRITE || fault.address != DATA) {
        fprintf(stderr, "expected a write-permission fault at the data page\n");
        return 1;
    }
    return 0;
}
