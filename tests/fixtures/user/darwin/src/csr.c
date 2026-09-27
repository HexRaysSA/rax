// csrctl and crossarch_trap: the System Integrity Protection configuration
// (the machine's), checks of masks against it, their argument checks,
// and the cross-architecture trap, which offers a process nothing.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define SYS_crossarch_trap 38
#define SYS_csrctl 483
#define CSR_SYSCALL_CHECK 0
#define CSR_SYSCALL_GET_ACTIVE_CONFIG 1
#define CSR_ALLOW_UNTRUSTED_KEXTS (1 << 0)
#define CSR_ALLOW_KERNEL_DEBUGGER (1 << 3)
#define CSR_ALLOW_APPLE_INTERNAL (1 << 4)
#define CSR_ALLOW_DEVICE_CONFIGURATION (1 << 7)

static void show(const char *what, int r) { printf("%s: %d errno=%d\n", what, r, r ? errno : 0); }

static int check(uint32_t mask) { return syscall(SYS_csrctl, CSR_SYSCALL_CHECK, &mask, sizeof mask); }

int main(void) {
    uint32_t config = 0xdeadbeef;
    int r = syscall(SYS_csrctl, CSR_SYSCALL_GET_ACTIVE_CONFIG, &config, sizeof config);
    show("get", r);
    printf("config valid bits only=%d\n", (config & ~0x1fffu) == 0);
    uint64_t wide = 0;
    show("get 8 bytes", syscall(SYS_csrctl, CSR_SYSCALL_GET_ACTIVE_CONFIG, &wide, sizeof wide));
    show("get null", syscall(SYS_csrctl, CSR_SYSCALL_GET_ACTIVE_CONFIG, NULL, 4));
    show("get fault", syscall(SYS_csrctl, CSR_SYSCALL_GET_ACTIVE_CONFIG, (void *)8, 4));
    show("unknown op", syscall(SYS_csrctl, 2, &config, sizeof config));
    show("check fault", syscall(SYS_csrctl, CSR_SYSCALL_CHECK, (void *)8, 4));
    show("check nothing", check(0));
    // Every allowed flag passes; a debugger is allowed whenever SIP is off.
    show("check config", check(config & ~CSR_ALLOW_DEVICE_CONFIGURATION));
    int off = (config & (CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_APPLE_INTERNAL)) != 0;
    printf("debugger allowed as expected=%d\n",
           (check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) == (off || (config & CSR_ALLOW_KERNEL_DEBUGGER)));
    printf("unset flag refused=%d\n", (config & (1 << 12)) || check(1 << 12) == -1);

    show("crossarch rosetta", syscall(SYS_crossarch_trap, 0));
    show("crossarch unknown", syscall(SYS_crossarch_trap, 1));
    return 0;
}
