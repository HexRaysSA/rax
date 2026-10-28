/* Remote Mach VM transfers larger than one internal message frame. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

enum { SIZE = (1 << 20) + 4096 };
static volatile unsigned char region[SIZE];
static unsigned char replacement[SIZE];
static unsigned char overwritten[SIZE];

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        region[0] = 0x12; region[SIZE - 1] = 0x34;
        uint64_t addr = (uintptr_t)region;
        char byte;
        if (write(ready[1], &addr, sizeof(addr)) != sizeof(addr)) _exit(90);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        if (n != 1) _exit(91);
        printf("child=%02x%02x\n", region[0], region[SIZE - 1]);
        _exit(region[0] == 0xab && region[SIZE - 1] == 0xcd ? 42 : 92);
    }
    close(ready[1]); close(gate[0]);
    uint64_t addr;
    int status;
    if (read(ready[0], &addr, sizeof(addr)) != sizeof(addr) || ptrace(PT_ATTACH, child, 0, 0) ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) goto fail;
    vm_offset_t data = 0;
    mach_msg_type_number_t count = 0;
    kern_return_t r = mach_vm_read(task, addr, SIZE, &data, &count);
    unsigned char *bytes = (unsigned char *)(uintptr_t)data;
    int first = count == SIZE ? bytes[0] : -1;
    int last = count == SIZE ? bytes[SIZE - 1] : -1;
    if (data) vm_deallocate(mach_task_self(), data, count);
    mach_vm_size_t copied = 0;
    kern_return_t o = mach_vm_read_overwrite(task, addr, SIZE, (mach_vm_address_t)overwritten, &copied);
    replacement[0] = 0xab; replacement[SIZE - 1] = 0xcd;
    kern_return_t w = mach_vm_write(task, addr, (vm_offset_t)replacement, SIZE);
    printf("read=%d count=%u edges=%02x%02x overwrite=%d size=%llu edges=%02x%02x write=%d\n",
           r, count, first, last, o, (unsigned long long)copied, overwritten[0], overwritten[SIZE - 1], w);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1 ||
        waitpid(child, &status, 0) != child) goto fail;
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return r || o || w || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    puts("failed");
    return 1;
}
