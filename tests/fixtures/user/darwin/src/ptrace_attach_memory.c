/* Read and write a stopped tracee through its task control right. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile uint64_t word = UINT64_C(0x1122334455667788);

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        uint64_t address = (uintptr_t)&word;
        char byte;
        if (write(ready[1], &address, sizeof(address)) != sizeof(address)) _exit(90);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        if (n != 1) _exit(91);
        printf("child=%016llx\n", (unsigned long long)word);
        _exit(word == UINT64_C(0xaabbccddeeff0011) ? 42 : 92);
    }
    close(ready[1]); close(gate[0]);
    uint64_t address;
    int status;
    if (read(ready[0], &address, sizeof(address)) != sizeof(address) ||
        ptrace(PT_ATTACH, child, 0, 0) != 0 ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) goto fail;
    vm_offset_t data = 0;
    mach_msg_type_number_t count = 0;
    kern_return_t read_result = mach_vm_read(task, address, sizeof(word), &data, &count);
    uint64_t copied = count == sizeof(word) ? *(uint64_t *)(uintptr_t)data : 0;
    if (data) vm_deallocate(mach_task_self(), data, count);
    uint64_t over = 0;
    mach_vm_size_t out_size = 0;
    kern_return_t overwrite_result = mach_vm_read_overwrite(task, address, sizeof(over),
                                                            (mach_vm_address_t)&over, &out_size);
    uint64_t replacement = UINT64_C(0xaabbccddeeff0011);
    kern_return_t write_result = mach_vm_write(task, address, (vm_offset_t)&replacement,
                                               sizeof(replacement));
    vm_offset_t invalid_data = 0;
    mach_msg_type_number_t invalid_count = 0;
    kern_return_t invalid_read = mach_vm_read(task, 0, sizeof(word), &invalid_data, &invalid_count);
    mach_vm_size_t invalid_size = 0;
    kern_return_t invalid_dest = mach_vm_read_overwrite(task, address, sizeof(word), 0, &invalid_size);
    kern_return_t invalid_write = mach_vm_write(task, 0, (vm_offset_t)&replacement, sizeof(replacement));
    kern_return_t wrap_read = mach_vm_read(task, UINT64_MAX - 7, 4, &invalid_data, &invalid_count);
    kern_return_t wrap_write = mach_vm_write(task, UINT64_MAX - 3, (vm_offset_t)&replacement, sizeof(replacement));
    printf("read=%d count=%u value=%016llx overwrite=%d size=%llu value=%016llx write=%d\n",
           read_result, count, (unsigned long long)copied, overwrite_result,
           (unsigned long long)out_size, (unsigned long long)over, write_result);
    printf("invalid-read=%d invalid-dest=%d invalid-write=%d\n", invalid_read, invalid_dest, invalid_write);
    printf("wrap-read=%d wrap-write=%d\n", wrap_read, wrap_write);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0 || write(gate[1], "x", 1) != 1 ||
        waitpid(child, &status, 0) != child) goto fail;
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return read_result || overwrite_result || write_result || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    puts("failed");
    return 1;
}
