/* Read and write a stopped tracee's callee-saved register through Mach. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

int main(void) {
    setbuf(stdout, NULL);
    int ready[2], release[2], result[2];
    if (pipe(ready) || pipe(release) || pipe(result)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]); close(result[0]);
#if defined(__aarch64__)
        register uint64_t marker __asm__("x19") = 0x1234;
#elif defined(__x86_64__)
        register uint64_t marker __asm__("r12") = 0x1234;
#else
#error unsupported architecture
#endif
        __asm__ volatile("" : "+r"(marker));
        char byte = 'r';
        if (write(ready[1], &byte, 1) != 1) _exit(90);
        ssize_t n;
        do { n = read(release[0], &byte, 1); } while (n < 0 && errno == EINTR);
        __asm__ volatile("" : "+r"(marker));
        uint64_t observed = marker;
        if (n != 1 || write(result[1], &observed, sizeof observed) != sizeof observed) _exit(91);
        _exit(42);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(release[0]); close(result[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, child, 0, 0) != 0) goto fail;
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t task_result = task_for_pid(mach_task_self(), child, &task);
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t list_result = task_result == KERN_SUCCESS ? task_threads(task, &threads, &count) : KERN_FAILURE;
    if (task_result != KERN_SUCCESS || list_result != KERN_SUCCESS || count == 0) goto fail;
    const uint64_t replacement = UINT64_C(0x1122334455667788);
#if defined(__aarch64__)
    arm_thread_state64_t state;
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t get_result = KERN_FAILURE;
    mach_msg_type_number_t selected = count;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        state_count = ARM_THREAD_STATE64_COUNT;
        get_result = thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&state, &state_count);
        if (get_result == KERN_SUCCESS && state.__x[19] == 0x1234) { selected = i; break; }
    }
    if (selected == count) goto fail;
    if (get_result == KERN_SUCCESS) state.__x[19] = replacement;
    kern_return_t set_result = get_result == KERN_SUCCESS ? thread_set_state(threads[selected], ARM_THREAD_STATE64, (thread_state_t)&state, state_count) : KERN_FAILURE;
#elif defined(__x86_64__)
    x86_thread_state64_t state;
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    kern_return_t get_result = KERN_FAILURE;
    mach_msg_type_number_t selected = count;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        state_count = x86_THREAD_STATE64_COUNT;
        get_result = thread_get_state(threads[i], x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
        if (get_result == KERN_SUCCESS && state.__r12 == 0x1234) { selected = i; break; }
    }
    if (selected == count) goto fail;
    if (get_result == KERN_SUCCESS) state.__r12 = replacement;
    kern_return_t set_result = get_result == KERN_SUCCESS ? thread_set_state(threads[selected], x86_THREAD_STATE64, (thread_state_t)&state, state_count) : KERN_FAILURE;
#endif
    printf("get=%d set=%d\n", get_result, set_result);
    for (mach_msg_type_number_t i = 0; i < count; i++) mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    mach_port_deallocate(mach_task_self(), task);
    if (get_result != KERN_SUCCESS || set_result != KERN_SUCCESS || ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) goto fail;
    if (write(release[1], "x", 1) != 1) goto fail;
    uint64_t observed = 0;
    if (read(result[0], &observed, sizeof observed) != sizeof observed) goto fail;
    if (waitpid(child, &status, 0) != child) goto fail;
    tracee = 0;
    alarm(0);
    printf("register=%016llx exit=%d\n", (unsigned long long)observed, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return observed != replacement || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    puts("failed");
    return 1;
}
