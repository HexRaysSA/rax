/* Exec invalidates old task/thread operations; a traced parent may get the new task. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
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

int main(int argc, char **argv) {
    if (argc > 1) _exit(42);
    setbuf(stdout, NULL);
    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        char byte = 'r';
        if (write(ready[1], &byte, 1) != 1) _exit(90);
        ssize_t n;
        do { n = read(release[0], &byte, 1); } while (n < 0 && errno == EINTR);
        if (n != 1) _exit(91);
        execl(argv[0], argv[0], "after", NULL);
        _exit(92);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, child, 0, 0) != 0) goto fail;
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) goto fail;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS || count == 0) goto fail;
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0 || write(release[1], "x", 1) != 1) goto fail;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    int old_pid = -1;
    kern_return_t old_task_result = pid_for_task(task, &old_pid);
#if defined(__arm64__)
    arm_thread_state64_t old_state;
    mach_msg_type_number_t old_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t old_thread_result = thread_get_state(threads[0], ARM_THREAD_STATE64,
                                                       (thread_state_t)&old_state, &old_count);
#else
    x86_thread_state64_t old_state;
    mach_msg_type_number_t old_count = x86_THREAD_STATE64_COUNT;
    kern_return_t old_thread_result = thread_get_state(threads[0], x86_THREAD_STATE64,
                                                       (thread_state_t)&old_state, &old_count);
#endif
    printf("old-task-unusable=%d old-thread-unusable=%d\n",
           old_task_result != KERN_SUCCESS, old_thread_result != KERN_SUCCESS);
    if (old_task_result == KERN_SUCCESS || old_thread_result == KERN_SUCCESS) goto fail;
    mach_port_t fresh = MACH_PORT_NULL;
    kern_return_t fresh_result = task_for_pid(mach_task_self(), child, &fresh);
    thread_act_array_t newer = NULL;
    mach_msg_type_number_t newer_count = 0;
    kern_return_t list_result = fresh_result == KERN_SUCCESS ? task_threads(fresh, &newer, &newer_count) : KERN_FAILURE;
    printf("fresh=%d threads=%d nonempty=%d\n", fresh_result, list_result, newer_count != 0);
    if (fresh_result != KERN_SUCCESS || list_result != KERN_SUCCESS || newer_count == 0) goto fail;
    for (mach_msg_type_number_t i = 0; i < count; i++) mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    for (mach_msg_type_number_t i = 0; i < newer_count; i++) mach_port_deallocate(mach_task_self(), newer[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)newer, newer_count * sizeof(*newer));
    mach_port_deallocate(mach_task_self(), task);
    mach_port_deallocate(mach_task_self(), fresh);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) != 0) goto fail;
    if (waitpid(child, &status, 0) != child) goto fail;
    tracee = 0;
    alarm(0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    puts("failed");
    return 1;
}
