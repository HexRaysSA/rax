/* Independently launched target and tracer; no guest fork creates the link. */
#include <errno.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_attributes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

extern int csops(pid_t, unsigned int, void *, size_t);

static int mach_checks(pid_t pid, int read_state) {
    task_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), pid, &task);
    printf("task=%d live=%d\n", result, task != MACH_PORT_NULL);
    if (result != KERN_SUCCESS || task == MACH_PORT_NULL) return 10;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    result = task_threads(task, &threads, &count);
    printf("threads=%d nonempty=%d\n", result, count != 0);
    if (result != KERN_SUCCESS || count == 0) return 11;
    if (read_state) {
#if defined(__arm64__)
    arm_thread_state64_t state;
    const thread_state_flavor_t flavor = ARM_THREAD_STATE64;
    const mach_msg_type_number_t expected_count = ARM_THREAD_STATE64_COUNT;
#else
    x86_thread_state64_t state;
    const thread_state_flavor_t flavor = x86_THREAD_STATE64;
    const mach_msg_type_number_t expected_count = x86_THREAD_STATE64_COUNT;
#endif
    /* Rosetta can return host helper threads without x86 architectural state. */
    result = KERN_FAILURE;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        mach_msg_type_number_t state_count = expected_count;
        result = thread_get_state(threads[i], flavor, (thread_state_t)&state, &state_count);
        if (result == KERN_SUCCESS) break;
    }
    printf("state=%d\n", result);
    if (result != KERN_SUCCESS) return 12;
    }
    result = task_suspend(task);
    printf("suspend=%d\n", result);
    if (result != KERN_SUCCESS) return 13;
    result = task_resume(task);
    printf("resume=%d\n", result);
    if (result != KERN_SUCCESS) return 14;
    task_suspension_token_t token = MACH_PORT_NULL;
    result = task_suspend2(task, &token);
    printf("suspend2=%d live=%d\n", result, token != MACH_PORT_NULL);
    if (result != KERN_SUCCESS || token == MACH_PORT_NULL) return 15;
    result = task_resume2(token);
    printf("resume2=%d\n", result);
    if (result != KERN_SUCCESS) return 16;
    mach_vm_address_t address = 0;
    result = mach_vm_allocate(task, &address, 0x4000, VM_FLAGS_ANYWHERE);
    printf("allocate=%d\n", result);
    if (result != KERN_SUCCESS) return 17;
    unsigned char source[5] = { 0x31, 0, 0x82, 0xff, 0x7e }, copy[5] = {0};
    result = mach_vm_write(task, address, (vm_offset_t)source, sizeof(source));
    mach_vm_size_t copied = 0;
    if (result == KERN_SUCCESS)
        result = mach_vm_read_overwrite(task, address, sizeof(copy),
                                        (mach_vm_address_t)copy, &copied);
    printf("memory=%d equal=%d\n", result,
           copied == sizeof(copy) && memcmp(source, copy, sizeof(copy)) == 0);
    if (result != KERN_SUCCESS || copied != sizeof(copy) || memcmp(source, copy, sizeof(copy))) return 18;
    vm_machine_attribute_val_t cache = MATTR_VAL_CACHE_FLUSH;
    result = mach_vm_machine_attribute(task, address, sizeof(source), MATTR_CACHE, &cache);
    printf("cache=%d value=%d\n", result, cache);
    if (result != KERN_SUCCESS || cache != MATTR_VAL_CACHE_FLUSH) return 25;
    result = mach_vm_deallocate(task, address, 0x4000);
    printf("deallocate=%d\n", result);
    if (result != KERN_SUCCESS) return 19;
    for (mach_msg_type_number_t i = 0; i < count; ++i)
        mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return 0;
}

static volatile sig_atomic_t finished;
static volatile sig_atomic_t continued;
static void catch_continue(int signal_number) { (void)signal_number;continued=1; }
static void finish(int signal_number) { (void)signal_number; finished = 1; }

static int exited(pid_t pid) {
    int status = 0;
    pid_t waited = waitpid(pid, &status, 0);
    printf("exited=%d status=%d\n", waited == pid && WIFEXITED(status),
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 42;
}

int main(int argc, char **argv) {
    if (argc == 2 && strncmp(argv[1], "target", 6) == 0) {
        pid_t original_parent = getppid();
        if (signal(SIGUSR1, finish) == SIG_ERR) return 82;
        if ((strstr(argv[1],"catch") || strcmp(argv[1],"target-native-continue")==0) && signal(SIGCONT,catch_continue)==SIG_ERR) return 84;
        puts("ready");
        fflush(stdout);
        if (strncmp(argv[1],"target-stopped",14)==0 || strcmp(argv[1],"target-native-continue")==0) raise(SIGSTOP);
        if (strcmp(argv[1],"target-native-continue")==0) return continued ? 42 : 85;
        while (!finished) {
            if (strstr(argv[1],"spin")) __asm__ volatile("" ::: "memory");
            else pause();
        }
        if (strstr(argv[1],"catch") && continued) return 85;
        int restored = strcmp(argv[1], "target-detach") == 0;
        return (getppid() == original_parent) == restored ? 42 : 83;
    }
    if (argc != 3) return 80;
    const char *mode = argv[1];
    int mach = strncmp(mode, "mach", 4) == 0;
    int pre = mach && strstr(mode, "pre") != NULL;
    int read_state = strstr(mode, "no-state") == NULL;
    pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
    if (pid < 2) return 81;
    alarm(30);
    if (pre) {
        int checked = mach_checks(pid, read_state);
        fflush(stdout);
        if (checked != 0) return checked;
    }
    errno = 0;
    int result = ptrace(PT_ATTACH, pid, 0, 0);
    printf("attach=%d errno=%d\n", result, errno);
    fflush(stdout);
    if (result != 0) return 1;
    int status = 0;
    pid_t waited = waitpid(pid, &status, WUNTRACED);
    printf("stop=%d signal=%d\n", waited == pid && WIFSTOPPED(status),
           WIFSTOPPED(status) ? WSTOPSIG(status) : 0);
    fflush(stdout);
    if (waited != pid || !WIFSTOPPED(status)) return 2;
    if (strcmp(mode, "codesign") == 0) {
        uint32_t flags = 0;
        errno = 0;
        int query = csops(pid, 0, &flags, sizeof(flags));
        printf("codesign=%d errno=%d flags=%08x\n", query, errno, flags);
        if (query != 0) return 24;
    }
    if (mach && !pre) {
        int checked = mach_checks(pid, read_state);
        fflush(stdout);
        if (checked != 0) return checked;
    }

    if (strcmp(mode, "detach") == 0) {
        errno = 0;
        result = ptrace(PT_DETACH, pid, (caddr_t)1, 0);
        printf("detach=%d errno=%d\n", result, errno);
        if (result != 0) return 20;
        errno = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        printf("nochild=%d\n", waited == -1 && errno == ECHILD);
        return waited != -1 || errno != ECHILD;
    }
    if (strcmp(mode, "exit") == 0 || strcmp(mode, "stopped") == 0 || strcmp(mode, "stopped-catch") == 0 || strcmp(mode,"external-stopped")==0 || strcmp(mode,"external-stopped-catch")==0 || strcmp(mode, "waitid") == 0 || strcmp(mode, "tracer-exit") == 0) {
        if (strcmp(mode, "waitid") == 0) {
            pid_t waited = waitpid(pid, &status, WNOHANG);
            printf("nohang=%d\n", waited == 0);
            if (waited != 0) return 21;
        }
        errno = 0;
        int signal_number = strcmp(mode, "tracer-exit") == 0 ? 0 : SIGUSR1;
        result = ptrace(PT_CONTINUE, pid, (caddr_t)1, signal_number);
        printf("continue=%d errno=%d\n", result, errno);
        if (result != 0) return 22;
        if (strcmp(mode, "tracer-exit") == 0) return 0;
        if (strcmp(mode, "waitid") == 0) {
            for (int i = 0; i < 2; ++i) {
                siginfo_t info = {0};
                result = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT);
                printf("peek=%d pid=%d status=%d\n", result, info.si_pid == pid, info.si_status);
                if (result || info.si_pid != pid || info.si_status != 42) return 23;
            }
        }
        return exited(pid);
    }
    errno = 0;
    result = ptrace(PT_KILL, pid, (caddr_t)1, 0);
    printf("kill=%d errno=%d\n", result, errno);
    fflush(stdout);
    if (result != 0) return 3;
    waited = waitpid(pid, &status, 0);
    printf("term=%d signal=%d\n", waited == pid && WIFSIGNALED(status),
           WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return waited != pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL;
}
