// arm64e pointer signing, kernel-exported state, signals, and pthread callbacks.
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <ptrauth.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "This fixture must be compiled for the arm64e pointer-authentication ABI"
#endif

static volatile sig_atomic_t caught;

static void handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    // These accessors authenticate the kernel's opaque state pointers.
    uintptr_t pc = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    uintptr_t sp = arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
    if (sig == SIGUSR1 && info != NULL && pc != 0 && sp != 0) {
        caught = 1;
    }
}

static void *worker(void *argument) {
    return argument;
}

int main(void) {
    uintptr_t data = 0x12340;
    unsigned changed = 0;
    for (uintptr_t modifier = 0; modifier < 32; ++modifier) {
        void *signed_pointer = ptrauth_sign_unauthenticated((void *)data,
            ptrauth_key_process_independent_data, modifier);
        void *plain = ptrauth_auth_data(signed_pointer,
            ptrauth_key_process_independent_data, modifier);
        if ((uintptr_t)plain != data) {
            return 1;
        }
        changed |= (uintptr_t)signed_pointer != data;
    }
    if (!changed) {
        return 2;
    }
    void *inherited = ptrauth_sign_unauthenticated((void *)data,
        ptrauth_key_process_independent_data, 0x7799);
    pid_t child = fork();
    if (child < 0) {
        return 5;
    }
    if (child == 0) {
        void *plain = ptrauth_auth_data(inherited,
            ptrauth_key_process_independent_data, 0x7799);
        _exit((uintptr_t)plain == data ? 0 : 6);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 7;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || raise(SIGUSR1) != 0 || caught != 1) {
        return 3;
    }
    pthread_t thread;
    void *result = NULL;
    if (pthread_create(&thread, NULL, worker, (void *)0x55) != 0 ||
        pthread_join(thread, &result) != 0 || result != (void *)0x55) {
        return 4;
    }
    printf("pauth=32 signal=%d thread=85 fork=1\n", (int)caught);
    return 0;
}
