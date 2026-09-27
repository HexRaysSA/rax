// The SDK's layouts of the structures signal frames carry, as `name value`
// lines (compared with the constants the Darwin personality uses).
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ucontext.h>
#include <mach/mach.h>

#define P(name, v) printf("%s %zu\n", name, (size_t)(v))

int main(void) {
    P("siginfo", sizeof(siginfo_t));
    P("ucontext", sizeof(ucontext_t));
    P("ucontext.uc_mcsize", offsetof(ucontext_t, uc_mcsize));
    P("ucontext.uc_mcontext", offsetof(ucontext_t, uc_mcontext));
#if defined(__arm64__)
    P("mcontext", sizeof(struct __darwin_mcontext64));
    P("mcontext.ss", offsetof(struct __darwin_mcontext64, __ss));
    P("mcontext.fs", offsetof(struct __darwin_mcontext64, __ns));
    P("thread_state", sizeof(arm_thread_state64_t));
    P("exception_state", sizeof(arm_exception_state64_t));
    P("float_state", sizeof(arm_neon_state64_t));
#else
    P("mcontext", sizeof(struct __darwin_mcontext_avx64));
    P("mcontext.ss", offsetof(struct __darwin_mcontext_avx64, __ss));
    P("mcontext.fs", offsetof(struct __darwin_mcontext_avx64, __fs));
    P("thread_state", sizeof(x86_thread_state64_t));
    P("exception_state", sizeof(x86_exception_state64_t));
    P("float_state", sizeof(x86_avx_state64_t));
#endif
    return 0;
}
