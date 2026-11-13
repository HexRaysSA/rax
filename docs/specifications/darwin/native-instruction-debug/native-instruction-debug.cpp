#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <signal.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/ucontext.h>

extern "C" void native_debug_touch();
asm(".text\n.p2align 2\n.globl _native_debug_touch\n_native_debug_touch:\n nop\n ret\n");
static std::atomic<bool> ready{false};
static semaphore_t start_gate;
static thread_t worker_port;
static volatile sig_atomic_t traps, signal_number, signal_code, clear_result;
static volatile uint64_t fault_pc, fault_esr;
static void on_trap(int sig, siginfo_t *info, void *context) {
    auto *uc = static_cast<ucontext_t *>(context);
    signal_number = sig;
    signal_code = info->si_code;
    fault_pc = uc->uc_mcontext->__ss.__pc;
    fault_esr = uc->uc_mcontext->__es.__esr;
    traps = traps + 1;
    arm_debug_state64_t clear{};
    clear_result = thread_set_state(worker_port, ARM_DEBUG_STATE64,
        reinterpret_cast<thread_state_t>(&clear), ARM_DEBUG_STATE64_COUNT);
    if (clear_result != KERN_SUCCESS || traps > 1) _exit(92);
}
static void *worker(void *) {
    ready.store(true, std::memory_order_release);
    if (semaphore_wait(start_gate) != KERN_SUCCESS) _exit(93);
    native_debug_touch();
    return nullptr;
}
static void require(bool condition, const char *label, long value) {
    if (!condition) { std::fprintf(stderr, "%s: %ld\n", label, value); std::exit(91); }
}
int main() {
    struct sigaction action{};
    action.sa_sigaction = on_trap;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    require(sigaction(SIGTRAP, &action, nullptr) == 0, "sigaction", 0);
    struct utsname os{};
    require(uname(&os) == 0, "uname", 0);
    std::printf("{\"system\":\"%s\",\"release\":\"%s\",\"machine\":\"%s\"}\n", os.sysname, os.release, os.machine);
    for (unsigned mode = 0; mode < 3; ++mode) {
        traps = 0; signal_number = 0; signal_code = 0; clear_result = 0;
        fault_pc = 0; fault_esr = 0;
        ready.store(false);
        kern_return_t k = semaphore_create(mach_task_self(), &start_gate, SYNC_POLICY_FIFO, 0);
        require(k == KERN_SUCCESS, "semaphore_create", k);
        pthread_t thread{};
        int p = pthread_create(&thread, nullptr, worker, nullptr);
        require(p == 0, "pthread_create", p);
        while (!ready.load(std::memory_order_acquire)) usleep(1000);
        worker_port = pthread_mach_thread_np(thread);
        k = thread_suspend(worker_port);
        require(k == KERN_SUCCESS, "thread_suspend", k);
        arm_debug_state64_t state{};
        state.__bvr[0] = reinterpret_cast<uintptr_t>(&native_debug_touch) + (mode == 2 ? 8 : 0);
        state.__bcr[0] = mode == 0 ? 0x1e4 : 0x1e5;
        k = thread_set_state(worker_port, ARM_DEBUG_STATE64,
            reinterpret_cast<thread_state_t>(&state), ARM_DEBUG_STATE64_COUNT);
        require(k == KERN_SUCCESS, "thread_set_state", k);
        arm_debug_state64_t actual{};
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        k = thread_get_state(worker_port, ARM_DEBUG_STATE64,
            reinterpret_cast<thread_state_t>(&actual), &count);
        require(k == KERN_SUCCESS && count == ARM_DEBUG_STATE64_COUNT, "thread_get_state", k);
        require(semaphore_signal(start_gate) == KERN_SUCCESS, "semaphore_signal", 0);
        require(thread_resume(worker_port) == KERN_SUCCESS, "thread_resume", 0);
        require(pthread_join(thread, nullptr) == 0, "pthread_join", 0);
        require(semaphore_destroy(mach_task_self(), start_gate) == KERN_SUCCESS, "semaphore_destroy", 0);
        std::printf("{\"mode\":%u,\"bcr\":%llu,\"bvr\":%llu,\"traps\":%d,\"signal\":%d,\"code\":%d,\"pc\":%llu,\"esr\":%llu,\"clear_result\":%d}\n",mode,
            static_cast<unsigned long long>(actual.__bcr[0]), static_cast<unsigned long long>(actual.__bvr[0]), traps,signal_number,signal_code,
            static_cast<unsigned long long>(fault_pc),static_cast<unsigned long long>(fault_esr),clear_result);
        require(traps == (mode == 1 ? 1 : 0), "trap_count", traps);
        if (mode == 1) {
            require(signal_number == SIGTRAP && fault_pc == reinterpret_cast<uintptr_t>(&native_debug_touch), "fault_pc", fault_pc);
            require((fault_esr >> 26) == 0x30 && (fault_esr & 0x3f) == 0x22, "fault_esr", fault_esr);
        }
    }
    return 0;
}
