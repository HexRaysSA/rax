// Physical Linux x86-64 control: even masked-zero memory shifts need write access.
// This tests page permissions. It does not observe HVF EPT qualifications or
// external device bus cycles.
#if !defined(__linux__) || !defined(__x86_64__)
#error This control requires native Linux x86-64.
#endif
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "signal control needs lock-free addresses");
static _Atomic(uintptr_t) expected_address;

static void fault(int signal, siginfo_t *info, void *context)
{
    (void)context;
    _exit(signal == SIGSEGV && info->si_code == SEGV_ACCERR &&
          (uintptr_t)info->si_addr == atomic_load_explicit(&expected_address, memory_order_relaxed)
          ? 77 : 78);
}

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "shift access control: %s failed\n", operation);
        exit(1);
    }
}

#define OPERAND(MODRM) do { \
    switch (size) { \
    case 1: __asm__ volatile(".byte 0xd2," MODRM : : "D"(address), "c"(count) : "cc", "memory"); break; \
    case 2: __asm__ volatile(".byte 0x66,0xd3," MODRM : : "D"(address), "c"(count) : "cc", "memory"); break; \
    case 4: __asm__ volatile(".byte 0xd3," MODRM : : "D"(address), "c"(count) : "cc", "memory"); break; \
    case 8: __asm__ volatile(".byte 0x48,0xd3," MODRM : : "D"(address), "c"(count) : "cc", "memory"); break; \
    } \
} while (0)

static void execute(unsigned int group, unsigned int size, unsigned int count, void *address)
{
    switch (group) {
    case 0: OPERAND("0x07"); break;
    case 1: OPERAND("0x0f"); break;
    case 2: OPERAND("0x17"); break;
    case 3: OPERAND("0x1f"); break;
    case 4: OPERAND("0x27"); break;
    case 5: OPERAND("0x2f"); break;
    case 6: OPERAND("0x37"); break;
    case 7: OPERAND("0x3f"); break;
    }
}

int main(void)
{
    long page = sysconf(_SC_PAGESIZE);
    require(page > 128, "page size");
    unsigned char *memory = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "allocate page");
    memory[64] = 0xa5;
    atomic_store_explicit(&expected_address, (uintptr_t)(memory + 64), memory_order_relaxed);
    require(mprotect(memory, (size_t)page, PROT_READ) == 0, "read-only page");
    struct sigaction action = {.sa_sigaction = fault, .sa_flags = SA_SIGINFO};
    require(sigemptyset(&action.sa_mask) == 0, "signal mask");
    require(sigaction(SIGSEGV, &action, NULL) == 0, "fault observer");
    // An ordinary volatile load from the same address must succeed first.
    require(*(volatile unsigned char *)(memory + 64) == 0xa5, "read control");
    for (unsigned int group = 0; group < 8; ++group) {
        for (unsigned int size = 1; size <= 8; size *= 2) {
            for (unsigned int variant = 0; variant < 2; ++variant) {
                unsigned int count = variant ? (size == 8 ? 64 : 32) : 0;
                pid_t child = fork();
                require(child >= 0, "fork control");
                if (child == 0) {
                    execute(group, size, count, memory + 64);
                    _exit(0);
                }
                int status;
                require(waitpid(child, &status, 0) == child, "wait control");
                require(WIFEXITED(status), "controlled child exit");
                printf("{\"group\":%u,\"size\":%u,\"count\":%u,\"exit\":%d}\n",
                       group, size, count, WEXITSTATUS(status));
                require(WEXITSTATUS(status) == 77, "write-permission fault at operand");
            }
        }
    }
    require(munmap(memory, (size_t)page) == 0, "release page");
    return 0;
}
