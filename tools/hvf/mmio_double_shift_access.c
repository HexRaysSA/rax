// Physical Linux x86-64 control: SHLD/SHRD write permission, including masked-zero and undefined word counts.
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

#define OP(IMMEDIATE, COUNT) do { \
    switch (size) { \
    case 2: __asm__ volatile(".byte 0x66,0x0f," IMMEDIATE ",0x07" COUNT : : "D"(address), "a"(source), "c"(count) : "cc", "memory"); break; \
    case 4: __asm__ volatile(".byte 0x0f," IMMEDIATE ",0x07" COUNT : : "D"(address), "a"(source), "c"(count) : "cc", "memory"); break; \
    case 8: __asm__ volatile(".byte 0x48,0x0f," IMMEDIATE ",0x07" COUNT : : "D"(address), "a"(source), "c"(count) : "cc", "memory"); break; \
    } \
} while (0)

#define DIRECTION(IMM, CL) do { \
    if (cl) { OP(CL, ""); } \
    else switch (count) { \
    case 0: OP(IMM, ",0"); break; \
    case 17: OP(IMM, ",17"); break; \
    case 31: OP(IMM, ",31"); break; \
    case 32: OP(IMM, ",32"); break; \
    case 64: OP(IMM, ",64"); break; \
    } \
} while (0)

static void execute(unsigned int right, unsigned int size, unsigned int cl,
                    unsigned int count, void *address)
{
    uint64_t source = UINT64_C(0x39c65aa5f00fc33c);
    if (right) { DIRECTION("0xac", "0xad"); }
    else { DIRECTION("0xa4", "0xa5"); }
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
    unsigned int checked = 0;
    for (unsigned int right = 0; right < 2; ++right) {
        for (unsigned int size = 2; size <= 8; size *= 2) {
            for (unsigned int cl = 0; cl < 2; ++cl) {
                for (unsigned int variant = 0; variant < (size == 2 ? 4u : 2u); ++variant) {
                    unsigned int count = variant == 0 ? 0 : variant == 1 ? (size == 8 ? 64 : 32)
                        : variant == 2 ? 17 : 31;
                    pid_t child = fork();
                    require(child >= 0, "fork control");
                    if (child == 0) {
                        execute(right, size, cl, count, memory + 64);
                        _exit(0);
                    }
                    int status;
                    require(waitpid(child, &status, 0) == child, "wait control");
                    require(WIFEXITED(status), "controlled child exit");
                    printf("{\"right\":%u,\"size\":%u,\"cl\":%u,\"count\":%u,\"exit\":%d}\n",
                           right, size, cl, count, WEXITSTATUS(status));
                    require(WEXITSTATUS(status) == 77, "write-permission fault at operand");
                    ++checked;
                }
            }
        }
    }
    require(checked == 32, "nonempty complete partition");
    require(munmap(memory, (size_t)page) == 0, "release page");
    return 0;
}
