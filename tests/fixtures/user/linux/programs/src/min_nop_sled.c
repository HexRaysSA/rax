/*
 * Minimal NOP Sled
 *
 * Generates sequences with NOP instructions and alignment padding.
 * NOPs are often used for alignment and have distinctive encodings.
 *
 * Expected dominant instructions by architecture:
 *   x86:    nop (0x90), multi-byte nops (66 90, 0f 1f xx)
 *   ARM:    nop (mov r0, r0 or dedicated nop)
 *   RISC-V: nop (addi x0, x0, 0)
 *   MIPS:   nop (sll $0, $0, 0)
 *   PPC:    nop (ori 0,0,0)
 *
 * Note: We use inline asm for actual NOPs, plus compiler intrinsics
 * where available. Falls back to volatile empty asm otherwise.
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

volatile int sink;

/* Generate NOPs using inline assembly */
#if defined(__GNUC__) || defined(__clang__)

#if defined(__x86_64__) || defined(__i386__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__aarch64__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__arm__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__riscv)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__mips__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__powerpc__) || defined(__ppc__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__sparc__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#elif defined(__s390__) || defined(__s390x__)
#define NOP_1() __asm__ volatile("nop")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#else
/* Generic fallback - empty volatile asm acts as compiler barrier */
#define NOP_1() __asm__ volatile("")
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#endif

#else
/* Non-GCC/Clang fallback */
#define NOP_1() ((void)0)
#define NOP_4() NOP_1(); NOP_1(); NOP_1(); NOP_1()
#define NOP_16() NOP_4(); NOP_4(); NOP_4(); NOP_4()
#endif

#define NOP_64() NOP_16(); NOP_16(); NOP_16(); NOP_16()
#define NOP_256() NOP_64(); NOP_64(); NOP_64(); NOP_64()

int main(void) {
    int counter = 0;

    for (int i = 0; i < 1000; i++) { /* rax: was 10000 */
        /* NOP sleds of varying lengths */
        NOP_16();
        counter++;

        NOP_64();
        counter++;

        NOP_256();
        counter++;

        NOP_16();
        NOP_16();
        counter++;

        /* Interleaved NOPs and operations */
        NOP_4();
        counter += 2;
        NOP_4();
        counter += 3;
        NOP_4();
        counter += 5;
        NOP_4();
    }

    sink = counter;
    printf("sink=%d\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
