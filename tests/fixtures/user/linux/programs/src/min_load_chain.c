/*
 * Minimal Memory Load Chain
 *
 * Generates sequences dominated by memory load instructions.
 * Creates pointer-chasing pattern that forces sequential loads.
 *
 * Expected dominant instructions by architecture:
 *   x86:    mov (memory operand), movzx, movsx
 *   ARM:    ldr, ldrb, ldrh
 *   RISC-V: lw, ld, lb, lh
 *   MIPS:   lw, ld, lb, lh
 *   PPC:    lwz, ld, lbz, lhz
 */

#include <stdio.h> /* rax: print the result so that runs can be compared */

#define ARRAY_SIZE 1024

volatile int sink;

/* Linked list node for pointer chasing */
struct node {
    struct node *next;
    int value;
};

static struct node nodes[ARRAY_SIZE];
static int data[ARRAY_SIZE];

int main(void) {
    /* Initialize data array */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        data[i] = i * 7 + 3;
    }

    /* Initialize linked list with pseudo-random order */
    for (int i = 0; i < ARRAY_SIZE; i++) {
        int next_idx = (i * 17 + 31) % ARRAY_SIZE;
        nodes[i].next = &nodes[next_idx];
        nodes[i].value = i;
    }

    int sum = 0;
    struct node *ptr = &nodes[0];

    /* Pointer chasing - forces sequential loads */
    for (int i = 0; i < 8000; i++) { /* rax: was 100000 */
        /* Load from linked list (pointer chase) */
        sum += ptr->value;
        ptr = ptr->next;

        sum += ptr->value;
        ptr = ptr->next;

        sum += ptr->value;
        ptr = ptr->next;

        sum += ptr->value;
        ptr = ptr->next;

        /* Array loads with varying offsets */
        int idx = (i * 13) % ARRAY_SIZE;
        sum += data[idx];
        sum += data[(idx + 1) % ARRAY_SIZE];
        sum += data[(idx + 2) % ARRAY_SIZE];
        sum += data[(idx + 3) % ARRAY_SIZE];
    }

    sink = sum;
    printf("sink=%d\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
