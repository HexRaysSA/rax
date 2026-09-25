/*
 * Deeply Nested Function Calls
 *
 * Tests stack frame allocation and unwinding.
 * Exercises prologue/epilogue code generation.
 *
 * Features exercised:
 *   - Deep call stacks
 *   - Stack frame setup/teardown
 *   - Callee-saved register preservation
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

__attribute__((noinline))
int64_t level_10(int a, int b, int c, int d) {
    return (int64_t)a + b + c + d;
}

__attribute__((noinline))
int64_t level_9(int a, int b, int c, int d) {
    int local = a + b;
    return level_10(local, b + c, c + d, d + a) + local;
}

__attribute__((noinline))
int64_t level_8(int a, int b, int c, int d) {
    int local = a * 2;
    return level_9(local, b, c, d) + local;
}

__attribute__((noinline))
int64_t level_7(int a, int b, int c, int d) {
    int local = a + 1;
    return level_8(local, b + 1, c + 1, d + 1) + local;
}

__attribute__((noinline))
int64_t level_6(int a, int b, int c, int d) {
    int local1 = a, local2 = b;
    return level_7(local1, local2, c, d) + local1 + local2;
}

__attribute__((noinline))
int64_t level_5(int a, int b, int c, int d) {
    int arr[4] = {a, b, c, d};
    return level_6(arr[0], arr[1], arr[2], arr[3]) + arr[0];
}

__attribute__((noinline))
int64_t level_4(int a, int b, int c, int d) {
    int local = a ^ b ^ c ^ d;
    return level_5(a + local, b, c, d) + local;
}

__attribute__((noinline))
int64_t level_3(int a, int b, int c, int d) {
    return level_4(a, b, c, d) + level_4(b, c, d, a);
}

__attribute__((noinline))
int64_t level_2(int a, int b, int c, int d) {
    int sum = 0;
    for (int i = 0; i < 2; i++) {
        sum += (int)level_3(a + i, b, c, d);
    }
    return sum;
}

__attribute__((noinline))
int64_t level_1(int a, int b, int c, int d) {
    return level_2(a, b, c, d) + a + b + c + d;
}

/* Alternative deep nesting with more local variables */
__attribute__((noinline))
int64_t deep_with_locals(int depth, int val) {
    int local1 = val + 1;
    int local2 = val * 2;
    int local3 = val ^ 0xFF;
    int local4 = val & 0xF0;

    if (depth <= 0) {
        return local1 + local2 + local3 + local4;
    }

    int64_t result = deep_with_locals(depth - 1, local1);
    result += deep_with_locals(depth - 1, local2);

    return result + local3 + local4;
}

/* Mutual recursion */
__attribute__((noinline)) int64_t mutual_a(int depth, int val);
__attribute__((noinline)) int64_t mutual_b(int depth, int val);

int64_t mutual_a(int depth, int val) {
    if (depth <= 0) return val;
    return mutual_b(depth - 1, val + 1) + val;
}

int64_t mutual_b(int depth, int val) {
    if (depth <= 0) return val * 2;
    return mutual_a(depth - 1, val * 2) + val;
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 500; i++) { /* rax: was 10000 */
        result += level_1(i, i + 1, i + 2, i + 3);

        if (i % 100 == 0) {
            result += deep_with_locals(8, i);
        }

        result += mutual_a(10, i % 100);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
