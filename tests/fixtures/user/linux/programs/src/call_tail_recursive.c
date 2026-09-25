/*
 * Tail Recursive Functions
 *
 * Functions that can be optimized via tail call optimization (TCO).
 * When TCO is applied, no stack growth occurs.
 *
 * Features exercised:
 *   - Tail call optimization detection
 *   - Jump vs call instruction selection
 *   - Accumulator pattern
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Classic factorial with accumulator - tail recursive */
__attribute__((noinline))
int64_t factorial_tail(int n, int64_t acc) {
    if (n <= 1) return acc;
    return factorial_tail(n - 1, acc * n);
}

__attribute__((noinline))
int64_t factorial(int n) {
    return factorial_tail(n, 1);
}

/* Fibonacci with accumulators - tail recursive */
__attribute__((noinline))
int64_t fib_tail(int n, int64_t a, int64_t b) {
    if (n == 0) return a;
    if (n == 1) return b;
    return fib_tail(n - 1, b, a + b);
}

__attribute__((noinline))
int64_t fibonacci(int n) {
    return fib_tail(n, 0, 1);
}

/* Sum with accumulator */
__attribute__((noinline))
int64_t sum_tail(int n, int64_t acc) {
    if (n <= 0) return acc;
    return sum_tail(n - 1, acc + n);
}

/* GCD - naturally tail recursive */
__attribute__((noinline))
int64_t gcd(int64_t a, int64_t b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

/* List-like iteration with accumulator */
__attribute__((noinline))
int64_t iterate_tail(const int *arr, int len, int64_t acc) {
    if (len <= 0) return acc;
    return iterate_tail(arr + 1, len - 1, acc + arr[0]);
}

/* Power with accumulator */
__attribute__((noinline))
int64_t power_tail(int64_t base, int exp, int64_t acc) {
    if (exp == 0) return acc;
    if (exp % 2 == 0) {
        return power_tail(base * base, exp / 2, acc);
    }
    return power_tail(base, exp - 1, acc * base);
}

/* Even/odd mutual recursion - can be TCO'd */
__attribute__((noinline)) int is_even_tail(int n);
__attribute__((noinline)) int is_odd_tail(int n);

int is_even_tail(int n) {
    if (n == 0) return 1;
    return is_odd_tail(n - 1);
}

int is_odd_tail(int n) {
    if (n == 0) return 0;
    return is_even_tail(n - 1);
}

/* State machine as tail recursion */
typedef enum { STATE_A, STATE_B, STATE_C, STATE_DONE } State;

__attribute__((noinline))
int64_t state_machine(State state, int counter, int64_t acc) {
    switch (state) {
        case STATE_A:
            if (counter <= 0) return state_machine(STATE_DONE, 0, acc);
            return state_machine(STATE_B, counter, acc + 1);
        case STATE_B:
            return state_machine(STATE_C, counter, acc * 2);
        case STATE_C:
            return state_machine(STATE_A, counter - 1, acc + 3);
        case STATE_DONE:
        default:
            return acc;
    }
}

int main(void) {
    int64_t result = 0;
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    for (int i = 0; i < 300; i++) { /* rax: was 10000 */
        result += factorial(12);

        result += fibonacci(30);

        result += sum_tail(100, 0);

        result += gcd(i + 1000, (i % 100) + 1);

        result += iterate_tail(arr, 10, 0);

        result += power_tail(2, i % 20, 1);

        result += is_even_tail(i % 100);
        result += is_odd_tail(i % 100);

        if (i % 100 == 0) {
            result += state_machine(STATE_A, 10, 0);
        }
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
