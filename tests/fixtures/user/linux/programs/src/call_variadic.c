/*
 * Variadic Functions
 *
 * Functions with variable number of arguments.
 * Tests va_list implementation across architectures.
 *
 * Features exercised:
 *   - va_start, va_arg, va_end
 *   - Type promotion in variadic calls
 *   - va_list passing and copying
 */

#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

__attribute__((noinline))
int sum_ints(int count, ...) {
    va_list args;
    va_start(args, count);

    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(args, int);
    }

    va_end(args);
    return sum;
}

__attribute__((noinline))
double sum_doubles(int count, ...) {
    va_list args;
    va_start(args, count);

    double sum = 0.0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(args, double);
    }

    va_end(args);
    return sum;
}

__attribute__((noinline))
int64_t sum_mixed(const char *format, ...) {
    va_list args;
    va_start(args, format);

    int64_t sum = 0;
    while (*format) {
        switch (*format) {
            case 'i':
                sum += va_arg(args, int);
                break;
            case 'd':
                sum += (int64_t)va_arg(args, double);
                break;
            case 'l':
                sum += va_arg(args, int64_t);
                break;
            case 'p':
                sum += (int64_t)(intptr_t)va_arg(args, void *);
                break;
        }
        format++;
    }

    va_end(args);
    return sum;
}

/* va_list as parameter */
__attribute__((noinline))
int sum_from_va_list(int count, va_list args) {
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(args, int);
    }
    return sum;
}

__attribute__((noinline))
int wrapper_sum(int count, ...) {
    va_list args;
    va_start(args, count);
    int result = sum_from_va_list(count, args);
    va_end(args);
    return result;
}

/* va_copy */
__attribute__((noinline))
int double_sum(int count, ...) {
    va_list args, args_copy;
    va_start(args, count);
    va_copy(args_copy, args);

    int sum1 = 0, sum2 = 0;
    for (int i = 0; i < count; i++) {
        sum1 += va_arg(args, int);
    }
    for (int i = 0; i < count; i++) {
        sum2 += va_arg(args_copy, int);
    }

    va_end(args);
    va_end(args_copy);
    return sum1 + sum2;
}

/* Variadic with struct return */
typedef struct { int a, b; } Pair;

__attribute__((noinline))
Pair min_max(int count, ...) {
    va_list args;
    va_start(args, count);

    int min_val = va_arg(args, int);
    int max_val = min_val;

    for (int i = 1; i < count; i++) {
        int v = va_arg(args, int);
        if (v < min_val) min_val = v;
        if (v > max_val) max_val = v;
    }

    va_end(args);
    Pair p = {min_val, max_val};
    return p;
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 300; i++) { /* rax: was 50000 */
        result += sum_ints(4, i, i+1, i+2, i+3);
        result += sum_ints(8, i, i+1, i+2, i+3, i+4, i+5, i+6, i+7);

        double d = (double)i;
        result += (int64_t)sum_doubles(4, d, d+0.1, d+0.2, d+0.3);

        result += sum_mixed("iidl", i, i+1, d, (int64_t)i*1000);

        result += wrapper_sum(6, i, i+1, i+2, i+3, i+4, i+5);

        result += double_sum(4, i, i+1, i+2, i+3);

        Pair p = min_max(5, i, i+10, i-5, i+3, i+7);
        result += p.a + p.b;
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
