/*
 * C++ Lambda Expressions and Captures
 *
 * Tests lambda closure generation and capture modes.
 * Exercises closure objects and their calling conventions.
 *
 * Features exercised:
 *   - Value captures
 *   - Reference captures
 *   - Init captures (C++14)
 *   - Generic lambdas (C++14)
 *   - Mutable lambdas
 */

#include <cstdint>
#include <cinttypes> /* rax: print the result so that runs can be compared */
#include <cstdio>
#include <functional>

volatile int64_t sink;

/* Basic lambda with no capture */
__attribute__((noinline))
int64_t test_no_capture() {
    auto add = [](int a, int b) { return a + b; };
    auto mul = [](int a, int b) { return a * b; };

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += add(i, i + 1);
        result += mul(i, 2);
    }
    return result;
}

/* Lambda with value capture */
__attribute__((noinline))
int64_t test_value_capture() {
    int multiplier = 3;
    int offset = 10;

    auto transform = [multiplier, offset](int x) {
        return x * multiplier + offset;
    };

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += transform(i);
    }
    return result;
}

/* Lambda with reference capture */
__attribute__((noinline))
int64_t test_reference_capture() {
    int64_t accumulator = 0;
    int call_count = 0;

    auto accumulate = [&accumulator, &call_count](int value) {
        accumulator += value;
        call_count++;
    };

    for (int i = 0; i < 100; i++) {
        accumulate(i);
    }

    return accumulator + call_count;
}

/* Lambda with mixed capture */
__attribute__((noinline))
int64_t test_mixed_capture() {
    int factor = 5;
    int64_t sum = 0;

    auto mixed = [factor, &sum](int x) {
        sum += x * factor;
        return x * factor;
    };

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += mixed(i);
    }

    return result + sum;
}

/* Lambda with default capture by value */
__attribute__((noinline))
int64_t test_default_value_capture() {
    int a = 1, b = 2, c = 3, d = 4;

    auto compute = [=](int x) {
        return a * x * x * x + b * x * x + c * x + d;
    };

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += compute(i);
    }
    return result;
}

/* Lambda with default capture by reference */
__attribute__((noinline))
int64_t test_default_reference_capture() {
    int64_t total = 0;
    int min_val = 1000;
    int max_val = -1000;

    auto stats = [&](int x) {
        total += x;
        if (x < min_val) min_val = x;
        if (x > max_val) max_val = x;
    };

    for (int i = 0; i < 100; i++) {
        stats(i - 50);
    }

    return total + min_val + max_val;
}

/* Mutable lambda */
__attribute__((noinline))
int64_t test_mutable_lambda() {
    int counter = 0;

    auto incrementer = [counter]() mutable {
        return ++counter;
    };

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += incrementer();
    }
    return result;
}

/* Init capture (C++14) */
__attribute__((noinline))
int64_t test_init_capture() {
    auto generator = [n = 0]() mutable {
        int current = n;
        n = n * 2 + 1;
        return current;
    };

    int64_t result = 0;
    for (int i = 0; i < 20; i++) {
        result += generator();
    }
    return result;
}

/* Generic lambda (C++14) */
__attribute__((noinline))
int64_t test_generic_lambda() {
    auto generic_add = [](auto a, auto b) { return a + b; };

    int64_t result = 0;

    /* Use with different types */
    result += generic_add(10, 20);
    result += generic_add(100L, 200L);
    result += (int64_t)generic_add(1.5, 2.5);

    for (int i = 0; i < 100; i++) {
        result += generic_add(i, i);
    }

    return result;
}

/* Lambda returning lambda */
__attribute__((noinline))
int64_t test_lambda_returning_lambda() {
    auto make_adder = [](int n) {
        return [n](int x) { return x + n; };
    };

    auto add_10 = make_adder(10);
    auto add_20 = make_adder(20);

    int64_t result = 0;
    for (int i = 0; i < 100; i++) {
        result += add_10(i);
        result += add_20(i);
    }
    return result;
}

/* Lambda with std::function */
__attribute__((noinline))
int64_t apply_operation(std::function<int(int, int)> op, int a, int b) {
    return op(a, b);
}

__attribute__((noinline))
int64_t test_std_function() {
    int64_t result = 0;

    result += apply_operation([](int a, int b) { return a + b; }, 10, 20);
    result += apply_operation([](int a, int b) { return a * b; }, 10, 20);
    result += apply_operation([](int a, int b) { return a - b; }, 10, 20);

    int factor = 3;
    result += apply_operation([factor](int a, int b) { return (a + b) * factor; }, 10, 20);

    return result;
}

/* Higher-order function with lambda */
template<typename F>
__attribute__((noinline))
int64_t fold(const int* arr, int len, int64_t init, F f) {
    int64_t acc = init;
    for (int i = 0; i < len; i++) {
        acc = f(acc, arr[i]);
    }
    return acc;
}

__attribute__((noinline))
int64_t test_higher_order() {
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    int64_t sum = fold(arr, 10, 0, [](int64_t acc, int x) { return acc + x; });
    int64_t prod = fold(arr, 10, 1, [](int64_t acc, int x) { return acc * x; });
    int64_t max_val = fold(arr, 10, 0, [](int64_t acc, int x) {
        return x > acc ? x : acc;
    });

    return sum + prod + max_val;
}

/* Immediately invoked lambda */
__attribute__((noinline))
int64_t test_iife() {
    int64_t result = 0;

    for (int i = 0; i < 100; i++) {
        result += [i]() {
            int temp = i * 2;
            temp += i / 2;
            temp ^= i;
            return temp;
        }();
    }

    return result;
}

/* Lambda with complex capture */
struct Data {
    int values[4];
    int multiplier;
};

__attribute__((noinline))
int64_t test_complex_capture() {
    Data data = {{1, 2, 3, 4}, 5};

    /* Capture struct by value */
    auto process_copy = [data]() {
        int64_t sum = 0;
        for (int i = 0; i < 4; i++) {
            sum += data.values[i] * data.multiplier;
        }
        return sum;
    };

    /* Capture struct by reference */
    auto process_ref = [&data]() {
        int64_t sum = 0;
        for (int i = 0; i < 4; i++) {
            sum += data.values[i] * data.multiplier;
        }
        return sum;
    };

    int64_t result = process_copy();
    data.multiplier = 10;
    result += process_copy();  /* Still uses old value */
    result += process_ref();   /* Uses new value */

    return result;
}

/* Recursive lambda via std::function */
__attribute__((noinline))
int64_t test_recursive_lambda() {
    std::function<int64_t(int)> factorial = [&factorial](int n) -> int64_t {
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    };

    int64_t result = 0;
    for (int i = 1; i <= 12; i++) {
        result += factorial(i);
    }
    return result;
}

int main() {
    int64_t result = 0;

    for (int iter = 0; iter < 1000; iter++) {
        result += test_no_capture();
        result += test_value_capture();
        result += test_reference_capture();
        result += test_mixed_capture();
        result += test_default_value_capture();
        result += test_default_reference_capture();
        result += test_mutable_lambda();
        result += test_init_capture();
        result += test_generic_lambda();
        result += test_lambda_returning_lambda();
        result += test_std_function();
        result += test_higher_order();
        result += test_iife();
        result += test_complex_capture();

        if (iter % 100 == 0) {
            result += test_recursive_lambda();
        }
    }

    sink = result;
    std::printf("sink=%" PRId64 "\n", static_cast<int64_t>(sink)); /* rax: print the result so that runs can be compared */
    return 0;
}
