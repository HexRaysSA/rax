/*
 * setjmp/longjmp Non-Local Jumps
 *
 * C's mechanism for non-local control flow.
 * Tests register save/restore and stack manipulation.
 *
 * Features exercised:
 *   - setjmp/longjmp implementation
 *   - Register state preservation
 *   - Non-local jumps
 *   - Error handling patterns
 */

#include <setjmp.h>
#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Basic setjmp/longjmp */
__attribute__((noinline))
int basic_setjmp(int trigger) {
    jmp_buf env;
    int val = setjmp(env);

    if (val != 0) {
        /* Returned from longjmp */
        return val * 10;
    }

    /* Normal path */
    if (trigger > 0) {
        longjmp(env, trigger);
    }

    return -1;
}

/* Nested function longjmp */
static jmp_buf nested_env;

__attribute__((noinline))
void deep_function(int depth, int val) {
    if (depth <= 0) {
        longjmp(nested_env, val);
    }
    deep_function(depth - 1, val + 1);
}

__attribute__((noinline))
int nested_longjmp(int depth) {
    int val = setjmp(nested_env);

    if (val != 0) {
        return val;
    }

    deep_function(depth, 1);
    return 0; /* Never reached */
}

/* Error handling pattern */
typedef struct {
    jmp_buf env;
    int error_code;
    const char *error_msg;
} ErrorContext;

static ErrorContext error_ctx;

__attribute__((noinline))
void raise_error(int code, const char *msg) {
    error_ctx.error_code = code;
    error_ctx.error_msg = msg;
    longjmp(error_ctx.env, code);
}

__attribute__((noinline))
int process_with_errors(int x) {
    if (x < 0) {
        raise_error(1, "negative");
    }
    if (x > 100) {
        raise_error(2, "too large");
    }
    if (x == 42) {
        raise_error(42, "forbidden");
    }
    return x * x;
}

__attribute__((noinline))
int try_process(int x) {
    int code = setjmp(error_ctx.env);

    if (code != 0) {
        /* Error occurred */
        return -code;
    }

    return process_with_errors(x);
}

/* Multiple jmp_buf variables */
__attribute__((noinline))
int multi_setjmp(int selector) {
    jmp_buf env1, env2, env3;
    int result = 0;

    int v1 = setjmp(env1);
    if (v1 != 0) {
        return v1 * 100;
    }

    int v2 = setjmp(env2);
    if (v2 != 0) {
        return v2 * 200;
    }

    int v3 = setjmp(env3);
    if (v3 != 0) {
        return v3 * 300;
    }

    switch (selector % 4) {
        case 0: result = 999; break;
        case 1: longjmp(env1, 1); break;
        case 2: longjmp(env2, 2); break;
        case 3: longjmp(env3, 3); break;
    }

    return result;
}

/* setjmp in loop */
__attribute__((noinline))
int64_t setjmp_loop(int iterations) {
    jmp_buf loop_env;
    volatile int64_t sum = 0;
    volatile int i = 0;

    int jumped = setjmp(loop_env);
    if (jumped) {
        sum += jumped;
    }

    if (i < iterations) {
        int val = i * i;
        i++;
        if (i % 7 == 0) {
            longjmp(loop_env, val);
        }
        sum += val;
        if (i < iterations) {
            longjmp(loop_env, 0);
        }
    }

    return sum;
}

/* Coroutine-like switching without jumping back into a dead stack frame. */
typedef struct {
    jmp_buf env;
    int state;
    int64_t value;
} Coroutine;

static Coroutine coro_main, coro_worker;
static int64_t shared_value;

__attribute__((noinline))
int64_t coroutine_test(int switches) {
    volatile int i = 0;
    volatile int64_t local = 0;
    shared_value = 1;

    for (i = 0; i < switches; i++) {
        int main_jump = setjmp(coro_main.env);
        if (main_jump == 0) {
            int worker_jump = setjmp(coro_worker.env);
            if (worker_jump == 0) {
                shared_value = i;
                longjmp(coro_worker.env, 1);
            }

            local += shared_value;
            shared_value = local;
            coro_worker.value = local;
            longjmp(coro_main.env, 1);
        }
    }

    return coro_worker.value;
}

/* Cleanup simulation */
typedef struct {
    int resource_id;
    int *cleanup_counter;
} Resource;

static jmp_buf cleanup_env;
static Resource resources[4];
static int resource_count;
static int cleanup_counter;

__attribute__((noinline))
void cleanup_resources(void) {
    while (resource_count > 0) {
        resource_count--;
        (*resources[resource_count].cleanup_counter)++;
    }
}

__attribute__((noinline))
void acquire_resource(int id) {
    if (resource_count >= 4) {
        cleanup_resources();
        longjmp(cleanup_env, 1);
    }
    resources[resource_count].resource_id = id;
    resources[resource_count].cleanup_counter = &cleanup_counter;
    resource_count++;
}

__attribute__((noinline))
int use_resources(int n) {
    resource_count = 0;
    cleanup_counter = 0;

    int code = setjmp(cleanup_env);
    if (code != 0) {
        return -cleanup_counter;
    }

    for (int i = 0; i < n; i++) {
        acquire_resource(i);
        if (i == 3) {
            /* Simulate error */
            cleanup_resources();
            longjmp(cleanup_env, 2);
        }
    }

    int result = 0;
    for (int i = 0; i < resource_count; i++) {
        result += resources[i].resource_id;
    }

    cleanup_resources();
    return result;
}

/* State machine with setjmp */
__attribute__((noinline))
int state_machine_setjmp(int input) {
    jmp_buf states[4];
    volatile int current = 0;
    volatile int state_input = input;
    volatile int result = 0;

    #define DEFINE_STATE(n) \
        if (setjmp(states[n]) != 0) goto state_##n;

    DEFINE_STATE(0);
    DEFINE_STATE(1);
    DEFINE_STATE(2);
    DEFINE_STATE(3);

    /* Start in state 0 */
    longjmp(states[0], 1);

state_0:
    current = 0;
    result += 1;
    if (state_input > 0) longjmp(states[1], 1);
    return result;

state_1:
    current = 1;
    result += 10;
    state_input--;
    if (state_input > 5) longjmp(states[2], 1);
    if (state_input > 0) longjmp(states[1], 1);
    longjmp(states[0], 1);

state_2:
    current = 2;
    result += 100;
    state_input -= 2;
    if (state_input > 10) longjmp(states[3], 1);
    longjmp(states[1], 1);

state_3:
    current = 3;
    result += 1000;
    return result + current;

    #undef DEFINE_STATE
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 250; i++) { /* rax: was 50000 */
        /* Basic setjmp */
        result += basic_setjmp(i % 10);

        /* Nested longjmp */
        result += nested_longjmp(5);

        /* Error handling pattern */
        int vals[] = {10, -5, 150, 42, 50};
        result += try_process(vals[i % 5]);

        /* Multiple jmp_buf */
        result += multi_setjmp(i);

        /* setjmp in loop */
        if (i % 100 == 0) {
            result += setjmp_loop(20);
        }

        /* Coroutine switching */
        if (i % 500 == 0) {
            result += coroutine_test(10);
        }

        /* Resource cleanup */
        result += use_resources(i % 6);

        /* State machine */
        result += state_machine_setjmp(i % 20);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
