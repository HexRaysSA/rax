/*
 * Indirect Function Calls
 *
 * Tests function pointer dispatch patterns.
 * Exercises indirect call/branch instructions.
 *
 * Features exercised:
 *   - Function pointer calls
 *   - Virtual dispatch simulation
 *   - Callback patterns
 *   - Jump tables via function pointers
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Basic function pointer type */
typedef int (*BinaryOp)(int, int);
typedef int (*UnaryOp)(int);

/* Simple operations */
__attribute__((noinline)) int op_add(int a, int b) { return a + b; }
__attribute__((noinline)) int op_sub(int a, int b) { return a - b; }
__attribute__((noinline)) int op_mul(int a, int b) { return a * b; }
__attribute__((noinline)) int op_div(int a, int b) { return b ? a / b : 0; }
__attribute__((noinline)) int op_mod(int a, int b) { return b ? a % b : 0; }
__attribute__((noinline)) int op_and(int a, int b) { return a & b; }
__attribute__((noinline)) int op_or(int a, int b) { return a | b; }
__attribute__((noinline)) int op_xor(int a, int b) { return a ^ b; }
__attribute__((noinline)) int op_min(int a, int b) { return a < b ? a : b; }
__attribute__((noinline)) int op_max(int a, int b) { return a > b ? a : b; }

/* Unary operations */
__attribute__((noinline)) int unary_neg(int a) { return -a; }
__attribute__((noinline)) int unary_not(int a) { return ~a; }
__attribute__((noinline)) int unary_abs(int a) { return a < 0 ? -a : a; }
__attribute__((noinline)) int unary_square(int a) { return a * a; }
__attribute__((noinline)) int unary_double(int a) { return a * 2; }
__attribute__((noinline)) int unary_half(int a) { return a / 2; }

/* Function pointer table - dispatch by index */
static BinaryOp binary_ops[] = {
    op_add, op_sub, op_mul, op_div, op_mod,
    op_and, op_or, op_xor, op_min, op_max
};
#define NUM_BINARY_OPS (sizeof(binary_ops) / sizeof(binary_ops[0]))

static UnaryOp unary_ops[] = {
    unary_neg, unary_not, unary_abs, unary_square, unary_double, unary_half
};
#define NUM_UNARY_OPS (sizeof(unary_ops) / sizeof(unary_ops[0]))

__attribute__((noinline))
int dispatch_binary(int op, int a, int b) {
    if (op >= 0 && (size_t)op < NUM_BINARY_OPS) {
        return binary_ops[op](a, b);
    }
    return 0;
}

__attribute__((noinline))
int dispatch_unary(int op, int a) {
    if (op >= 0 && (size_t)op < NUM_UNARY_OPS) {
        return unary_ops[op](a);
    }
    return a;
}

/* Simulated virtual dispatch - struct with function pointers */
typedef struct {
    int (*get_value)(void *self);
    void (*set_value)(void *self, int value);
    int (*process)(void *self, int input);
} VTable;

typedef struct {
    const VTable *vtable;
    int data;
} Object;

/* Implementation A */
__attribute__((noinline))
int impl_a_get(void *self) {
    Object *obj = (Object *)self;
    return obj->data;
}

__attribute__((noinline))
void impl_a_set(void *self, int value) {
    Object *obj = (Object *)self;
    obj->data = value;
}

__attribute__((noinline))
int impl_a_process(void *self, int input) {
    Object *obj = (Object *)self;
    return obj->data + input;
}

static const VTable vtable_a = {impl_a_get, impl_a_set, impl_a_process};

/* Implementation B */
__attribute__((noinline))
int impl_b_get(void *self) {
    Object *obj = (Object *)self;
    return obj->data * 2;
}

__attribute__((noinline))
void impl_b_set(void *self, int value) {
    Object *obj = (Object *)self;
    obj->data = value / 2;
}

__attribute__((noinline))
int impl_b_process(void *self, int input) {
    Object *obj = (Object *)self;
    return obj->data * input;
}

static const VTable vtable_b = {impl_b_get, impl_b_set, impl_b_process};

/* Callback pattern */
typedef void (*Callback)(int value, void *context);

__attribute__((noinline))
void callback_accumulate(int value, void *context) {
    int64_t *acc = (int64_t *)context;
    *acc += value;
}

__attribute__((noinline))
void callback_multiply(int value, void *context) {
    int64_t *acc = (int64_t *)context;
    *acc *= value;
}

__attribute__((noinline))
void iterate_with_callback(const int *arr, int len, Callback cb, void *context) {
    for (int i = 0; i < len; i++) {
        cb(arr[i], context);
    }
}

/* Higher-order function simulation */
__attribute__((noinline))
int apply_twice(UnaryOp f, int x) {
    return f(f(x));
}

__attribute__((noinline))
int compose(UnaryOp f, UnaryOp g, int x) {
    return f(g(x));
}

__attribute__((noinline))
int fold_left(BinaryOp f, const int *arr, int len, int init) {
    int acc = init;
    for (int i = 0; i < len; i++) {
        acc = f(acc, arr[i]);
    }
    return acc;
}

/* State machine with function pointer transitions */
typedef struct StateMachine StateMachine;
typedef void (*StateHandler)(StateMachine *sm, int input);

struct StateMachine {
    StateHandler current_state;
    int64_t accumulator;
    int counter;
};

__attribute__((noinline)) void state_idle(StateMachine *sm, int input);
__attribute__((noinline)) void state_running(StateMachine *sm, int input);
__attribute__((noinline)) void state_paused(StateMachine *sm, int input);

void state_idle(StateMachine *sm, int input) {
    if (input > 0) {
        sm->accumulator = input;
        sm->counter = 0;
        sm->current_state = state_running;
    }
}

void state_running(StateMachine *sm, int input) {
    sm->accumulator += input;
    sm->counter++;
    if (sm->counter >= 10) {
        sm->current_state = state_paused;
    } else if (input < 0) {
        sm->current_state = state_idle;
    }
}

void state_paused(StateMachine *sm, int input) {
    if (input == 0) {
        sm->current_state = state_idle;
    } else if (input > 0) {
        sm->counter = 0;
        sm->current_state = state_running;
    }
}

__attribute__((noinline))
void step_machine(StateMachine *sm, int input) {
    sm->current_state(sm, input);
}

int main(void) {
    int64_t result = 0;
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    /* Virtual dispatch simulation */
    Object obj_a = {&vtable_a, 100};
    Object obj_b = {&vtable_b, 100};
    Object *objects[2] = {&obj_a, &obj_b};

    /* State machine */
    StateMachine sm = {state_idle, 0, 0};

    for (int i = 0; i < 400; i++) { /* rax: was 100000 */
        /* Table dispatch */
        result += dispatch_binary(i % NUM_BINARY_OPS, i, i % 10 + 1);
        result += dispatch_unary(i % NUM_UNARY_OPS, i);

        /* Virtual dispatch */
        Object *obj = objects[i % 2];
        result += obj->vtable->get_value(obj);
        obj->vtable->set_value(obj, i);
        result += obj->vtable->process(obj, i % 100);

        /* Callback iteration */
        int64_t acc = 0;
        iterate_with_callback(arr, 10,
            i % 2 == 0 ? callback_accumulate : callback_multiply,
            &acc);
        if (i % 2 == 1) {
            acc = 1; /* Reset for multiply */
            iterate_with_callback(arr, 5, callback_multiply, &acc);
        }
        result += acc;

        /* Higher-order functions */
        result += apply_twice(unary_double, i % 100);
        result += compose(unary_square, unary_abs, -(i % 50));
        result += fold_left(op_add, arr, 10, 0);
        result += fold_left(i % 2 == 0 ? op_add : op_mul, arr, 5, i % 2 == 0 ? 0 : 1);

        /* State machine */
        step_machine(&sm, (i % 20) - 5);
        result += sm.accumulator;
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
