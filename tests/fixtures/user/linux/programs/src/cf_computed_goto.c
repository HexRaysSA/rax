/*
 * Computed Goto (Labels as Values)
 *
 * GCC/Clang extension for direct threaded code.
 * Common in interpreter loops and dispatch tables.
 *
 * Features exercised:
 *   - Label addresses
 *   - Indirect goto
 *   - Threaded code dispatch
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Simple bytecode interpreter using computed goto */
typedef enum {
    OP_NOP = 0,
    OP_PUSH,
    OP_POP,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_DUP,
    OP_SWAP,
    OP_LOAD,
    OP_STORE,
    OP_JMP,
    OP_JZ,
    OP_JNZ,
    OP_HALT,
    OP_COUNT
} Opcode;

#define STACK_SIZE 64
#define MEM_SIZE 16

__attribute__((noinline))
int64_t interpret(const uint8_t *code, int code_len) {
    /* Dispatch table using label addresses */
    static const void *dispatch_table[] = {
        &&do_nop,
        &&do_push,
        &&do_pop,
        &&do_add,
        &&do_sub,
        &&do_mul,
        &&do_div,
        &&do_dup,
        &&do_swap,
        &&do_load,
        &&do_store,
        &&do_jmp,
        &&do_jz,
        &&do_jnz,
        &&do_halt
    };

    int64_t stack[STACK_SIZE];
    int sp = 0;
    int64_t mem[MEM_SIZE] = {0};
    int pc = 0;

    #define DISPATCH() do { \
        if (pc >= code_len || code[pc] >= OP_COUNT) goto do_halt; \
        goto *dispatch_table[code[pc]]; \
    } while(0)

    #define NEXT() do { pc++; DISPATCH(); } while(0)

    DISPATCH();

do_nop:
    NEXT();

do_push:
    pc++;
    if (pc < code_len && sp < STACK_SIZE) {
        stack[sp++] = code[pc];
    }
    NEXT();

do_pop:
    if (sp > 0) sp--;
    NEXT();

do_add:
    if (sp >= 2) {
        int64_t b = stack[--sp];
        int64_t a = stack[--sp];
        stack[sp++] = a + b;
    }
    NEXT();

do_sub:
    if (sp >= 2) {
        int64_t b = stack[--sp];
        int64_t a = stack[--sp];
        stack[sp++] = a - b;
    }
    NEXT();

do_mul:
    if (sp >= 2) {
        int64_t b = stack[--sp];
        int64_t a = stack[--sp];
        stack[sp++] = a * b;
    }
    NEXT();

do_div:
    if (sp >= 2) {
        int64_t b = stack[--sp];
        int64_t a = stack[--sp];
        stack[sp++] = b != 0 ? a / b : 0;
    }
    NEXT();

do_dup:
    if (sp > 0 && sp < STACK_SIZE) {
        stack[sp] = stack[sp - 1];
        sp++;
    }
    NEXT();

do_swap:
    if (sp >= 2) {
        int64_t tmp = stack[sp - 1];
        stack[sp - 1] = stack[sp - 2];
        stack[sp - 2] = tmp;
    }
    NEXT();

do_load:
    pc++;
    if (pc < code_len && sp < STACK_SIZE) {
        int addr = code[pc] % MEM_SIZE;
        stack[sp++] = mem[addr];
    }
    NEXT();

do_store:
    pc++;
    if (pc < code_len && sp > 0) {
        int addr = code[pc] % MEM_SIZE;
        mem[addr] = stack[--sp];
    }
    NEXT();

do_jmp:
    pc++;
    if (pc < code_len) {
        pc = code[pc] % code_len;
        DISPATCH();
    }
    goto do_halt;

do_jz:
    pc++;
    if (pc < code_len && sp > 0) {
        if (stack[sp - 1] == 0) {
            sp--;
            pc = code[pc] % code_len;
            DISPATCH();
        }
    }
    NEXT();

do_jnz:
    pc++;
    if (pc < code_len && sp > 0) {
        if (stack[sp - 1] != 0) {
            sp--;
            pc = code[pc] % code_len;
            DISPATCH();
        }
    }
    NEXT();

do_halt:
    return sp > 0 ? stack[sp - 1] : 0;

    #undef DISPATCH
    #undef NEXT
}

/* State machine using computed goto */
__attribute__((noinline))
int64_t state_machine_cgoto(int iterations) {
    static const void *states[] = {
        &&state_init,
        &&state_running,
        &&state_waiting,
        &&state_done
    };

    int64_t acc = 0;
    int state = 0;
    int counter = 0;

    #define GOTO_STATE(s) do { state = (s); goto *states[state]; } while(0)

    GOTO_STATE(0);

state_init:
    acc = 1;
    counter = 0;
    GOTO_STATE(1);

state_running:
    acc += counter;
    counter++;
    if (counter >= iterations) {
        GOTO_STATE(3);
    } else if (counter % 10 == 0) {
        GOTO_STATE(2);
    }
    GOTO_STATE(1);

state_waiting:
    acc *= 2;
    GOTO_STATE(1);

state_done:
    return acc;

    #undef GOTO_STATE
}

/* Pattern matching simulation with computed goto */
__attribute__((noinline))
int match_pattern(const char *str, int len) {
    static const void *char_handlers[4] = {
        &&handle_alpha,
        &&handle_digit,
        &&handle_space,
        &&handle_other
    };

    int alpha_count = 0;
    int digit_count = 0;
    int space_count = 0;
    int other_count = 0;
    int pos = 0;

    #define CLASSIFY_CHAR(c) ( \
        ((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') ? 0 : \
        ((c) >= '0' && (c) <= '9') ? 1 : \
        ((c) == ' ' || (c) == '\t' || (c) == '\n') ? 2 : 3 \
    )

    if (pos >= len) goto done;
    goto *char_handlers[CLASSIFY_CHAR(str[pos])];

handle_alpha:
    alpha_count++;
    pos++;
    if (pos >= len) goto done;
    goto *char_handlers[CLASSIFY_CHAR(str[pos])];

handle_digit:
    digit_count++;
    pos++;
    if (pos >= len) goto done;
    goto *char_handlers[CLASSIFY_CHAR(str[pos])];

handle_space:
    space_count++;
    pos++;
    if (pos >= len) goto done;
    goto *char_handlers[CLASSIFY_CHAR(str[pos])];

handle_other:
    other_count++;
    pos++;
    if (pos >= len) goto done;
    goto *char_handlers[CLASSIFY_CHAR(str[pos])];

done:
    return (alpha_count << 24) | (digit_count << 16) | (space_count << 8) | other_count;

    #undef CLASSIFY_CHAR
}

/* Direct threaded dispatch - common in Forth-like languages */
typedef void **CodeWord;

__attribute__((noinline))
int64_t threaded_exec(int iterations) {
    static const void *code[] = {
        &&t_lit, (void*)10,
        &&t_lit, (void*)20,
        &&t_add,
        &&t_dup,
        &&t_mul,
        &&t_exit
    };

    int64_t data_stack[32];
    int dsp = 0;
    CodeWord ip = (CodeWord)code;

    #define NEXT_WORD() goto **(ip++)

    NEXT_WORD();

t_lit:
    data_stack[dsp++] = (int64_t)(intptr_t)*ip++;
    NEXT_WORD();

t_add:
    if (dsp >= 2) {
        int64_t b = data_stack[--dsp];
        int64_t a = data_stack[--dsp];
        data_stack[dsp++] = a + b;
    }
    NEXT_WORD();

t_dup:
    if (dsp > 0 && dsp < 32) {
        data_stack[dsp] = data_stack[dsp - 1];
        dsp++;
    }
    NEXT_WORD();

t_mul:
    if (dsp >= 2) {
        int64_t b = data_stack[--dsp];
        int64_t a = data_stack[--dsp];
        data_stack[dsp++] = a * b;
    }
    NEXT_WORD();

t_exit:
    (void)iterations;
    return dsp > 0 ? data_stack[dsp - 1] : 0;

    #undef NEXT_WORD
}

int main(void) {
    int64_t result = 0;

    /* Test bytecode interpreter */
    uint8_t programs[][20] = {
        /* Program 1: push 10, push 20, add -> 30 */
        {OP_PUSH, 10, OP_PUSH, 20, OP_ADD, OP_HALT},
        /* Program 2: push 5, dup, mul -> 25 */
        {OP_PUSH, 5, OP_DUP, OP_MUL, OP_HALT},
        /* Program 3: push 100, push 7, div -> 14 */
        {OP_PUSH, 100, OP_PUSH, 7, OP_DIV, OP_HALT},
        /* Program 4: push 3, push 4, mul, push 5, add -> 17 */
        {OP_PUSH, 3, OP_PUSH, 4, OP_MUL, OP_PUSH, 5, OP_ADD, OP_HALT},
        /* Program 5: push 10, store 0, push 5, load 0, add -> 15 */
        {OP_PUSH, 10, OP_STORE, 0, OP_PUSH, 5, OP_LOAD, 0, OP_ADD, OP_HALT}
    };
    int prog_lens[] = {6, 5, 6, 9, 10};

    const char *test_strings[] = {
        "Hello World 123",
        "abc123 def456",
        "    ",
        "12345",
        "!@#$%"
    };

    for (int i = 0; i < 300; i++) { /* rax: was 100000 */
        /* Run bytecode interpreter */
        int prog_idx = i % 5;
        result += interpret(programs[prog_idx], prog_lens[prog_idx]);

        /* Run state machine */
        if (i % 100 == 0) {
            result += state_machine_cgoto(50);
        }

        /* Run pattern matcher */
        const char *str = test_strings[i % 5];
        int len = 0;
        while (str[len]) len++;
        result += match_pattern(str, len);

        /* Run threaded code */
        result += threaded_exec(i);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
