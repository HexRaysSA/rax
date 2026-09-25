/*
 * =============================================================================
 * BYTECODE VIRTUAL MACHINE INTERPRETER
 * =============================================================================
 * 
 * A complete stack-based bytecode virtual machine implementation in C.
 * 
 * ARCHITECTURE OVERVIEW:
 * ----------------------
 * This VM uses a stack-based architecture, similar to the Java Virtual Machine
 * (JVM) or Python's bytecode interpreter. In a stack-based VM, operands are
 * pushed onto a stack, operations pop their operands from the stack, and push
 * results back onto the stack.
 * 
 * Key components:
 * 1. OPERAND STACK - Where all computation happens. Instructions pop operands
 *    from here and push results back.
 * 
 * 2. CALL STACK - Tracks function call frames. Each frame contains:
 *    - Return address (where to continue after function returns)
 *    - Local variables for that function
 *    - Base pointer (stack position when function was called)
 * 
 * 3. GLOBAL VARIABLES - Accessible from any function
 * 
 * 4. PROGRAM COUNTER (PC) - Points to the next instruction to execute
 * 
 * BYTECODE FORMAT:
 * ----------------
 * Each instruction consists of:
 * - 1 byte opcode (identifies the operation)
 * - 0-4 bytes of operands (depending on instruction)
 * 
 * For example:
 *   PUSH 42    -> [OP_PUSH][0x00][0x00][0x00][0x2A]  (5 bytes: opcode + 32-bit value)
 *   ADD        -> [OP_ADD]                           (1 byte: just opcode)
 *   JMP 100    -> [OP_JMP][0x00][0x00][0x00][0x64]   (5 bytes: opcode + 32-bit address)
 * 
 * EXECUTION MODEL:
 * ----------------
 * The VM runs in a fetch-decode-execute loop:
 * 1. FETCH: Read the opcode at the current PC
 * 2. DECODE: Determine what operation to perform and read any operands
 * 3. EXECUTE: Perform the operation, possibly modifying stack/PC
 * 4. Repeat until HALT instruction or error
 * 
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp (glibc declares it here, not <string.h>) */
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

/* =============================================================================
 * CONFIGURATION CONSTANTS
 * =============================================================================
 * These define the limits of our VM. In a production VM, these might be
 * dynamically allocated, but fixed sizes simplify the implementation.
 */

#define STACK_SIZE      256     /* Maximum operand stack depth */
#define CALL_STACK_SIZE 64      /* Maximum nested function calls */
#define LOCALS_SIZE     16      /* Local variables per call frame */
#define GLOBALS_SIZE    256     /* Global variables */
#define CODE_SIZE       4096    /* Maximum bytecode size */
#define MAX_LABELS      256     /* Maximum labels in assembler */
#define MAX_LINE_LEN    256     /* Maximum assembly line length */

/* =============================================================================
 * OPCODE DEFINITIONS
 * =============================================================================
 * Each opcode is a single byte. The enum assigns sequential values starting
 * from 0. Comments indicate the stack effect: (before -- after)
 * 
 * Stack notation:
 *   a, b  = values on stack (a is deeper, b is top)
 *   --    = separator between before and after
 *   
 * Example: ADD has effect (a, b -- a+b) meaning it pops two values and pushes sum
 */

typedef enum {
    /* Stack Manipulation */
    OP_NOP = 0,         /* ( -- )           No operation */
    OP_PUSH,            /* ( -- n)          Push 32-bit immediate value */
    OP_POP,             /* (a -- )          Discard top of stack */
    OP_DUP,             /* (a -- a, a)      Duplicate top of stack */
    OP_SWAP,            /* (a, b -- b, a)   Swap top two values */
    OP_OVER,            /* (a, b -- a, b, a) Copy second value to top */
    
    /* Arithmetic Operations */
    OP_ADD,             /* (a, b -- a+b)    Addition */
    OP_SUB,             /* (a, b -- a-b)    Subtraction */
    OP_MUL,             /* (a, b -- a*b)    Multiplication */
    OP_DIV,             /* (a, b -- a/b)    Integer division */
    OP_MOD,             /* (a, b -- a%b)    Modulo (remainder) */
    OP_NEG,             /* (a -- -a)        Negate */
    OP_INC,             /* (a -- a+1)       Increment */
    OP_DEC,             /* (a -- a-1)       Decrement */
    
    /* Comparison Operations - push 1 for true, 0 for false */
    OP_EQ,              /* (a, b -- a==b)   Equal */
    OP_NE,              /* (a, b -- a!=b)   Not equal */
    OP_LT,              /* (a, b -- a<b)    Less than */
    OP_LE,              /* (a, b -- a<=b)   Less or equal */
    OP_GT,              /* (a, b -- a>b)    Greater than */
    OP_GE,              /* (a, b -- a>=b)   Greater or equal */
    
    /* Logical/Bitwise Operations */
    OP_AND,             /* (a, b -- a&&b)   Logical AND */
    OP_OR,              /* (a, b -- a||b)   Logical OR */
    OP_NOT,             /* (a -- !a)        Logical NOT */
    OP_BAND,            /* (a, b -- a&b)    Bitwise AND */
    OP_BOR,             /* (a, b -- a|b)    Bitwise OR */
    OP_BNOT,            /* (a -- ~a)        Bitwise NOT */
    OP_XOR,             /* (a, b -- a^b)    Bitwise XOR */
    OP_SHL,             /* (a, b -- a<<b)   Shift left */
    OP_SHR,             /* (a, b -- a>>b)   Shift right */
    
    /* Control Flow */
    OP_JMP,             /* ( -- )           Unconditional jump */
    OP_JZ,              /* (a -- )          Jump if zero (false) */
    OP_JNZ,             /* (a -- )          Jump if not zero (true) */
    OP_CALL,            /* ( -- )           Call function at address */
    OP_RET,             /* ( -- )           Return from function */
    
    /* Variable Access */
    OP_LOAD_LOCAL,      /* ( -- v)          Push local variable */
    OP_STORE_LOCAL,     /* (v -- )          Pop to local variable */
    OP_LOAD_GLOBAL,     /* ( -- v)          Push global variable */
    OP_STORE_GLOBAL,    /* (v -- )          Pop to global variable */
    
    /* I/O Operations */
    OP_PRINT,           /* (a -- )          Print top of stack as integer */
    OP_PRINT_CHAR,      /* (a -- )          Print top of stack as ASCII char */
    OP_PRINT_STR,       /* ( -- )           Print inline string (null-terminated) */
    OP_READ,            /* ( -- n)          Read integer from stdin */
    
    /* Special */
    OP_HALT,            /* ( -- )           Stop execution */
    OP_DEBUG,           /* ( -- )           Print debug info (stack dump) */
    
    OP_COUNT            /* Number of opcodes (not a real opcode) */
} Opcode;

/* =============================================================================
 * OPCODE METADATA
 * =============================================================================
 * This table provides information about each opcode for the assembler,
 * disassembler, and VM. It maps opcode numbers to their names and operand sizes.
 */

typedef struct {
    const char *name;   /* Mnemonic (e.g., "PUSH", "ADD") */
    int operand_size;   /* Size of operand in bytes (0, 1, 2, or 4) */
} OpcodeInfo;

static const OpcodeInfo opcode_info[OP_COUNT] = {
    [OP_NOP]          = {"NOP",          0},
    [OP_PUSH]         = {"PUSH",         4},  /* 32-bit immediate */
    [OP_POP]          = {"POP",          0},
    [OP_DUP]          = {"DUP",          0},
    [OP_SWAP]         = {"SWAP",         0},
    [OP_OVER]         = {"OVER",         0},
    [OP_ADD]          = {"ADD",          0},
    [OP_SUB]          = {"SUB",          0},
    [OP_MUL]          = {"MUL",          0},
    [OP_DIV]          = {"DIV",          0},
    [OP_MOD]          = {"MOD",          0},
    [OP_NEG]          = {"NEG",          0},
    [OP_INC]          = {"INC",          0},
    [OP_DEC]          = {"DEC",          0},
    [OP_EQ]           = {"EQ",           0},
    [OP_NE]           = {"NE",           0},
    [OP_LT]           = {"LT",           0},
    [OP_LE]           = {"LE",           0},
    [OP_GT]           = {"GT",           0},
    [OP_GE]           = {"GE",           0},
    [OP_AND]          = {"AND",          0},
    [OP_OR]           = {"OR",           0},
    [OP_NOT]          = {"NOT",          0},
    [OP_BAND]         = {"BAND",         0},
    [OP_BOR]          = {"BOR",          0},
    [OP_BNOT]         = {"BNOT",         0},
    [OP_XOR]          = {"XOR",          0},
    [OP_SHL]          = {"SHL",          0},
    [OP_SHR]          = {"SHR",          0},
    [OP_JMP]          = {"JMP",          4},  /* 32-bit address */
    [OP_JZ]           = {"JZ",           4},
    [OP_JNZ]          = {"JNZ",          4},
    [OP_CALL]         = {"CALL",         4},
    [OP_RET]          = {"RET",          0},
    [OP_LOAD_LOCAL]   = {"LOAD_LOCAL",   1},  /* 8-bit index */
    [OP_STORE_LOCAL]  = {"STORE_LOCAL",  1},
    [OP_LOAD_GLOBAL]  = {"LOAD_GLOBAL",  4},  /* 32-bit index for flexibility */
    [OP_STORE_GLOBAL] = {"STORE_GLOBAL", 4},
    [OP_PRINT]        = {"PRINT",        0},
    [OP_PRINT_CHAR]   = {"PRINT_CHAR",   0},
    [OP_PRINT_STR]    = {"PRINT_STR",   -1},  /* Variable length (null-terminated) */
    [OP_READ]         = {"READ",         0},
    [OP_HALT]         = {"HALT",         0},
    [OP_DEBUG]        = {"DEBUG",        0},
};

/* =============================================================================
 * CALL FRAME STRUCTURE
 * =============================================================================
 * Each function call creates a new frame on the call stack. The frame stores
 * everything needed to resume execution when the function returns.
 * 
 * This is similar to how CPU stack frames work in native code, but simplified.
 * In a real CPU, the frame would contain saved registers, but our VM only needs
 * to track the return address and local variables.
 */

typedef struct {
    uint32_t return_addr;           /* PC to return to after RET */
    int32_t locals[LOCALS_SIZE];    /* Local variables for this frame */
    int stack_base;                 /* Stack pointer when frame was created */
} CallFrame;

/* =============================================================================
 * VIRTUAL MACHINE STATE
 * =============================================================================
 * This structure contains the complete state of the VM. In theory, you could
 * serialize this structure to implement VM snapshots/checkpoints.
 */

typedef struct {
    /* Memory regions */
    uint8_t code[CODE_SIZE];        /* Bytecode storage */
    int32_t stack[STACK_SIZE];      /* Operand stack */
    int32_t globals[GLOBALS_SIZE];  /* Global variables */
    CallFrame call_stack[CALL_STACK_SIZE];  /* Function call frames */
    
    /* Registers/pointers */
    uint32_t pc;                    /* Program counter (next instruction) */
    int sp;                         /* Stack pointer (index of next free slot) */
    int fp;                         /* Frame pointer (current call frame index) */
    
    /* Metadata */
    uint32_t code_size;             /* Actual size of loaded bytecode */
    bool running;                   /* VM is executing */
    bool debug_mode;                /* Print trace during execution */
    
    /* Statistics (for profiling) */
    uint64_t instruction_count;     /* Total instructions executed */
} VM;

/* =============================================================================
 * ERROR HANDLING
 * =============================================================================
 * In a production VM, you'd want more sophisticated error handling with
 * exception mechanisms. Here we just print and exit for simplicity.
 */

typedef enum {
    VM_OK = 0,
    VM_ERROR_STACK_OVERFLOW,
    VM_ERROR_STACK_UNDERFLOW,
    VM_ERROR_CALL_STACK_OVERFLOW,
    VM_ERROR_CALL_STACK_UNDERFLOW,
    VM_ERROR_INVALID_OPCODE,
    VM_ERROR_DIVISION_BY_ZERO,
    VM_ERROR_OUT_OF_BOUNDS,
    VM_ERROR_INVALID_ADDRESS,
} VMError;

static const char *error_messages[] = {
    [VM_OK]                       = "OK",
    [VM_ERROR_STACK_OVERFLOW]     = "Stack overflow",
    [VM_ERROR_STACK_UNDERFLOW]    = "Stack underflow",
    [VM_ERROR_CALL_STACK_OVERFLOW]= "Call stack overflow",
    [VM_ERROR_CALL_STACK_UNDERFLOW]= "Call stack underflow",
    [VM_ERROR_INVALID_OPCODE]     = "Invalid opcode",
    [VM_ERROR_DIVISION_BY_ZERO]   = "Division by zero",
    [VM_ERROR_OUT_OF_BOUNDS]      = "Array index out of bounds",
    [VM_ERROR_INVALID_ADDRESS]    = "Invalid memory address",
};

static void vm_error(VM *vm, VMError error) {
    fprintf(stderr, "VM Error at PC=%u: %s\n", vm->pc, error_messages[error]);
    fprintf(stderr, "Stack pointer: %d, Frame pointer: %d\n", vm->sp, vm->fp);
    vm->running = false;
}

/* =============================================================================
 * VM INITIALIZATION
 * =============================================================================
 * Reset the VM to a clean initial state. This must be called before loading
 * any bytecode or executing.
 */

static void vm_init(VM *vm) {
    memset(vm, 0, sizeof(VM));
    vm->running = false;
    vm->debug_mode = false;
    vm->fp = -1;  /* No active call frames initially */
}

/* =============================================================================
 * STACK OPERATIONS
 * =============================================================================
 * These are the primitive operations for manipulating the operand stack.
 * The stack grows upward (sp increases when pushing).
 * 
 * Stack layout example after pushing 10, 20, 30:
 *   Index:  0    1    2    3    4   ...
 *   Value: [10] [20] [30] [ ] [ ]  ...
 *                          ^
 *                          sp (next free slot)
 */

/* Push a value onto the operand stack */
static bool vm_push(VM *vm, int32_t value) {
    if (vm->sp >= STACK_SIZE) {
        vm_error(vm, VM_ERROR_STACK_OVERFLOW);
        return false;
    }
    vm->stack[vm->sp++] = value;
    return true;
}

/* Pop a value from the operand stack */
static bool vm_pop(VM *vm, int32_t *value) {
    if (vm->sp <= 0) {
        vm_error(vm, VM_ERROR_STACK_UNDERFLOW);
        return false;
    }
    *value = vm->stack[--vm->sp];
    return true;
}

/* Peek at top of stack without removing */
static bool vm_peek(VM *vm, int32_t *value) {
    if (vm->sp <= 0) {
        vm_error(vm, VM_ERROR_STACK_UNDERFLOW);
        return false;
    }
    *value = vm->stack[vm->sp - 1];
    return true;
}

/* Peek at value at offset from top (0 = top, 1 = second from top, etc.) */
static bool vm_peek_at(VM *vm, int offset, int32_t *value) {
    int index = vm->sp - 1 - offset;
    if (index < 0 || index >= vm->sp) {
        vm_error(vm, VM_ERROR_STACK_UNDERFLOW);
        return false;
    }
    *value = vm->stack[index];
    return true;
}

/* =============================================================================
 * BYTECODE READING HELPERS
 * =============================================================================
 * These functions read operands from the bytecode stream. The PC is advanced
 * past the operand after reading.
 * 
 * Bytecode is stored in little-endian format (least significant byte first).
 * This matches x86/x64 native byte order but we decode explicitly for portability.
 */

/* Read a single byte operand */
static uint8_t vm_read_byte(VM *vm) {
    if (vm->pc >= vm->code_size) {
        vm_error(vm, VM_ERROR_INVALID_ADDRESS);
        return 0;
    }
    return vm->code[vm->pc++];
}

/* Read a 32-bit operand (little-endian) */
static uint32_t vm_read_uint32(VM *vm) {
    if (vm->pc + 4 > vm->code_size) {
        vm_error(vm, VM_ERROR_INVALID_ADDRESS);
        return 0;
    }
    uint32_t value = (uint32_t)vm->code[vm->pc]
                   | ((uint32_t)vm->code[vm->pc + 1] << 8)
                   | ((uint32_t)vm->code[vm->pc + 2] << 16)
                   | ((uint32_t)vm->code[vm->pc + 3] << 24);
    vm->pc += 4;
    return value;
}

/* Read a signed 32-bit operand */
static int32_t vm_read_int32(VM *vm) {
    return (int32_t)vm_read_uint32(vm);
}

/* =============================================================================
 * DEBUG/TRACE FUNCTIONS
 * =============================================================================
 * These functions help with debugging VM programs by printing the current
 * state of execution.
 */

/* Print the current stack contents */
static void vm_dump_stack(VM *vm) {
    printf("  Stack [%d]: ", vm->sp);
    if (vm->sp == 0) {
        printf("(empty)");
    } else {
        for (int i = 0; i < vm->sp && i < 10; i++) {
            printf("%d ", vm->stack[i]);
        }
        if (vm->sp > 10) {
            printf("... ");
        }
    }
    printf("\n");
}

/* Print information about the current instruction */
static void vm_trace_instruction(VM *vm, uint32_t addr, uint8_t opcode) {
    printf("[%04u] %-12s ", addr, opcode_info[opcode].name);
    
    /* Print operand if present */
    uint32_t operand_addr = addr + 1;
    int operand_size = opcode_info[opcode].operand_size;
    
    if (operand_size == 4 && operand_addr + 4 <= vm->code_size) {
        uint32_t operand = (uint32_t)vm->code[operand_addr]
                         | ((uint32_t)vm->code[operand_addr + 1] << 8)
                         | ((uint32_t)vm->code[operand_addr + 2] << 16)
                         | ((uint32_t)vm->code[operand_addr + 3] << 24);
        printf("%-10d ", (int32_t)operand);
    } else if (operand_size == 1 && operand_addr < vm->code_size) {
        printf("%-10u ", vm->code[operand_addr]);
    } else if (operand_size == -1) {
        /* String operand */
        printf("\"%s\" ", (char*)&vm->code[operand_addr]);
    } else {
        printf("%-10s ", "");
    }
}

/* =============================================================================
 * MAIN EXECUTION LOOP
 * =============================================================================
 * This is the heart of the VM - the fetch-decode-execute cycle. Each iteration:
 * 1. Fetches the opcode at the current PC
 * 2. Decodes it to determine the operation
 * 3. Executes the operation
 * 
 * The switch statement dispatches to the appropriate handler for each opcode.
 * In a production VM, you might use computed gotos or a jump table for better
 * performance, but a switch is clearest for learning.
 */

static void vm_run(VM *vm) {
    vm->running = true;
    vm->instruction_count = 0;
    
    while (vm->running && vm->pc < vm->code_size) {
        /* Save current PC for debugging before we modify it */
        uint32_t instruction_addr = vm->pc;
        
        /* FETCH: Read the opcode */
        uint8_t opcode = vm_read_byte(vm);
        
        /* Debug trace if enabled */
        if (vm->debug_mode) {
            vm_trace_instruction(vm, instruction_addr, opcode);
        }
        
        /* DECODE & EXECUTE: Handle each opcode */
        int32_t a, b, result;
        uint32_t addr;
        uint8_t index;
        
        switch (opcode) {
            /* ===== Stack Manipulation ===== */
            
            case OP_NOP:
                /* Do nothing - useful for padding or as placeholder */
                break;
                
            case OP_PUSH:
                /* Push immediate 32-bit value onto stack */
                result = vm_read_int32(vm);
                vm_push(vm, result);
                break;
                
            case OP_POP:
                /* Discard top of stack */
                vm_pop(vm, &a);
                break;
                
            case OP_DUP:
                /* Duplicate top of stack: (a -- a a) */
                if (vm_peek(vm, &a)) {
                    vm_push(vm, a);
                }
                break;
                
            case OP_SWAP:
                /* Swap top two values: (a b -- b a) */
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, b);
                    vm_push(vm, a);
                }
                break;
                
            case OP_OVER:
                /* Copy second value to top: (a b -- a b a) */
                if (vm_peek_at(vm, 1, &a)) {
                    vm_push(vm, a);
                }
                break;
                
            /* ===== Arithmetic Operations ===== */
            
            case OP_ADD:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a + b);
                }
                break;
                
            case OP_SUB:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a - b);
                }
                break;
                
            case OP_MUL:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a * b);
                }
                break;
                
            case OP_DIV:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    if (b == 0) {
                        vm_error(vm, VM_ERROR_DIVISION_BY_ZERO);
                    } else {
                        vm_push(vm, a / b);
                    }
                }
                break;
                
            case OP_MOD:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    if (b == 0) {
                        vm_error(vm, VM_ERROR_DIVISION_BY_ZERO);
                    } else {
                        vm_push(vm, a % b);
                    }
                }
                break;
                
            case OP_NEG:
                if (vm_pop(vm, &a)) {
                    vm_push(vm, -a);
                }
                break;
                
            case OP_INC:
                if (vm_pop(vm, &a)) {
                    vm_push(vm, a + 1);
                }
                break;
                
            case OP_DEC:
                if (vm_pop(vm, &a)) {
                    vm_push(vm, a - 1);
                }
                break;
                
            /* ===== Comparison Operations ===== */
            /* All comparisons push 1 for true, 0 for false */
            
            case OP_EQ:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a == b ? 1 : 0);
                }
                break;
                
            case OP_NE:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a != b ? 1 : 0);
                }
                break;
                
            case OP_LT:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a < b ? 1 : 0);
                }
                break;
                
            case OP_LE:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a <= b ? 1 : 0);
                }
                break;
                
            case OP_GT:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a > b ? 1 : 0);
                }
                break;
                
            case OP_GE:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a >= b ? 1 : 0);
                }
                break;
                
            /* ===== Logical Operations ===== */
            
            case OP_AND:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, (a && b) ? 1 : 0);
                }
                break;
                
            case OP_OR:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, (a || b) ? 1 : 0);
                }
                break;
                
            case OP_NOT:
                if (vm_pop(vm, &a)) {
                    vm_push(vm, a ? 0 : 1);
                }
                break;
                
            case OP_BAND:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a & b);
                }
                break;
                
            case OP_BOR:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a | b);
                }
                break;
                
            case OP_BNOT:
                if (vm_pop(vm, &a)) {
                    vm_push(vm, ~a);
                }
                break;
                
            case OP_XOR:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a ^ b);
                }
                break;
                
            case OP_SHL:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, a << b);
                }
                break;
                
            case OP_SHR:
                if (vm_pop(vm, &b) && vm_pop(vm, &a)) {
                    vm_push(vm, (int32_t)((uint32_t)a >> b));
                }
                break;
                
            /* ===== Control Flow ===== */
            
            case OP_JMP:
                /* Unconditional jump to address */
                addr = vm_read_uint32(vm);
                vm->pc = addr;
                break;
                
            case OP_JZ:
                /* Jump if top of stack is zero (false) */
                addr = vm_read_uint32(vm);
                if (vm_pop(vm, &a)) {
                    if (a == 0) {
                        vm->pc = addr;
                    }
                }
                break;
                
            case OP_JNZ:
                /* Jump if top of stack is non-zero (true) */
                addr = vm_read_uint32(vm);
                if (vm_pop(vm, &a)) {
                    if (a != 0) {
                        vm->pc = addr;
                    }
                }
                break;
                
            case OP_CALL:
                /*
                 * Call a function:
                 * 1. Read target address
                 * 2. Create new call frame
                 * 3. Save return address (current PC after reading operand)
                 * 4. Save current stack base
                 * 5. Jump to function
                 */
                addr = vm_read_uint32(vm);
                
                if (vm->fp >= CALL_STACK_SIZE - 1) {
                    vm_error(vm, VM_ERROR_CALL_STACK_OVERFLOW);
                    break;
                }
                
                vm->fp++;
                CallFrame *frame = &vm->call_stack[vm->fp];
                frame->return_addr = vm->pc;
                frame->stack_base = vm->sp;
                memset(frame->locals, 0, sizeof(frame->locals));
                
                vm->pc = addr;
                break;
                
            case OP_RET:
                /*
                 * Return from function:
                 * 1. Pop the call frame
                 * 2. Restore PC to return address
                 * 
                 * Note: We don't restore the stack pointer, allowing the
                 * function to leave a return value on the stack.
                 */
                if (vm->fp < 0) {
                    /* Return from main - halt execution */
                    vm->running = false;
                    break;
                }
                
                frame = &vm->call_stack[vm->fp];
                vm->pc = frame->return_addr;
                vm->fp--;
                break;
                
            /* ===== Variable Access ===== */
            
            case OP_LOAD_LOCAL:
                /* Push local variable value onto stack */
                index = vm_read_byte(vm);
                if (index >= LOCALS_SIZE) {
                    vm_error(vm, VM_ERROR_OUT_OF_BOUNDS);
                } else if (vm->fp >= 0) {
                    vm_push(vm, vm->call_stack[vm->fp].locals[index]);
                } else {
                    /* No active frame - use globals as fallback */
                    vm_push(vm, vm->globals[index]);
                }
                break;
                
            case OP_STORE_LOCAL:
                /* Pop stack and store in local variable */
                index = vm_read_byte(vm);
                if (index >= LOCALS_SIZE) {
                    vm_error(vm, VM_ERROR_OUT_OF_BOUNDS);
                } else if (vm_pop(vm, &a)) {
                    if (vm->fp >= 0) {
                        vm->call_stack[vm->fp].locals[index] = a;
                    } else {
                        vm->globals[index] = a;
                    }
                }
                break;
                
            case OP_LOAD_GLOBAL:
                /* Push global variable value onto stack */
                addr = vm_read_uint32(vm);
                if (addr >= GLOBALS_SIZE) {
                    vm_error(vm, VM_ERROR_OUT_OF_BOUNDS);
                } else {
                    vm_push(vm, vm->globals[addr]);
                }
                break;
                
            case OP_STORE_GLOBAL:
                /* Pop stack and store in global variable */
                addr = vm_read_uint32(vm);
                if (addr >= GLOBALS_SIZE) {
                    vm_error(vm, VM_ERROR_OUT_OF_BOUNDS);
                } else if (vm_pop(vm, &a)) {
                    vm->globals[addr] = a;
                }
                break;
                
            /* ===== I/O Operations ===== */
            
            case OP_PRINT:
                /* Pop and print as integer */
                if (vm_pop(vm, &a)) {
                    printf("%d\n", a);
                }
                break;
                
            case OP_PRINT_CHAR:
                /* Pop and print as ASCII character */
                if (vm_pop(vm, &a)) {
                    putchar(a);
                }
                break;
                
            case OP_PRINT_STR:
                /* Print inline string from bytecode */
                while (vm->pc < vm->code_size && vm->code[vm->pc] != 0) {
                    putchar(vm->code[vm->pc++]);
                }
                vm->pc++;  /* Skip null terminator */
                break;
                
            case OP_READ:
                /* Read integer from stdin */
                if (scanf("%d", &a) == 1) {
                    vm_push(vm, a);
                } else {
                    vm_push(vm, 0);  /* Default on read error */
                }
                break;
                
            /* ===== Special ===== */
            
            case OP_HALT:
                vm->running = false;
                break;
                
            case OP_DEBUG:
                vm_dump_stack(vm);
                break;
                
            default:
                vm_error(vm, VM_ERROR_INVALID_OPCODE);
                break;
        }
        
        /* Debug: print stack after instruction */
        if (vm->debug_mode && vm->running) {
            vm_dump_stack(vm);
        }
        
        vm->instruction_count++;
    }
}

/* =============================================================================
 * DISASSEMBLER
 * =============================================================================
 * Converts bytecode back to human-readable assembly. This is essential for
 * debugging and understanding what the VM will execute.
 */

static void disassemble(const uint8_t *code, uint32_t size) {
    printf("=== Disassembly ===\n");
    printf("Address  Opcode       Operand\n");
    printf("-------  -----------  ----------\n");
    
    uint32_t pc = 0;
    while (pc < size) {
        uint32_t addr = pc;
        uint8_t opcode = code[pc++];
        
        if (opcode >= OP_COUNT) {
            printf("%04u     ???          (invalid: 0x%02X)\n", addr, opcode);
            continue;
        }
        
        printf("%04u     %-12s ", addr, opcode_info[opcode].name);
        
        int operand_size = opcode_info[opcode].operand_size;
        
        if (operand_size == 4) {
            uint32_t operand = (uint32_t)code[pc]
                             | ((uint32_t)code[pc + 1] << 8)
                             | ((uint32_t)code[pc + 2] << 16)
                             | ((uint32_t)code[pc + 3] << 24);
            printf("%d", (int32_t)operand);
            pc += 4;
        } else if (operand_size == 1) {
            printf("%u", code[pc]);
            pc += 1;
        } else if (operand_size == -1) {
            /* String operand */
            printf("\"");
            while (pc < size && code[pc] != 0) {
                putchar(code[pc++]);
            }
            printf("\"");
            pc++;  /* Skip null terminator */
        }
        
        printf("\n");
    }
    printf("===================\n\n");
}

/* =============================================================================
 * ASSEMBLER
 * =============================================================================
 * Converts human-readable assembly text to bytecode. This is a two-pass
 * assembler:
 *   Pass 1: Collect label addresses
 *   Pass 2: Generate bytecode, resolving label references
 * 
 * Assembly syntax:
 *   - Instructions are one per line
 *   - Labels end with colon (e.g., "loop:")
 *   - Comments start with semicolon (;)
 *   - Operands follow the mnemonic, separated by whitespace
 *   - Labels can be used as operands for jump/call instructions
 */

typedef struct {
    char name[64];
    uint32_t address;
} Label;

typedef struct {
    Label labels[MAX_LABELS];
    int label_count;
    uint8_t code[CODE_SIZE];
    uint32_t code_size;
    int line_number;
    bool has_error;
} Assembler;

/* Find opcode by mnemonic name */
static int find_opcode(const char *name) {
    for (int i = 0; i < OP_COUNT; i++) {
        if (opcode_info[i].name && strcasecmp(name, opcode_info[i].name) == 0) {
            return i;
        }
    }
    return -1;
}

/* Find or create a label */
static Label* find_label(Assembler *as, const char *name) {
    for (int i = 0; i < as->label_count; i++) {
        if (strcmp(as->labels[i].name, name) == 0) {
            return &as->labels[i];
        }
    }
    return NULL;
}

static Label* add_label(Assembler *as, const char *name, uint32_t address) {
    if (as->label_count >= MAX_LABELS) {
        fprintf(stderr, "Error: Too many labels\n");
        as->has_error = true;
        return NULL;
    }
    
    Label *label = &as->labels[as->label_count++];
    strncpy(label->name, name, sizeof(label->name) - 1);
    label->name[sizeof(label->name) - 1] = '\0';
    label->address = address;
    return label;
}

/* Emit a single byte to the code buffer */
static void emit_byte(Assembler *as, uint8_t byte) {
    if (as->code_size >= CODE_SIZE) {
        fprintf(stderr, "Error: Code buffer overflow\n");
        as->has_error = true;
        return;
    }
    as->code[as->code_size++] = byte;
}

/* Emit a 32-bit value (little-endian) */
static void emit_uint32(Assembler *as, uint32_t value) {
    emit_byte(as, value & 0xFF);
    emit_byte(as, (value >> 8) & 0xFF);
    emit_byte(as, (value >> 16) & 0xFF);
    emit_byte(as, (value >> 24) & 0xFF);
}

/* 
 * Emit a string (including null terminator)
 * Note: This helper is provided for potential use by extensions or external callers.
 * The inline assembler uses direct byte emission for escape sequence handling.
 */
__attribute__((unused))
static void emit_string(Assembler *as, const char *str) {
    while (*str) {
        emit_byte(as, *str++);
    }
    emit_byte(as, 0);
}

/* Parse an operand - could be number or label reference */
static bool parse_operand(Assembler *as, const char *str, uint32_t *value, bool resolve_labels) {
    /* Skip whitespace */
    while (isspace(*str)) str++;
    
    /* Check if it's a number */
    char *endptr;
    long num = strtol(str, &endptr, 0);  /* 0 = auto-detect base (decimal, hex, octal) */
    
    if (endptr != str && (*endptr == '\0' || isspace(*endptr))) {
        *value = (uint32_t)num;
        return true;
    }
    
    /* Must be a label */
    if (resolve_labels) {
        Label *label = find_label(as, str);
        if (label) {
            *value = label->address;
            return true;
        }
        fprintf(stderr, "Error line %d: Undefined label '%s'\n", as->line_number, str);
        as->has_error = true;
        return false;
    } else {
        /* First pass - use placeholder */
        *value = 0;
        return true;
    }
}

/* Find character in string, but not inside quoted strings */
static char* find_outside_quotes(char *str, char c) {
    bool in_quotes = false;
    char *start = str;
    while (*str) {
        if (*str == '"' && (str == start || *(str-1) != '\\')) {
            in_quotes = !in_quotes;
        } else if (*str == c && !in_quotes) {
            return str;
        }
        str++;
    }
    return NULL;
}

/* Trim whitespace and comments from line */
static char* trim_line(char *line) {
    /* Remove comment (but not ; inside quotes) */
    char *comment = find_outside_quotes(line, ';');
    if (comment) *comment = '\0';
    
    /* Trim leading whitespace */
    while (isspace(*line)) line++;
    
    /* Trim trailing whitespace */
    int len = strlen(line);
    while (len > 0 && isspace(line[len - 1])) {
        line[--len] = '\0';
    }
    
    return line;
}

/* Assemble a single line */
static void assemble_line(Assembler *as, char *line, bool pass2) {
    line = trim_line(line);
    
    /* Skip empty lines */
    if (line[0] == '\0') return;
    
    /* Check for label definition - colon must be before any quotes */
    char *quote = strchr(line, '"');
    char *colon = strchr(line, ':');
    
    /* Only treat as label if colon appears before any quoted string */
    if (colon && (!quote || colon < quote)) {
        /* Verify the label name contains only valid characters (alphanumeric + underscore) */
        bool valid_label = true;
        for (char *p = line; p < colon; p++) {
            if (!isalnum(*p) && *p != '_') {
                valid_label = false;
                break;
            }
        }
        
        if (valid_label && colon > line) {
            /* Extract label name */
            char label_name[64];
            int label_len = colon - line;
            if (label_len >= (int)sizeof(label_name)) {
                label_len = sizeof(label_name) - 1;
            }
            strncpy(label_name, line, label_len);
            label_name[label_len] = '\0';
            
            /* In pass 1, record the label */
            if (!pass2) {
                if (find_label(as, label_name)) {
                    fprintf(stderr, "Error line %d: Duplicate label '%s'\n", 
                            as->line_number, label_name);
                    as->has_error = true;
                } else {
                    add_label(as, label_name, as->code_size);
                }
            }
            
            /* Continue parsing after the colon */
            line = colon + 1;
            while (isspace(*line)) line++;
            if (line[0] == '\0') return;
        }
    }
    
    /* Parse instruction mnemonic */
    char mnemonic[32];
    char operand[MAX_LINE_LEN];
    operand[0] = '\0';
    
    int matched = sscanf(line, "%31s %255[^\n]", mnemonic, operand);
    if (matched < 1) return;
    
    /* Find the opcode */
    int opcode = find_opcode(mnemonic);
    if (opcode < 0) {
        fprintf(stderr, "Error line %d: Unknown instruction '%s'\n", 
                as->line_number, mnemonic);
        as->has_error = true;
        return;
    }
    
    /* Emit opcode */
    emit_byte(as, (uint8_t)opcode);
    
    /* Emit operand if needed */
    int operand_size = opcode_info[opcode].operand_size;
    
    if (operand_size == 4) {
        uint32_t value = 0;
        if (matched < 2 || operand[0] == '\0') {
            fprintf(stderr, "Error line %d: %s requires an operand\n", 
                    as->line_number, mnemonic);
            as->has_error = true;
            emit_uint32(as, 0);
        } else {
            parse_operand(as, operand, &value, pass2);
            emit_uint32(as, value);
        }
    } else if (operand_size == 1) {
        uint32_t value = 0;
        if (matched < 2 || operand[0] == '\0') {
            fprintf(stderr, "Error line %d: %s requires an operand\n", 
                    as->line_number, mnemonic);
            as->has_error = true;
            emit_byte(as, 0);
        } else {
            parse_operand(as, operand, &value, pass2);
            emit_byte(as, (uint8_t)value);
        }
    } else if (operand_size == -1) {
        /* String operand - extract quoted string */
        char *start = strchr(operand, '"');
        char *end = start ? strrchr(operand, '"') : NULL;
        if (start && end && end > start) {
            start++;
            *end = '\0';
            /* Process escape sequences */
            char *src = start;
            while (*src) {
                if (*src == '\\' && *(src + 1)) {
                    src++;
                    switch (*src) {
                        case 'n': emit_byte(as, '\n'); break;
                        case 't': emit_byte(as, '\t'); break;
                        case 'r': emit_byte(as, '\r'); break;
                        case '\\': emit_byte(as, '\\'); break;
                        case '"': emit_byte(as, '"'); break;
                        default: emit_byte(as, *src); break;
                    }
                } else {
                    emit_byte(as, *src);
                }
                src++;
            }
            emit_byte(as, 0);  /* Null terminator */
        } else {
            fprintf(stderr, "Error line %d: Expected quoted string\n", as->line_number);
            as->has_error = true;
            emit_byte(as, 0);
        }
    }
}

/* Assemble a complete program from source text */
static bool assemble(const char *source, uint8_t *code, uint32_t *code_size) {
    Assembler as;
    memset(&as, 0, sizeof(as));
    
    /* Make a copy of source for parsing (strtok modifies the string) */
    char *source_copy = strdup(source);
    if (!source_copy) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return false;
    }
    
    /* Pass 1: Collect labels */
    as.line_number = 0;
    char *line = strtok(source_copy, "\n");
    while (line) {
        as.line_number++;
        assemble_line(&as, line, false);
        if (as.has_error) {
            free(source_copy);
            return false;
        }
        line = strtok(NULL, "\n");
    }
    
    /* Pass 2: Generate final code with resolved labels */
    free(source_copy);
    source_copy = strdup(source);
    if (!source_copy) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return false;
    }
    
    as.code_size = 0;  /* Reset for pass 2 */
    as.line_number = 0;
    line = strtok(source_copy, "\n");
    while (line) {
        as.line_number++;
        assemble_line(&as, line, true);
        if (as.has_error) {
            free(source_copy);
            return false;
        }
        line = strtok(NULL, "\n");
    }
    
    free(source_copy);
    
    /* Copy result */
    memcpy(code, as.code, as.code_size);
    *code_size = as.code_size;
    
    printf("Assembly successful: %u bytes\n", as.code_size);
    return true;
}

/* =============================================================================
 * EXAMPLE PROGRAMS
 * =============================================================================
 * These functions create example bytecode programs to demonstrate the VM.
 */

/* 
 * Example 1: Recursive Factorial
 * 
 * This implements the classic recursive factorial function:
 *   factorial(n) = 1 if n <= 1
 *                = n * factorial(n-1) otherwise
 *
 * Assembly equivalent:
 *   main:
 *       PUSH 10          ; Calculate 10!
 *       CALL factorial
 *       PRINT            ; Print result
 *       HALT
 *   
 *   factorial:
 *       STORE_LOCAL 0    ; Save n in local 0
 *       LOAD_LOCAL 0     ; Load n
 *       PUSH 1
 *       LE               ; n <= 1?
 *       JNZ base_case
 *       
 *       LOAD_LOCAL 0     ; Load n
 *       LOAD_LOCAL 0     ; Load n again
 *       PUSH 1
 *       SUB              ; n - 1
 *       CALL factorial   ; factorial(n-1)
 *       MUL              ; n * factorial(n-1)
 *       RET
 *       
 *   base_case:
 *       PUSH 1           ; Return 1
 *       RET
 */
static const char *factorial_source = 
    "; Recursive factorial program\n"
    "; Calculates n! for n = 10\n"
    "\n"
    "main:\n"
    "    PRINT_STR \"Calculating 10! (factorial)...\\n\"\n"
    "    PUSH 10              ; n = 10\n"
    "    CALL factorial       ; Call factorial function\n"
    "    PRINT                ; Print result\n"
    "    PRINT_STR \"Done!\\n\"\n"
    "    HALT\n"
    "\n"
    "; factorial(n) - returns n!\n"
    "; Input: n on top of stack\n"
    "; Output: n! on top of stack\n"
    "factorial:\n"
    "    STORE_LOCAL 0        ; Save n in local 0\n"
    "    LOAD_LOCAL 0         ; Load n\n"
    "    PUSH 1\n"
    "    LE                   ; n <= 1?\n"
    "    JNZ base_case        ; If so, go to base case\n"
    "    \n"
    "    ; Recursive case: n * factorial(n-1)\n"
    "    LOAD_LOCAL 0         ; Load n\n"
    "    LOAD_LOCAL 0         ; Load n again for argument\n"
    "    PUSH 1\n"
    "    SUB                  ; n - 1\n"
    "    CALL factorial       ; factorial(n-1)\n"
    "    MUL                  ; n * factorial(n-1)\n"
    "    RET\n"
    "    \n"
    "base_case:\n"
    "    PUSH 1               ; factorial(0) = factorial(1) = 1\n"
    "    RET\n";

/*
 * Example 2: Fibonacci sequence
 * 
 * Iterative implementation that prints first N Fibonacci numbers.
 */
static const char *fibonacci_source =
    "; Fibonacci sequence generator\n"
    "; Prints first 15 Fibonacci numbers\n"
    "\n"
    "start:\n"
    "    PRINT_STR \"Fibonacci sequence:\\n\"\n"
    "    \n"
    "    ; Initialize: a=0, b=1, count=15\n"
    "    PUSH 0\n"
    "    STORE_GLOBAL 0       ; a = 0 (fib[n-2])\n"
    "    PUSH 1\n"
    "    STORE_GLOBAL 1       ; b = 1 (fib[n-1])\n"
    "    PUSH 15\n"
    "    STORE_GLOBAL 2       ; count = 15\n"
    "    \n"
    "loop:\n"
    "    ; Print current value (a)\n"
    "    LOAD_GLOBAL 0\n"
    "    PRINT\n"
    "    \n"
    "    ; Calculate next: temp = a + b\n"
    "    LOAD_GLOBAL 0\n"
    "    LOAD_GLOBAL 1\n"
    "    ADD\n"
    "    STORE_GLOBAL 3       ; temp = a + b\n"
    "    \n"
    "    ; Shift: a = b, b = temp\n"
    "    LOAD_GLOBAL 1\n"
    "    STORE_GLOBAL 0       ; a = b\n"
    "    LOAD_GLOBAL 3\n"
    "    STORE_GLOBAL 1       ; b = temp\n"
    "    \n"
    "    ; Decrement counter\n"
    "    LOAD_GLOBAL 2\n"
    "    DEC\n"
    "    DUP\n"
    "    STORE_GLOBAL 2       ; count--\n"
    "    JNZ loop             ; Loop if count > 0\n"
    "    \n"
    "    PRINT_STR \"Done!\\n\"\n"
    "    HALT\n";

/*
 * Example 3: Nested function calls with local variables
 *
 * Demonstrates call stack behavior with multiple active frames.
 */
static const char *nested_calls_source =
    "; Demonstrates nested function calls\n"
    "; Each function has its own local variables\n"
    "\n"
    "main:\n"
    "    PRINT_STR \"Testing nested calls...\\n\"\n"
    "    PUSH 5\n"
    "    CALL outer\n"
    "    PRINT_STR \"Final result: \"\n"
    "    PRINT\n"
    "    HALT\n"
    "\n"
    "; outer(x) returns inner(x) + x\n"
    "outer:\n"
    "    STORE_LOCAL 0        ; Save x\n"
    "    PRINT_STR \"outer called with: \"\n"
    "    LOAD_LOCAL 0\n"
    "    PRINT\n"
    "    \n"
    "    LOAD_LOCAL 0         ; Push x for inner call\n"
    "    CALL inner           ; Call inner(x)\n"
    "    LOAD_LOCAL 0         ; Push x again\n"
    "    ADD                  ; inner(x) + x\n"
    "    RET\n"
    "\n"
    "; inner(y) returns y * 2\n"
    "inner:\n"
    "    STORE_LOCAL 0        ; Save y\n"
    "    PRINT_STR \"  inner called with: \"\n"
    "    LOAD_LOCAL 0\n"
    "    PRINT\n"
    "    \n"
    "    LOAD_LOCAL 0\n"
    "    PUSH 2\n"
    "    MUL                  ; y * 2\n"
    "    \n"
    "    PRINT_STR \"  inner returning: \"\n"
    "    DUP\n"
    "    PRINT\n"
    "    RET\n";

/*
 * Example 4: Simple arithmetic and comparisons
 */
static const char *arithmetic_source =
    "; Arithmetic and comparison demo\n"
    "\n"
    "    PRINT_STR \"=== Arithmetic Demo ===\\n\"\n"
    "    \n"
    "    ; Addition\n"
    "    PRINT_STR \"10 + 25 = \"\n"
    "    PUSH 10\n"
    "    PUSH 25\n"
    "    ADD\n"
    "    PRINT\n"
    "    \n"
    "    ; Subtraction\n"
    "    PRINT_STR \"100 - 37 = \"\n"
    "    PUSH 100\n"
    "    PUSH 37\n"
    "    SUB\n"
    "    PRINT\n"
    "    \n"
    "    ; Multiplication\n"
    "    PRINT_STR \"7 * 8 = \"\n"
    "    PUSH 7\n"
    "    PUSH 8\n"
    "    MUL\n"
    "    PRINT\n"
    "    \n"
    "    ; Division\n"
    "    PRINT_STR \"99 / 9 = \"\n"
    "    PUSH 99\n"
    "    PUSH 9\n"
    "    DIV\n"
    "    PRINT\n"
    "    \n"
    "    ; Modulo\n"
    "    PRINT_STR \"17 %% 5 = \"\n"
    "    PUSH 17\n"
    "    PUSH 5\n"
    "    MOD\n"
    "    PRINT\n"
    "    \n"
    "    ; Comparison\n"
    "    PRINT_STR \"5 < 10 = \"\n"
    "    PUSH 5\n"
    "    PUSH 10\n"
    "    LT\n"
    "    PRINT\n"
    "    \n"
    "    PRINT_STR \"5 > 10 = \"\n"
    "    PUSH 5\n"
    "    PUSH 10\n"
    "    GT\n"
    "    PRINT\n"
    "    \n"
    "    PRINT_STR \"=== Done ===\\n\"\n"
    "    HALT\n";

/* =============================================================================
 * MAIN FUNCTION
 * =============================================================================
 * Entry point demonstrating the VM capabilities.
 */

static void print_usage(const char *program) {
    printf("Bytecode Virtual Machine\n");
    printf("========================\n\n");
    printf("Usage: %s [options] [program]\n\n", program);
    printf("Programs:\n");
    printf("  factorial   - Recursive factorial (10!)\n");
    printf("  fibonacci   - Fibonacci sequence (first 15 numbers)\n");
    printf("  nested      - Nested function call demo\n");
    printf("  arithmetic  - Arithmetic operations demo\n");
    printf("  all         - Run all demo programs\n");
    printf("\nOptions:\n");
    printf("  -d, --debug    Enable instruction tracing\n");
    printf("  -h, --help     Show this help\n");
}

static void run_program(const char *name, const char *source, bool debug) {
    printf("\n");
    printf("========================================\n");
    printf("Running: %s\n", name);
    printf("========================================\n\n");
    
    VM vm;
    vm_init(&vm);
    vm.debug_mode = debug;
    
    /* Assemble the program */
    if (!assemble(source, vm.code, &vm.code_size)) {
        fprintf(stderr, "Assembly failed!\n");
        return;
    }
    
    /* Show disassembly */
    printf("\n");
    disassemble(vm.code, vm.code_size);
    
    /* Run the program */
    printf("=== Execution ===\n");
    vm_run(&vm);
    
    /* Show statistics */
    printf("\n=== Statistics ===\n");
    printf("Instructions executed: %llu\n", (unsigned long long)vm.instruction_count);
    printf("Final stack pointer: %d\n", vm.sp);
    printf("==================\n");
}

int main(int argc, char *argv[]) {
    bool debug = false;
    const char *program = "all";
    
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            debug = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            program = argv[i];
        }
    }
    
    printf("Bytecode Virtual Machine Interpreter\n");
    printf("====================================\n");
    printf("Stack size: %d entries\n", STACK_SIZE);
    printf("Call stack: %d frames\n", CALL_STACK_SIZE);
    printf("Locals per frame: %d\n", LOCALS_SIZE);
    printf("Global variables: %d\n", GLOBALS_SIZE);
    printf("Code buffer: %d bytes\n", CODE_SIZE);
    printf("Total opcodes: %d\n", OP_COUNT);
    printf("Debug mode: %s\n", debug ? "ON" : "OFF");
    
    /* Run selected program(s) */
    if (strcmp(program, "factorial") == 0) {
        run_program("Recursive Factorial", factorial_source, debug);
    } else if (strcmp(program, "fibonacci") == 0) {
        run_program("Fibonacci Sequence", fibonacci_source, debug);
    } else if (strcmp(program, "nested") == 0) {
        run_program("Nested Function Calls", nested_calls_source, debug);
    } else if (strcmp(program, "arithmetic") == 0) {
        run_program("Arithmetic Demo", arithmetic_source, debug);
    } else if (strcmp(program, "all") == 0) {
        run_program("Arithmetic Demo", arithmetic_source, debug);
        run_program("Recursive Factorial", factorial_source, debug);
        run_program("Fibonacci Sequence", fibonacci_source, debug);
        run_program("Nested Function Calls", nested_calls_source, debug);
    } else {
        fprintf(stderr, "Unknown program: %s\n", program);
        print_usage(argv[0]);
        return 1;
    }
    
    printf("\n=== All programs completed ===\n");
    return 0;
}

/*
 * =============================================================================
 * COMPILATION AND TESTING
 * =============================================================================
 * 
 * To compile:
 *   gcc -o bytecode_vm 09_bytecode_vm.c -Wall -Wextra -O2
 * 
 * To run:
 *   ./bytecode_vm              # Run all demos
 *   ./bytecode_vm factorial    # Run factorial demo
 *   ./bytecode_vm -d fibonacci # Run fibonacci with instruction tracing
 * 
 * =============================================================================
 * ARCHITECTURE NOTES
 * =============================================================================
 * 
 * 1. STACK-BASED VS REGISTER-BASED VMs:
 *    This VM uses a stack-based architecture (like JVM, Python, WebAssembly).
 *    The alternative is register-based (like Lua, Dalvik/ART).
 *    
 *    Stack-based pros:
 *    - Simpler instruction encoding (no register allocation)
 *    - Smaller bytecode (no register operands needed)
 *    - Easier to generate code for
 *    
 *    Stack-based cons:
 *    - More instructions needed (more stack manipulation)
 *    - Harder to optimize (values aren't named)
 *    - More memory traffic (stack operations)
 * 
 * 2. BYTECODE FORMAT:
 *    Our format is simple: 1-byte opcode + optional operands.
 *    Production VMs might use:
 *    - Variable-length opcodes (like x86)
 *    - Constant pools (like JVM) for strings/large numbers
 *    - Line number tables for debugging
 *    - Exception tables for try/catch
 * 
 * 3. CALL CONVENTION:
 *    Our calling convention:
 *    - Arguments passed on the stack
 *    - Return value left on stack
 *    - Callee saves all locals (they're in the frame)
 *    
 *    More sophisticated VMs might use:
 *    - Argument count in bytecode
 *    - Named parameters
 *    - Variable argument lists
 *    - Multiple return values
 * 
 * 4. POSSIBLE EXTENSIONS:
 *    - Garbage collection for dynamic memory
 *    - Object/class system
 *    - Exception handling (try/catch)
 *    - Closures and first-class functions
 *    - JIT compilation for hot paths
 *    - Debugging support (breakpoints, stepping)
 *    - Constant pools for large values
 *    - Type information for verification
 * 
 * =============================================================================
 */
