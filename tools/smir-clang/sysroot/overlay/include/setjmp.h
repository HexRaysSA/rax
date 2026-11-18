// Non-local jumps. The compiler makes them ordinary control flow (see
// tools/smir-clang/jumps.cpp): a buffer holds no registers, only which
// activation called `setjmp` and which of its calls it was.
#ifndef SMIR_SYSROOT_SETJMP_H
#define SMIR_SYSROOT_SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif

struct __smir_jump {
  void *__frame;
  int __site;
};

typedef struct __smir_jump jmp_buf[1];
typedef struct __smir_jump sigjmp_buf[1];

int setjmp(jmp_buf) __attribute__((__returns_twice__));
int _setjmp(jmp_buf) __attribute__((__returns_twice__));
// There are no signals whose mask could be saved.
int sigsetjmp(sigjmp_buf, int) __attribute__((__returns_twice__));

__attribute__((__noreturn__)) void longjmp(jmp_buf, int);
__attribute__((__noreturn__)) void _longjmp(jmp_buf, int);
__attribute__((__noreturn__)) void siglongjmp(sigjmp_buf, int);

// C wants `setjmp` to be a macro.
#define setjmp(buffer) setjmp(buffer)

#ifdef __cplusplus
}
#endif

#endif
