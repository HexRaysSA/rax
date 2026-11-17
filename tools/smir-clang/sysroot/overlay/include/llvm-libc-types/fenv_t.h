// The floating-point environment of the smir64 target, in place of LLVM
// libc's own header, which knows no architecture-independent layout.
//
// It is the 32-byte snapshot of the execution chapter: a revision, the
// rounding mode, the sticky flags and the trap mask, then two reserved
// 64-bit fields.
#ifndef LLVM_LIBC_TYPES_FENV_T_H
#define LLVM_LIBC_TYPES_FENV_T_H

typedef struct {
  unsigned int __revision;
  unsigned int __round;
  unsigned int __flags;
  unsigned int __traps;
  unsigned long long __control;
  unsigned long long __reserved;
} fenv_t;

#endif // LLVM_LIBC_TYPES_FENV_T_H
