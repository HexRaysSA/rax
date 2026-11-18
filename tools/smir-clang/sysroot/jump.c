// What <setjmp.h> names, before the compiler has made a program's jumps
// control flow (tools/smir-clang/jumps.cpp), and the note of a jump on its
// way, which the code the compiler adds reads.
//
// The header is not included: it says of `longjmp` that it does not return,
// and here it does. It notes the jump; the call of it goes on to where the
// jump is looked at.

struct __smir_jump {
  void *frame;
  int site;
};

// Where a jump on its way goes: the buffer `setjmp` wrote. Null if none is.
__thread struct __smir_jump *__smir_jump_target;
// What `setjmp` yields when the jump arrives.
__thread int __smir_jump_value;

void longjmp(struct __smir_jump *buffer, int value) {
  __smir_jump_target = buffer;
  // A jump never makes `setjmp` yield zero.
  __smir_jump_value = value ? value : 1;
}

void _longjmp(struct __smir_jump *buffer, int value) { longjmp(buffer, value); }
void siglongjmp(struct __smir_jump *buffer, int value) { longjmp(buffer, value); }

// A call the compiler has not replaced is one in a program without
// `longjmp`: it yields zero, once.
int setjmp(struct __smir_jump *buffer) {
  (void)buffer;
  return 0;
}

int _setjmp(struct __smir_jump *buffer) { return setjmp(buffer); }

int sigsetjmp(struct __smir_jump *buffer, int mask) {
  (void)mask;
  return setjmp(buffer);
}
