; Pinned LLVM IR permits a stronger failure ordering. This is an IR witness,
; not a C source claim about __c11_atomic_compare_exchange preconditions.
define {i32,i1} @stronger_failure(ptr %p, i32 %old, i32 %new) {
  %r = cmpxchg ptr %p, i32 %old, i32 %new acquire seq_cst
  ret {i32,i1} %r
}
