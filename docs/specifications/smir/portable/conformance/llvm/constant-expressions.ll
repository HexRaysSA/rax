; Actual LLVM24 retained symbolic constant expressions. Not executable SMIR.
target triple = "x86_64-unknown-linux-gnu"
@a = external global i8
@b = external global i8
declare void @f()
@difference = global i64 sub (i64 ptrtoint (ptr @a to i64), i64 ptrtoint (ptr @b to i64))
@sum = global i64 add (i64 ptrtoint (ptr @a to i64), i64 ptrtoint (ptr @b to i64))
@xor_bits = global i64 xor (i64 ptrtoint (ptr @a to i64), i64 ptrtoint (ptr @b to i64))
@truncated = global i7 trunc (i64 ptrtoint (ptr @a to i64) to i7)
@address = global i64 ptrtoaddr (ptr @a to i64)
@pointer = global ptr inttoptr (i64 17 to ptr)
@vector = global <2 x i64> <i64 ptrtoint (ptr @a to i64), i64 ptrtoint (ptr @b to i64)>
@symbolic_gep_index = global ptr getelementptr inbounds (i64, ptr @a, i128 ptrtoint (ptr @b to i128))
@local_equivalent = global ptr dso_local_equivalent @f
@without_cfi_jump_table = global ptr no_cfi @f
