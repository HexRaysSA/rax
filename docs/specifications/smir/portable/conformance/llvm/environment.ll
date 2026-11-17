; Platform-specific opaque integer width selected by LLVM-CC027 is i64.
declare i64 @llvm.get.fpenv.i64()
declare void @llvm.set.fpenv.i64(i64)
declare i64 @llvm.get.fpmode.i64()
declare void @llvm.set.fpmode.i64(i64)
declare i32 @llvm.get.rounding()
declare void @llvm.set.rounding(i32)
define i64 @preserve_env() strictfp {
  %environment = call i64 @llvm.get.fpenv.i64()
  call void @llvm.set.fpenv.i64(i64 %environment)
  %mode = call i64 @llvm.get.fpmode.i64()
  call void @llvm.set.fpmode.i64(i64 %mode)
  %round = call i32 @llvm.get.rounding()
  call void @llvm.set.rounding(i32 %round)
  ret i64 %environment
}
