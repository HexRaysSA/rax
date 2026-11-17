; Pinned overload witness. The wide powi constant exposes a pinned optimizer gap.
declare double @llvm.powi.f64.i64(double, i64)
declare double @llvm.ldexp.f64.i64(double, i64)
declare { double, i8 } @llvm.frexp.f64.i8(double)
define double @pow_wide() {
  %v = call double @llvm.powi.f64.i64(double 2.0, i64 4294967296)
  ret double %v
}
define double @scale_wide() {
  %v = call double @llvm.ldexp.f64.i64(double 0.0, i64 9223372036854775807)
  ret double %v
}
define i8 @frexp_narrow() {
  %v = call {double, i8} @llvm.frexp.f64.i8(double 1.0e300)
  %e = extractvalue {double, i8} %v, 1
  ret i8 %e
}
