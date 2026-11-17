; Pinned constrained powi exponent is fixed i32, unlike ordinary anyint powi.
declare double @llvm.experimental.constrained.powi.f64(double, i32, metadata, metadata)
define double @strict_power(double %base, i32 %exponent) strictfp {
  %result = call double @llvm.experimental.constrained.powi.f64(double %base, i32 %exponent, metadata !"round.dynamic", metadata !"fpexcept.strict")
  ret double %result
}
