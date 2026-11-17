; Independent optimizer witnesses. No SMIR execution or backend emission.
define i8 @unused_poison() {
  %unused = add nsw i8 127, 1
  ret i8 7
}
define i8 @unselected_poison() {
  %r = select i1 false, i8 poison, i8 9
  ret i8 %r
}
define i8 @freeze_identity() {
  %x = freeze i8 poison
  %r = xor i8 %x, %x
  ret i8 %r
}
define i8 @signed_remainder() {
  %r = srem i8 -7, 3
  ret i8 %r
}
define i8 @signed_quotient() {
  %r = sdiv i8 -7, 3
  ret i8 %r
}
define i8 @wrap_add() {
  %r = add i8 255, 1
  ret i8 %r
}
define i8 @overshift_is_deferred() {
  %unused = shl i8 1, 8
  ret i8 11
}
define i8 @lane_poison_barrier() {
  %v = select <2 x i1> <i1 false, i1 true>, <2 x i8> <i8 poison, i8 13>, <2 x i8> <i8 5, i8 poison>
  %r = extractelement <2 x i8> %v, i32 1
  ret i8 %r
}
define i8 @unselected_undef() {
  %r = select i1 true, i8 17, i8 undef
  ret i8 %r
}
define i8 @exact_is_deferred() {
  %unused = udiv exact i8 10, 3
  ret i8 19
}
