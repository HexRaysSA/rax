; Identical final offsets do not imply identical original GEP promises.
define ptr @wide_bad(ptr %base) {
  %p = getelementptr nuw i8, ptr %base, i65 18446744073709551616
  ret ptr %p
}
define ptr @wide_good(ptr %base) {
  %p = getelementptr nuw i8, ptr %base, i65 0
  ret ptr %p
}
define ptr @multiply_bad(ptr %base) {
  %p = getelementptr nuw i64, ptr %base, i64 2305843009213693952
  ret ptr %p
}
