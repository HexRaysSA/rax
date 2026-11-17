; Hand-authored LLVM24 byte-provenance witness, no production SMIR emission.
define b128 @raw_copy(ptr %dst, ptr %src) {
  %bits = load b128, ptr %src, align 1
  store b128 %bits, ptr %dst, align 1
  %f = freeze b128 %bits
  ret b128 %f
}
