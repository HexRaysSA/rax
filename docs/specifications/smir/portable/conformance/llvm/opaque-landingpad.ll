; LLVM-only accepted result type witness. No portable emission or EH execution.
target triple = "x86_64-unknown-linux-gnu"
declare void @may_raise()
declare i32 @portable_personality(...)
define target("smir.exception") @opaque_landingpad() personality ptr @portable_personality {
entry:
  invoke void @may_raise() to label %normal unwind label %exceptional
normal:
  unreachable
exceptional:
  %pair = landingpad { target("smir.exception"), i32 } cleanup
  %exception = extractvalue { target("smir.exception"), i32 } %pair, 0
  ret target("smir.exception") %exception
}
