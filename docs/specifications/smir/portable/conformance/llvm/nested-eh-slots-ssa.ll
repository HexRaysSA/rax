; Independent expected SSA form of the closed compiler-private slot witness.
; No opaque memory or native unwinding execution is claimed.
target triple = "x86_64-unknown-linux-gnu"
declare void @outer_raise()
declare void @inner_raise()
declare i32 @portable_personality(...)
declare void @opaque_observe(target("smir.exception"))
define target("smir.exception") @nested_exception_slots() personality ptr @portable_personality {
entry:
  invoke void @outer_raise() to label %impossible unwind label %outer
impossible:
  unreachable
outer:
  %outer_pair = landingpad { target("smir.exception"), i32 } cleanup
  %outer_exception = extractvalue { target("smir.exception"), i32 } %outer_pair, 0
  invoke void @inner_raise() to label %outer_resume unwind label %inner
inner:
  %inner_pair = landingpad { target("smir.exception"), i32 } cleanup
  %inner_exception = extractvalue { target("smir.exception"), i32 } %inner_pair, 0
  call void @opaque_observe(target("smir.exception") %inner_exception)
  br label %outer_resume
outer_resume:
  ret target("smir.exception") %outer_exception
}
