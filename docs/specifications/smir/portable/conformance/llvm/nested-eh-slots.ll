; Compiler-private preoptimization grammar. Independent expected file follows.
; No opaque memory or native unwinding execution is claimed.
target triple = "x86_64-unknown-linux-gnu"
declare void @outer_raise()
declare void @inner_raise()
declare i32 @portable_personality(...)
declare target("smir.exception") @__smir_eh_slot_get(i32)
declare void @__smir_eh_slot_set(i32, target("smir.exception"))
declare void @opaque_observe(target("smir.exception"))
define target("smir.exception") @nested_exception_slots() personality ptr @portable_personality !smir.eh.slots !0 {
entry:
  invoke void @outer_raise() to label %impossible unwind label %outer
impossible:
  unreachable
outer:
  %outer_pair = landingpad { target("smir.exception"), i32 } cleanup
  %outer_exception = extractvalue { target("smir.exception"), i32 } %outer_pair, 0
  call void @__smir_eh_slot_set(i32 0, target("smir.exception") %outer_exception)
  invoke void @inner_raise() to label %outer_resume unwind label %inner
inner:
  %inner_pair = landingpad { target("smir.exception"), i32 } cleanup
  %inner_exception = extractvalue { target("smir.exception"), i32 } %inner_pair, 0
  call void @__smir_eh_slot_set(i32 1, target("smir.exception") %inner_exception)
  %caught_inner = call target("smir.exception") @__smir_eh_slot_get(i32 1)
  call void @opaque_observe(target("smir.exception") %caught_inner)
  br label %outer_resume
outer_resume:
  %restored_outer = call target("smir.exception") @__smir_eh_slot_get(i32 0)
  ret target("smir.exception") %restored_outer
}
!0 = !{i32 1, i32 0, i32 1}
