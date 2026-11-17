declare target("smir.journal") @__rax_primitive_claim(ptr)
declare void @__rax_primitive_step(target("smir.journal"), i32, i64)
define void @opaque_transport(ptr %object, i1 %condition) {
  %journal = call target("smir.journal") @__rax_primitive_claim(ptr %object)
  %copy = select i1 %condition, target("smir.journal") %journal, target("smir.journal") %journal
  call void @__rax_primitive_step(target("smir.journal") %copy, i32 1, i64 0)
  ret void
}
