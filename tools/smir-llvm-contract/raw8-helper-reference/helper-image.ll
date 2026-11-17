target datalayout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1"
target triple = "smir64-unknown-rax"
@site = private constant [1 x i8] zeroinitializer
declare target("smir.raw_byte") @__rax_draft_raw_load8(ptr, ptr) addrspace(1) #0
declare void @__rax_draft_raw_store8(ptr, ptr, target("smir.raw_byte")) addrspace(1) #0
declare i8 @__rax_draft_raw_observe8(ptr, target("smir.raw_byte")) addrspace(1) #0
declare target("smir.raw_byte") @__rax_draft_raw_from_int8(i8) addrspace(1) #2
declare target("smir.raw_byte") @__rax_draft_raw_freeze8(ptr, target("smir.raw_byte")) addrspace(1) #0
declare { target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte") } @__rax_draft_raw_split_code64(ptr, ptr addrspace(1)) addrspace(1) #0
declare ptr addrspace(1) @__rax_draft_raw_join_code64(ptr, { target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte") }) addrspace(1) #0
define void @all_images(ptr %p, ptr addrspace(1) %code) addrspace(1) #1 {
 %r = call addrspace(1) target("smir.raw_byte") @__rax_draft_raw_load8(ptr @site, ptr %p)
 call addrspace(1) void @__rax_draft_raw_store8(ptr @site, ptr %p, target("smir.raw_byte") %r)
 %i = call addrspace(1) i8 @__rax_draft_raw_observe8(ptr @site, target("smir.raw_byte") %r)
 %n = call addrspace(1) target("smir.raw_byte") @__rax_draft_raw_from_int8(i8 %i)
 %f = call addrspace(1) target("smir.raw_byte") @__rax_draft_raw_freeze8(ptr @site, target("smir.raw_byte") %n)
 %v = call addrspace(1) { target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte") } @__rax_draft_raw_split_code64(ptr @site, ptr addrspace(1) %code)
 %a = call addrspace(1) ptr addrspace(1) @__rax_draft_raw_join_code64(ptr @site, { target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte"), target("smir.raw_byte") } %v)
 ret void
}
attributes #0 = { nounwind nocallback convergent noduplicate memory(readwrite) }
attributes #1 = { noinline optnone }
attributes #2 = { nounwind nocallback nosync willreturn speculatable memory(none) }
