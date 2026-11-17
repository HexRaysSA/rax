target datalayout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1"
target triple = "smir64-unknown-rax"
declare void @decl() addrspace(1)
define ptr addrspace(1) @transport(ptr %slot, i1 %condition) addrspace(1) {
entry:
  store ptr addrspace(1) @decl, ptr %slot, align 8
  %loaded = load ptr addrspace(1), ptr %slot, align 8
  %selected = select i1 %condition, ptr addrspace(1) null, ptr addrspace(1) %loaded
  %equal = icmp eq ptr addrspace(1) %selected, null
  br i1 %equal, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %joined = phi ptr addrspace(1) [null, %left], [%selected, %right]
  ret ptr addrspace(1) %joined
}
