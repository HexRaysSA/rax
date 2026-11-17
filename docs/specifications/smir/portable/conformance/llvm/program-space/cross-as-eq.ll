target datalayout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1"
target triple = "smir64-unknown-rax"
define i1 @bad(ptr %data, ptr addrspace(1) %code) addrspace(1) {
 %x = icmp eq ptr %data, %code
 ret i1 %x
}
