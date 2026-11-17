; Opaque aggregate SSA only. No sized/stored/native ABI is asserted.
target datalayout = "e-p:64:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-i128:128:128-f16:16:16-f32:32:32-f64:64:64-f128:128:128-v8:8:8-v16:16:16-v32:32:32-v64:64:64-v128:128:128-v256:256:256-v512:512:512-a:0:64-n8:16:32:64-S128-pe1:64:64:64:64-P1"
target triple = "smir64-unknown-rax"
@execution_ref = private constant [1 x i8] zeroinitializer

declare <2 x i64> @__rax_ir_v1_codeptr_expose_group.2({target("smir.code_binding"), target("smir.code_binding")}, ptr) addrspace(1) #0
declare {target("smir.code_binding"), target("smir.code_binding")} @__rax_ir_v1_codeptr_recover_group.2(<2 x i64>, ptr) addrspace(1) #0

define {target("smir.code_binding"), target("smir.code_binding")} @group_roundtrip({target("smir.code_binding"), target("smir.code_binding")} %pair) addrspace(1) #1 {
  %exposed = call addrspace(1) <2 x i64> @__rax_ir_v1_codeptr_expose_group.2({target("smir.code_binding"), target("smir.code_binding")} %pair, ptr @execution_ref)
  %recovered = call addrspace(1) {target("smir.code_binding"), target("smir.code_binding")} @__rax_ir_v1_codeptr_recover_group.2(<2 x i64> %exposed, ptr @execution_ref)
  ret {target("smir.code_binding"), target("smir.code_binding")} %recovered
}

attributes #0 = { nounwind nocallback convergent noduplicate memory(readwrite) }
attributes #1 = { noinline optnone }
