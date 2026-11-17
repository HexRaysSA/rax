; Opaque aggregate SSA only. No sized/stored/native ABI is asserted.
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
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
