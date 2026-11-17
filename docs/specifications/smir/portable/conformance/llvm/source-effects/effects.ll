; Native-target structural LLVM IR only; not the proposed SMIR DataLayout.
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Deliberately invalid RAX descriptor bytes. These prove operand retention only.
@source_call_ref = private constant [1 x i8] zeroinitializer
@execution_ref = private constant [1 x i8] zeroinitializer
@scope_ref = private constant [1 x i8] zeroinitializer

declare i64 @__rax_ir_v1_code_address_expose(ptr addrspace(1)) addrspace(1) #0
declare target("smir.code_binding") @__rax_ir_v1_code_bind(ptr addrspace(1), ptr) addrspace(1) #0
declare ptr addrspace(1) @__rax_ir_v1_code_erase(target("smir.code_binding"), ptr) addrspace(1) #0
declare target("smir.source_scope") @__rax_ir_v1_object_begin_root(ptr, target("smir.journal"), ptr) addrspace(1) #0
declare void @__rax_ir_v1_object_publish(ptr, target("smir.source_scope"), target("smir.journal"), ptr) addrspace(1) #0

define i64 @observed(ptr addrspace(1) %address) addrspace(1) #1 {
  %discard = call addrspace(1) i64 @__rax_ir_v1_code_address_expose(ptr addrspace(1) %address)
  %binding = call addrspace(1) target("smir.code_binding") @__rax_ir_v1_code_bind(ptr addrspace(1) %address, ptr @source_call_ref)
  %erased = call addrspace(1) ptr addrspace(1) @__rax_ir_v1_code_erase(target("smir.code_binding") %binding, ptr @execution_ref)
  %result = call addrspace(1) i64 @__rax_ir_v1_code_address_expose(ptr addrspace(1) %erased)
  ret i64 %result
}

define i64 @outer(ptr addrspace(1) %address) addrspace(1) {
  %result = call addrspace(1) i64 @observed(ptr addrspace(1) %address)
  ret i64 %result
}

; Journal is an actual opaque SSA operand here, not an invented source Scope.
define void @begin_publish(target("smir.journal") %journal, ptr %object) addrspace(1) #1 {
  %scope = call addrspace(1) target("smir.source_scope") @__rax_ir_v1_object_begin_root(ptr @scope_ref, target("smir.journal") %journal, ptr %object)
  call addrspace(1) void @__rax_ir_v1_object_publish(ptr @scope_ref, target("smir.source_scope") %scope, target("smir.journal") %journal, ptr %object)
  ret void
}

attributes #0 = { nounwind nocallback convergent noduplicate memory(readwrite) }
attributes #1 = { noinline optnone }
