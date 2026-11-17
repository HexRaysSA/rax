; LLVM021 six-form opaque-E structural witness only. No CPP source issuer,
; source lifetime/JournalView association, native execution or emitter proof.
; Numeric AS1/native DataLayout here assigns NO portable program address space.
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
@ref = private constant [1 x i8] zeroinitializer
; Ref intentionally invalid as a source descriptor. Structural IR only.
declare i32 @portable_personality(...)
declare void @may_throw() addrspace(1)
declare void @__rax_ir_v1_scope_exit.normal.no_journal(ptr, target("smir.source_scope")) addrspace(1) #0
declare void @__rax_ir_v1_scope_exit.normal.with_journal(ptr, target("smir.source_scope"), target("smir.journal")) addrspace(1) #0
declare void @__rax_ir_v1_scope_exit.unwind.no_journal(ptr, target("smir.source_scope"), target("smir.exception")) addrspace(1) #0
declare void @__rax_ir_v1_scope_exit.unwind.with_journal(ptr, target("smir.source_scope"), target("smir.journal"), target("smir.exception")) addrspace(1) #0
declare void @__rax_ir_v1_scope_exit.outward_unwind.no_journal(ptr, target("smir.source_scope")) addrspace(1) #0
declare void @__rax_ir_v1_scope_exit.outward_unwind.with_journal(ptr, target("smir.source_scope"), target("smir.journal")) addrspace(1) #0
define void @normal_no_j(target("smir.source_scope") %scope) addrspace(1) #1 {
entry:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.no_journal(ptr @ref, target("smir.source_scope") %scope)
 ret void
}
define void @normal_j(target("smir.source_scope") %scope, target("smir.journal") %journal) addrspace(1) #1 {
entry:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.with_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.journal") %journal)
 ret void
}
define void @unwind_no_j(target("smir.source_scope") %scope) addrspace(1) #1 personality ptr @portable_personality {
entry:
 invoke addrspace(1) void @may_throw() to label %done unwind label %cleanup
done:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.no_journal(ptr @ref, target("smir.source_scope") %scope)
 ret void
cleanup:
 %pair = landingpad { target("smir.exception"), i32 } cleanup
 %exception = extractvalue { target("smir.exception"), i32 } %pair, 0
 call addrspace(1) void @__rax_ir_v1_scope_exit.unwind.no_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.exception") %exception)
 resume { target("smir.exception"), i32 } %pair
}
define void @unwind_j(target("smir.source_scope") %scope, target("smir.journal") %journal) addrspace(1) #1 personality ptr @portable_personality {
entry:
 invoke addrspace(1) void @may_throw() to label %done unwind label %cleanup
done:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.with_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.journal") %journal)
 ret void
cleanup:
 %pair = landingpad { target("smir.exception"), i32 } cleanup
 %exception = extractvalue { target("smir.exception"), i32 } %pair, 0
 call addrspace(1) void @__rax_ir_v1_scope_exit.unwind.with_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.journal") %journal, target("smir.exception") %exception)
 resume { target("smir.exception"), i32 } %pair
}
define void @outward_unwind_no_j(target("smir.source_scope") %scope) addrspace(1) #1 personality ptr @portable_personality {
entry:
 invoke addrspace(1) void @may_throw() to label %done unwind label %cleanup
done:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.no_journal(ptr @ref, target("smir.source_scope") %scope)
 ret void
cleanup:
 %pair = landingpad { target("smir.exception"), i32 } cleanup
 %exception = extractvalue { target("smir.exception"), i32 } %pair, 0
 call addrspace(1) void @__rax_ir_v1_scope_exit.outward_unwind.no_journal(ptr @ref, target("smir.source_scope") %scope)
 resume { target("smir.exception"), i32 } %pair
}
define void @outward_unwind_j(target("smir.source_scope") %scope, target("smir.journal") %journal) addrspace(1) #1 personality ptr @portable_personality {
entry:
 invoke addrspace(1) void @may_throw() to label %done unwind label %cleanup
done:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.with_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.journal") %journal)
 ret void
cleanup:
 %pair = landingpad { target("smir.exception"), i32 } cleanup
 %exception = extractvalue { target("smir.exception"), i32 } %pair, 0
 call addrspace(1) void @__rax_ir_v1_scope_exit.outward_unwind.with_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.journal") %journal)
 resume { target("smir.exception"), i32 } %pair
}
define void @joined_exception(target("smir.source_scope") %scope, i1 %choose) addrspace(1) #1 personality ptr @portable_personality {
entry:
 br i1 %choose, label %left, label %right
left:
 invoke addrspace(1) void @may_throw() to label %done unwind label %lp_left
right:
 invoke addrspace(1) void @may_throw() to label %done unwind label %lp_right
done:
 call addrspace(1) void @__rax_ir_v1_scope_exit.normal.no_journal(ptr @ref, target("smir.source_scope") %scope)
 ret void
lp_left:
 %left_pair = landingpad { target("smir.exception"), i32 } cleanup
 %left_e = extractvalue { target("smir.exception"), i32 } %left_pair, 0
 %left_selector = extractvalue { target("smir.exception"), i32 } %left_pair, 1
 br label %join
lp_right:
 %right_pair = landingpad { target("smir.exception"), i32 } cleanup
 %right_e = extractvalue { target("smir.exception"), i32 } %right_pair, 0
 %right_selector = extractvalue { target("smir.exception"), i32 } %right_pair, 1
 br label %join
join:
 %exception = phi target("smir.exception") [ %left_e, %lp_left ], [ %right_e, %lp_right ]
 %selector = phi i32 [ %left_selector, %lp_left ], [ %right_selector, %lp_right ]
 %joined0 = insertvalue { target("smir.exception"), i32 } poison, target("smir.exception") %exception, 0
 %joined = insertvalue { target("smir.exception"), i32 } %joined0, i32 %selector, 1
 call addrspace(1) void @__rax_ir_v1_scope_exit.unwind.no_journal(ptr @ref, target("smir.source_scope") %scope, target("smir.exception") %exception)
 resume { target("smir.exception"), i32 } %joined
}
attributes #0 = { nounwind nocallback convergent noduplicate memory(readwrite) }
attributes #1 = { noinline optnone }
