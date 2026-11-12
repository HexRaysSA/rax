//! The raw ARM64 syscall ABI is distinct from logical AMD64 DLL APIs.
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll;
use crate::user::windows::hle::{ApiResult, Ctx};

pub(super) fn call(source: &str, context: &mut Ctx) -> ApiResult {
    let instruction_arch = context.t.cpu.instruction_arch();
    if source == "NTDLL"
        && context.p.arch == WinArch::X64
        && context
            .p
            .native
            .as_ref()
            .is_some_and(|native| native.object_namespace.native_machine == Some(0xaa64))
        && let Some(result) = dll::native_context_service(context, instruction_arch)
    {
        return result;
    }
    (context.api.imp)(context)
}

#[cfg(test)]
#[path = "kernel_context_tests.rs"]
mod tests;
