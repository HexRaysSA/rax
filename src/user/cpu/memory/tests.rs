use crate::user::cpu::aarch64::{A64UserCpu, UserArmMemory};
use crate::user::cpu::riscv64::RvUserCpu;
use crate::user::cpu::x86_64::X86UserCpu;

/// Taking these existing function items requires no argument or return-type
/// context. Generic storage constructors must not introduce type ambiguity.
#[test]
fn default_cpu_function_items_require_no_type_annotations() {
    let _x86 = X86UserCpu::new;
    let _a64 = A64UserCpu::new;
    let _a64_config = A64UserCpu::with_config;
    let _a64_memory = UserArmMemory::new;
    let _rv = RvUserCpu::new;
    let _x86_run = X86UserCpu::run;
    let _x86_step = X86UserCpu::step;
    let _x86_clone = X86UserCpu::clone_thread;
    let _a64_run = A64UserCpu::run;
    let _a64_clone = A64UserCpu::clone_thread;
    let _rv_run = RvUserCpu::run;
    let _rv_clone = RvUserCpu::clone_thread;
}
