//! Helper-backed scalar port-I/O native exit bridge.

use super::X86_64Vcpu;
use crate::isa::x86_64::execute::io::IoPermissionState;
use crate::smir::lower::runtime::GuestRegs;
use crate::vm::vcpu::VcpuExit;

/// Validate dynamic I/O permission and publish one packed external exit.
/// No host `IN`/`OUT` opcode is executed. Zero requests exact direct replay;
/// one guarantees that only the append-only `io_request` field was committed.
pub(super) unsafe extern "C" fn rax_jit_io(
    state: *mut GuestRegs,
    port: u32,
    size: u32,
    output: u32,
) -> u64 {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    if port > u32::from(u16::MAX)
        || !matches!(size, 1 | 2 | 4)
        || output > 1
        || state.io_request != 0
        || state.cpl > 3
    {
        return 0;
    }
    let Some(vcpu) = (unsafe { (state.ctx as *mut X86_64Vcpu).as_mut() }) else {
        return 0;
    };
    let permission = IoPermissionState {
        cr0: state.cr0,
        cr3: state.cr3,
        cr4: state.cr4,
        efer: state.efer,
        cpl: state.cpl as u8,
        rflags: state.interrupt_flags,
    };
    if !vcpu.jit_io_permission_allowed(port as u16, size as u8, permission) {
        return 0;
    }

    let value = if output == 0 {
        0
    } else {
        match size {
            1 => u32::from(state.gpr[0] as u8),
            2 => u32::from(state.gpr[0] as u16),
            4 => state.gpr[0] as u32,
            _ => unreachable!("validated scalar I/O width"),
        }
    };
    state.set_io_request(port as u16, size as u8, output != 0, value);
    1
}

impl X86_64Vcpu {
    /// Convert a helper-published request into the established VMM exit only
    /// after the native trampoline has restored complete architectural state.
    pub(super) fn complete_jit_io_request(&mut self, state: &mut GuestRegs) {
        let Some((port, size, output, value)) = state.take_io_request() else {
            return;
        };
        self.jit_callout_exit = Some(if output {
            let bytes = value.to_le_bytes();
            VcpuExit::IoOut {
                port,
                data: bytes[..usize::from(size)].to_vec(),
            }
        } else {
            self.set_io_pending_reg(port, size);
            VcpuExit::IoIn { port, size }
        });
    }
}
