//! Actual protected-mode faults, traps and retired-unit accounting.
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::vcpu::{CpuState, DescriptorTable, Segment, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
pub fn cpu(code: &[u8]) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
    let m = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
    m.write_obj(0x00cf9b000000ffffu64.to_le(), GuestAddress(0x6008))
        .unwrap();
    m.write_obj(0x00cf93000000ffffu64.to_le(), GuestAddress(0x6010))
        .unwrap();
    for v in 0..32u64 {
        let h = 0x9000 + 16 * v;
        m.write_obj(
            (0x00008e0000080000u64 | h).to_le(),
            GuestAddress(0x7000 + v * 8),
        )
        .unwrap();
    }
    m.write_slice(code, GuestAddress(0x8000)).unwrap();
    let mut c = X86_64Vcpu::new(0, m.clone());
    let mut state = c.get_state().unwrap();
    let CpuState::X86_64(s) = &mut state else {
        panic!()
    };
    s.sregs.cr0 = 1 | 16 | (1 << 16);
    s.sregs.cr4 = 0;
    s.sregs.efer = 0;
    s.sregs.gdt = DescriptorTable {
        base: 0x6000,
        limit: 23,
    };
    s.sregs.idt = DescriptorTable {
        base: 0x7000,
        limit: 0x7ff,
    };
    s.sregs.cs = Segment {
        base: 0,
        limit: u32::MAX,
        selector: 8,
        type_: 11,
        s: true,
        present: true,
        db: true,
        g: true,
        ..Default::default()
    };
    s.sregs.ss = Segment {
        base: 0,
        limit: u32::MAX,
        selector: 16,
        type_: 3,
        s: true,
        present: true,
        db: true,
        g: true,
        ..Default::default()
    };
    s.regs.rip = 0x8000;
    s.regs.rsp = 0xf000;
    s.regs.rflags = 2;
    s.regs.rax = 1 << 31;
    s.regs.rcx = 0;
    c.set_state(&state).unwrap();
    (c, m)
}

fn state(c: &X86_64Vcpu) -> rax::vm::vcpu::X86_64CpuState {
    let CpuState::X86_64(s) = c.get_state().unwrap() else {
        panic!()
    };
    s
}
fn set(c: &mut X86_64Vcpu, f: impl FnOnce(&mut rax::vm::vcpu::X86_64CpuState)) {
    let mut s = state(c);
    f(&mut s);
    c.set_state(&CpuState::X86_64(s)).unwrap();
}
fn fault(code: &[u8], vector: u8, error: bool, configure: impl FnOnce(&mut X86_64Vcpu)) {
    let (mut c, m) = cpu(code);
    configure(&mut c);
    let r = c.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(r.stop, rax::vm::vcpu::RetirementStop::StateChange));
    assert_eq!(c.instruction_count(), 0);
    let s = state(&c);
    assert_eq!(s.regs.rip, 0x9000 + 16 * u64::from(vector));
    assert_eq!(
        u32::from_le(
            m.read_obj::<u32>(GuestAddress(s.regs.rsp + if error { 4 } else { 0 }))
                .unwrap()
        ),
        0x8000
    );
}
#[test]
fn gp_delivered_by_control_handler_does_not_retire() {
    fault(&[0x0f, 0x22, 0xc0], 13, true, |_| {});
}
#[test]
fn ud_delivered_by_instruction_handler_does_not_retire() {
    fault(&[0x0f, 0x0b], 6, false, |_| {});
}
#[test]
fn divide_error_does_not_retire() {
    fault(&[0xf7, 0xf1], 0, false, |_| {});
}
#[test]
fn x87_device_not_available_does_not_retire() {
    fault(&[0xd9, 0xd0], 7, false, |c| {
        set(c, |s| s.sregs.cr0 |= 1 << 3)
    });
}
#[test]
fn debug_register_access_fault_does_not_retire() {
    fault(&[0x0f, 0x23, 0xc0], 1, false, |c| {
        set(c, |s| s.sregs.dr7 |= 1 << 13)
    });
}
#[test]
fn bounds_fault_does_not_retire() {
    fault(&[0x62, 0x13], 5, false, |c| {
        set(c, |s| {
            s.regs.rbx = 0xa000;
            s.regs.rdx = 1;
        })
    });
}
#[test]
fn software_and_debug_traps_retire_once() {
    for (code, vector) in [
        (&[0xcc][..], 3u8),
        (&[0xf1], 1),
        (&[0xcd, 0x0d], 13),
        (&[0xcd, 0], 0),
        (&[0xce], 4),
    ] {
        let (mut c, m) = cpu(code);
        set(&mut c, |s| s.regs.rflags |= 1 << 11);
        let r = c.run_retirement_budget(1).unwrap();
        assert_eq!(r.retired, 1);
        assert!(matches!(
            r.stop,
            rax::vm::vcpu::RetirementStop::BudgetExhausted
        ));
        assert_eq!(c.instruction_count(), 1);
        let s = state(&c);
        assert_eq!(s.regs.rip, 0x9000 + 16 * u64::from(vector));
        assert_eq!(
            u32::from_le(m.read_obj::<u32>(GuestAddress(s.regs.rsp)).unwrap()),
            0x8000 + code.len() as u32
        );
    }
}
#[test]
fn software_gate_fault_saves_restart_pc_without_retirement() {
    let (mut c, m) = cpu(&[0xcc]);
    m.write_obj(0x00000e0000089030u64.to_le(), GuestAddress(0x7000 + 3 * 8))
        .unwrap();
    let r = c.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 0);
    assert!(matches!(r.stop, rax::vm::vcpu::RetirementStop::StateChange));
    let s = state(&c);
    assert_eq!(s.regs.rip, 0x90b0);
    assert_eq!(
        u32::from_le(m.read_obj::<u32>(GuestAddress(s.regs.rsp + 4)).unwrap()),
        0x8000
    );
}
#[test]
fn delivered_fault_does_not_advance_clock_and_handler_starts_next_budget() {
    use rax::vm::timing::{ClockMode, TimingContext};
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _guard = clock.enter();
    let (mut c, m) = cpu(&[0x90, 0x90, 0x90, 0xf7, 0xf1]);
    m.write_slice(&[0x90, 0xf4], GuestAddress(0x9000)).unwrap();
    let r = c.run_retirement_budget(1000).unwrap();
    assert_eq!(r.retired, 3);
    assert!(matches!(r.stop, rax::vm::vcpu::RetirementStop::StateChange));
    assert_eq!(clock.checkpoint_state().retired_units, 3);
    assert_eq!(clock.checkpoint_state().elapsed_nanos, 1);
    let r = c.run_retirement_budget(1).unwrap();
    assert_eq!(r.retired, 1);
    assert_eq!(clock.checkpoint_state().retired_units, 4);
    assert_eq!(clock.checkpoint_state().subnanosecond_quanta, 1);
}
#[test]
fn out_of_step_exception_does_not_suppress_next_instruction() {
    let (mut c, m) = cpu(&[0x90]);
    m.write_slice(&[0x90], GuestAddress(0x90d0)).unwrap();
    c.inject_exception(13, Some(0)).unwrap();
    assert_eq!(c.instruction_count(), 0);
    c.step_with_faults().unwrap();
    assert_eq!(c.instruction_count(), 1);
    assert_eq!(state(&c).regs.rip, 0x90d1);
}
#[test]
fn raw_fetch_error_is_counted_once_as_a_failed_attempt() {
    let (mut c, _) = cpu(&[0x90]);
    c.set_current_pc(0x10000).unwrap();
    assert!(c.step().is_err());
    assert_eq!(c.instruction_count(), 0);
    c.set_current_pc(0x8000).unwrap();
    c.step().unwrap();
    assert_eq!(c.instruction_count(), 1);
}
#[test]
fn user_event_reporting_and_nonretirement_contract_is_preserved() {
    use rax::error::{GuestMemoryFault, MemoryAccessKind};
    struct Flat;
    impl rax::vm::memory::FlatTranslation for Flat {
        fn translate(
            &self,
            linear: u64,
            _: MemoryAccessKind,
        ) -> std::result::Result<u64, GuestMemoryFault> {
            Ok(linear)
        }
    }
    for code in [&[0xcc][..], &[0xf1], &[0x0f, 0x0b], &[0xf7, 0xf1]] {
        let (mut c, _) = cpu(code);
        c.enable_user_mode(Arc::new(Flat));
        c.set_current_pc(0x8000).unwrap();
        assert!(matches!(
            c.step_with_faults(),
            Err(rax::error::Error::GuestEvent { .. })
        ));
        assert_eq!(c.instruction_count(), 0);
        assert!(c.take_user_trap().is_some());
    }
}
