//! Architectural register banks, IRQ/FIQ masks, vectors and low-power wakeup.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

fn cpu(group: u8, word: u32) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(FlatMemory::new(0, 4096)));
    cpu.write_memory(0, &word.to_le_bytes()).unwrap();
    cpu.write_memory(4, &0xd503_201fu32.to_le_bytes()).unwrap();
    let handle = cpu.gic_handle().unwrap();
    let mut gic = handle.lock().unwrap();
    gic.write_redist(0, 0x14, 0);
    gic.write_dist(0, 1 << group);
    gic.set_group_enable(0, group == 1, true);
    gic.cpu_mut(0).unwrap().private_interrupts[7].group = group;
    gic.write_redist(0, 0x10100, 1 << 7);
    gic.send_sgi(7, 1, false);
    cpu
}

fn virtual_interrupt_cpu(el: u8, word: u32) -> AArch64Cpu {
    let config = AArch64Config {
        initial_el: el,
        gic_config: None,
        ..AArch64Config::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 4096)));
    cpu.sysregs.scr_el3 = 0x501;
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.el1.vbar = 0x800;
    cpu.write_memory(0, &word.to_le_bytes()).unwrap();
    cpu.write_memory(4, &0xd503_201fu32.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn hcr_virtual_interrupts_vector_to_el1_without_consuming_the_level() {
    for (enable, level, mask, offset) in [(4, 7, 2, 0x80), (3, 6, 1, 0x100)] {
        for el in [0, 1] {
            let mut cpu = virtual_interrupt_cpu(el, 0xd503_201f);
            cpu.daif = 3 ^ mask;
            cpu.sysregs.hcr_el2 |= (1 << enable) | (1 << level);
            // Physical routing must not redirect a virtual interrupt to EL3.
            cpu.sysregs.scr_el3 |= 0b110;
            assert_eq!(cpu.step().unwrap(), CpuExit::InterruptPending);
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            let vector = if el == 0 { 0x400 } else { 0x200 };
            assert_eq!(
                (cpu.current_el, cpu.pc, cpu.insn_count),
                (1, 0x800 + vector + offset, 0)
            );
            assert_eq!(cpu.sysregs.el1.elr, 0);
            assert_eq!(cpu.sysregs.hcr_el2 & (1 << level), 1 << level);
        }
    }
}

#[test]
fn hcr_virtual_interrupts_respect_route_level_security_and_independent_masks() {
    for (enable, level, mask, offset) in [(4, 7, 2, 0x80), (3, 6, 1, 0x100)] {
        for (el, secure, hcr_enable, tge, masked) in [
            (1, false, false, false, false),
            (1, false, true, true, false),
            (1, true, true, false, false),
            (2, false, true, false, false),
            (1, false, true, false, true),
        ] {
            let mut cpu = virtual_interrupt_cpu(el, 0xd503_201f);
            cpu.sysregs.scr_el3 &= !u64::from(secure);
            cpu.sysregs.hcr_el2 |=
                (u64::from(hcr_enable) << enable) | (u64::from(tge) << 27) | (1 << level);
            cpu.daif = u8::from(masked) * mask;
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (el, 4, 1));
        }
        let mut cpu = virtual_interrupt_cpu(1, 0xd503_201f);
        cpu.sysregs.hcr_el2 |= (1 << 3) | (1 << 4) | (1 << 6) | (1 << 7);
        cpu.daif = 3 ^ mask;
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count), (0xa00 + offset, 0));
    }
    let mut cpu = virtual_interrupt_cpu(1, 0xd503_201f);
    cpu.sysregs.hcr_el2 |= (1 << 3) | (1 << 4) | (1 << 6) | (1 << 7);
    cpu.daif = 0;
    assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
    assert_eq!((cpu.pc, cpu.insn_count), (0xa80, 0));
}

#[test]
fn hcr_virtual_interrupts_wake_wfi_even_when_masked() {
    use crate::vm::timing::{ClockMode, TimingContext};
    use crate::vm::vcpu::ClockIdle;
    use std::sync::Arc;

    for (enable, level) in [(4, 7), (3, 6)] {
        let mut cpu = virtual_interrupt_cpu(1, 0xd503_207f);
        cpu.daif = 0xf;
        cpu.sysregs.hcr_el2 |= (1 << enable) | (1 << level) | (1 << 13);
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Wfi);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.wfi), (4, 1, false));

        let mut cpu = virtual_interrupt_cpu(1, 0xd503_207f);
        cpu.daif = 0xf;
        cpu.bind_system_counter(Arc::new(TimingContext::with_mode(ClockMode::Retired)));
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Wfi);
        assert!(cpu.wfi);
        assert!(matches!(
            cpu.clock_idle().unwrap(),
            ClockIdle::Waiting { .. }
        ));
        cpu.sysregs.hcr_el2 |= (1 << enable) | (1 << level);
        assert!(matches!(cpu.clock_idle().unwrap(), ClockIdle::Runnable));
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.wfi), (8, 2, false));
    }
}

#[test]
fn hcr_virtual_interrupts_complete_an_existing_wfe_when_unmasked() {
    for direct in [false, true] {
        let mut cpu = virtual_interrupt_cpu(1, 0xd503_205f);
        cpu.daif = 0xd; // IRQ unmasked.
        let step = |cpu: &mut AArch64Cpu| {
            if direct {
                cpu.step()
            } else {
                cpu.step_system()
            }
            .unwrap()
        };
        assert_eq!(step(&mut cpu), CpuExit::Wfe);
        assert!(cpu.wfe);
        cpu.sysregs.hcr_el2 |= (1 << 4) | (1 << 7);
        let result = step(&mut cpu);
        assert!(!cpu.wfe);
        assert_eq!(cpu.insn_count, 1);
        if direct {
            assert_eq!((result, cpu.pc), (CpuExit::InterruptPending, 4));
        } else {
            assert_eq!((result, cpu.pc), (CpuExit::Continue, 0xa80));
            assert_eq!(cpu.sysregs.el1.elr, 4);
        }
    }
}

#[test]
fn hcr_virtual_interrupts_share_the_boundary_with_physical_interrupts() {
    for (group, gate, level, virtual_vector, physical_vector, physical_mask) in
        [(0, 4, 7, 0x280, 0x300, 1), (1, 3, 6, 0x300, 0x280, 2)]
    {
        for masked in [false, true] {
            let mut cpu = cpu(group, 0xd503_201f);
            cpu.sysregs.scr_el3 = 0x501;
            cpu.sysregs.hcr_el2 = (1 << 31) | (1 << gate) | (1 << level);
            cpu.daif = if masked { physical_mask } else { 0 };
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            let vector = if masked {
                virtual_vector
            } else {
                physical_vector
            };
            assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (1, vector, 0));
        }
    }
}

#[test]
fn hcr_virtual_interrupts_stay_out_of_the_process_entry() {
    let mut cpu = virtual_interrupt_cpu(0, 0xd503_201f);
    cpu.daif = 0;
    cpu.sysregs.hcr_el2 |= (1 << 4) | (1 << 7);
    assert_eq!(cpu.step_user_pauth(false).unwrap(), CpuExit::Continue);
    assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (0, 4, 1));
    assert_eq!(cpu.step().unwrap(), CpuExit::InterruptPending);
}

#[test]
fn hcr_virtual_interrupts_enter_aarch32_el1_in_the_selected_mode() {
    for (gate, level, mode, vector) in [(4, 7, 0x12, 0x18), (3, 6, 0x11, 0x1c)] {
        let mut cpu = virtual_interrupt_cpu(1, 0xe320_f000);
        cpu.sysregs.hcr_el2 = (1 << gate) | (1 << level); // AArch32 EL1.
        cpu.set_pstate_bits(0x13).unwrap(); // Unmasked AArch32 SVC.
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!(
            (cpu.current_el, cpu.pc, cpu.insn_count),
            (1, 0x800 + vector, 0)
        );
        assert_eq!(cpu.aarch32.unwrap().mode, mode);
        assert_eq!(cpu.get_lr(), 4);
    }
}

#[test]
fn hcr_virtual_serror_is_consumed_when_the_el1_handler_is_entered() {
    use crate::isa::arm::aarch64::hcr;

    for (el, sp_sel, vector) in [(0, false, 0x580), (1, false, 0x180), (1, true, 0x380)] {
        let mut cpu = virtual_interrupt_cpu(el, 0xd503_201f);
        cpu.sp_sel = sp_sel;
        cpu.daif = 3; // SError is unmasked while IRQ and FIQ are masked.
        cpu.sysregs.hcr_el2 |= hcr::AMO | hcr::VSE;
        cpu.sysregs.scr_el3 |= 1 << 3; // The physical EA routing is independent.
        let spsr = cpu.pstate_bits();
        let handler = 0x800 + vector;
        cpu.write_memory(handler, &0xd69f_03e0u32.to_le_bytes())
            .unwrap(); // ERET
        assert_eq!(cpu.step().unwrap(), CpuExit::InterruptPending);
        assert_ne!(cpu.sysregs.hcr_el2 & hcr::VSE, 0);

        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (1, handler, 0));
        assert_eq!((cpu.sysregs.el1.elr, cpu.sysregs.el1.spsr), (0, spsr));
        assert_eq!(cpu.sysregs.el1.esr, 0xbe00_0000);
        assert_eq!(cpu.sysregs.hcr_el2, (1 << 31) | hcr::AMO);
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue); // ERET
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue); // Original NOP.
        assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (el, 4, 2));
    }
}

#[test]
fn hcr_virtual_serror_routing_mask_and_priority_preserve_pending_state() {
    use crate::isa::arm::aarch64::hcr;

    for (el, secure, masked, hcr, pc) in [
        (1, false, false, hcr::VSE, 4),
        (1, false, false, hcr::AMO, 4),
        (1, false, true, hcr::AMO | hcr::VSE, 4),
        (0, false, false, (1 << 27) | hcr::AMO | hcr::VSE, 4),
        (1, true, false, hcr::AMO | hcr::VSE, 4),
        (2, false, false, hcr::AMO | hcr::VSE, 4),
        (
            1,
            false,
            false,
            hcr::AMO | hcr::VSE | hcr::VI | hcr::IMO,
            0xa80,
        ),
        (
            1,
            false,
            false,
            hcr::AMO | hcr::VSE | hcr::VF | hcr::FMO,
            0xb00,
        ),
    ] {
        let mut cpu = virtual_interrupt_cpu(el, 0xd503_201f);
        cpu.sysregs.scr_el3 &= !u64::from(secure);
        cpu.sysregs.hcr_el2 |= hcr;
        cpu.daif = u8::from(masked) << 2;
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count), (pc, u64::from(pc == 4)));
        assert_eq!(cpu.sysregs.hcr_el2, (1 << 31) | hcr);
    }
}

#[test]
fn hcr_virtual_serror_wakes_wfi_while_masked_and_vectors_after_unmasking() {
    use crate::isa::arm::aarch64::hcr;
    use crate::vm::timing::{ClockMode, TimingContext};
    use crate::vm::vcpu::ClockIdle;
    use std::sync::Arc;

    for pending_before_wfi in [false, true] {
        let mut cpu = virtual_interrupt_cpu(1, 0xd503_207f); // WFI
        cpu.daif = 0xf;
        cpu.bind_system_counter(Arc::new(TimingContext::with_mode(ClockMode::Retired)));
        if pending_before_wfi {
            cpu.sysregs.hcr_el2 |= hcr::AMO | hcr::VSE | hcr::TWI;
        }
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Wfi);
        assert_eq!(
            (cpu.pc, cpu.insn_count, cpu.wfi),
            (4, 1, !pending_before_wfi)
        );
        if !pending_before_wfi {
            assert!(matches!(
                cpu.clock_idle().unwrap(),
                ClockIdle::Waiting { .. }
            ));
        }
        cpu.sysregs.hcr_el2 |= hcr::AMO | hcr::VSE;
        assert!(matches!(cpu.clock_idle().unwrap(), ClockIdle::Runnable));
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.wfi), (8, 2, false));
        assert_ne!(cpu.sysregs.hcr_el2 & hcr::VSE, 0);
        cpu.daif &= !4;
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.sysregs.el1.elr), (0xb80, 2, 8));
        assert_eq!(cpu.sysregs.hcr_el2 & hcr::VSE, 0);
    }
}

#[test]
fn hcr_virtual_serror_reports_an_aarch32_asynchronous_external_abort() {
    use crate::isa::arm::aarch64::hcr;

    for (ttbcr, pstate, dfsr) in [(0, 0x13, 0x406), (1 << 31, 0x33, 0x211)] {
        let mut cpu = virtual_interrupt_cpu(1, 0xe320_f000);
        cpu.sysregs.hcr_el2 = hcr::AMO | hcr::VSE;
        cpu.sysregs.el1.tcr = ttbcr;
        cpu.set_pstate_bits(pstate).unwrap();
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.current_el, cpu.pc, cpu.insn_count), (1, 0x810, 0));
        assert_eq!(cpu.aarch32.unwrap().mode, 0x17);
        assert_eq!(cpu.get_lr(), 8);
        assert_eq!(cpu.sysregs.el1.esr, dfsr);
        assert_eq!(cpu.sysregs.hcr_el2, hcr::AMO);
    }
}

#[test]
fn mrs_iar_and_hppir_respect_group_without_consuming_a_wrong_bank() {
    for (group, wrong_iar, wrong_hppir, right_iar) in [
        (0, 0xd538_cc00, 0xd538_cc40, 0xd538_c800u32),
        (1, 0xd538_c800, 0xd538_c840, 0xd538_cc00),
    ] {
        for wrong in [wrong_iar, wrong_hppir] {
            let mut cpu = cpu(group, wrong);
            assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
            assert_eq!(cpu.get_x(0), 1023);
            let handle = cpu.gic_handle().unwrap();
            assert!(
                handle.lock().unwrap().cpu(0).unwrap().private_interrupts[7]
                    .state
                    .is_pending()
            );
            cpu.write_memory(4, &right_iar.to_le_bytes()).unwrap();
            assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
            assert_eq!(cpu.get_x(0), 7);
            assert!(
                handle.lock().unwrap().cpu(0).unwrap().private_interrupts[7]
                    .state
                    .is_active()
            );
        }
    }
}

#[test]
fn exceptions_routed_to_higher_el2_are_not_masked_by_lower_el_pstate() {
    for group in [0, 1] {
        let mut cpu = cpu(group, 0xd503_201f);
        cpu.sysregs.scr_el3 |= 1;
        cpu.sysregs.hcr_el2 |= if group == 0 { 1 << 3 } else { 1 << 4 };
        assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
        assert_eq!(cpu.current_el, 2);
        assert_eq!(cpu.pc, if group == 0 { 0x500 } else { 0x480 });
        assert_eq!(cpu.sysregs.el2.elr, 0);
        assert_eq!(cpu.insn_count, 0);
    }
}

#[test]
fn interrupts_targeting_el1_are_implicitly_masked_at_el2_and_el3() {
    for group in [0, 1] {
        for el in [2, 3] {
            for system in [false, true] {
                let mut cpu = cpu(group, 0xd503_201f);
                cpu.current_el = el;
                cpu.sysregs.scr_el3 |= u64::from(el == 2);
                cpu.daif = 0;
                let exit = if system {
                    cpu.step_system()
                } else {
                    cpu.step()
                }
                .unwrap();
                assert!(matches!(exit, CpuExit::Continue));
                assert_eq!((cpu.pc, cpu.current_el, cpu.insn_count), (4, el, 1));
            }
        }
    }
}

#[test]
fn direct_wfe_publishes_expired_timer_before_testing_wakeup() {
    let mut cpu = cpu(1, 0xd503_205f);
    let handle = cpu.gic_handle().unwrap();
    handle.lock().unwrap().write_redist(0, 0x10280, 1 << 7);
    assert!(matches!(cpu.step().unwrap(), CpuExit::Wfe));
    cpu.daif = 1;
    handle.lock().unwrap().write_redist(0, 0x10100, 1 << 30);
    cpu.sysregs.cntp_cval_el0 = 0;
    cpu.sysregs.cntp_ctl_el0 = 1;
    assert!(matches!(cpu.step().unwrap(), CpuExit::InterruptPending));
    assert!(!cpu.wfe);
    assert_eq!(cpu.pc, 4);
}

#[test]
fn effective_tge_and_e2h_routing_and_scr_priority_follow_configured_profile() {
    for group in [0, 1] {
        let kind = if group == 0 {
            ExceptionType::Fiq
        } else {
            ExceptionType::Irq
        };
        for vhe in [false, true] {
            for e2h in [false, true] {
                for tge in [false, true] {
                    for raw in [false, true] {
                        let mut cpu = cpu(group, 0xd503_201f);
                        cpu.current_el = 0;
                        cpu.sp_sel = false;
                        cpu.config.features.set(ArmFeatures::VHE, vhe);
                        cpu.sysregs.scr_el3 |= 1;
                        cpu.sysregs.hcr_el2 |= u64::from(e2h) << 34 | u64::from(tge) << 27;
                        cpu.sysregs.hcr_el2 |= u64::from(raw) << (if group == 0 { 3 } else { 4 });
                        // TGE/raw routing truth table, independent of E2H.
                        let route =
                            [false, true, true, true][usize::from(tge) * 2 + usize::from(raw)];
                        assert_eq!(cpu.interrupt_target_el(kind), if route { 2 } else { 1 });
                        cpu.sysregs.scr_el3 |= 1 << (if group == 0 { 2 } else { 1 });
                        assert_eq!(cpu.interrupt_target_el(kind), 3);
                        assert!(cpu.interrupt_unmasked(kind));
                    }
                }
            }
        }
    }
}

#[test]
fn private_checkpoint_rebinds_masked_vhe_request_before_higher_el_delivery() {
    for group in [0, 1] {
        let mut source = cpu(group, 0xd503_201f);
        source.config.features.insert(ArmFeatures::VHE);
        source.current_el = 0;
        source.sp_sel = false;
        source.sysregs.scr_el3 |= 1;
        source.sysregs.hcr_el2 |= (1 << 27) | (1 << 34);
        let bytes = crate::codec::serialize(&CoreCheckpoint::capture(&source).unwrap()).unwrap();
        let image: CoreCheckpoint = crate::codec::deserialize(&bytes).unwrap();
        let mut target = cpu(group, 0xd503_201f);
        target.config.features.insert(ArmFeatures::VHE);
        let line = target.gic_irq_line.clone().unwrap();
        image.install_in_prepared(&mut target).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &line,
            target.gic_irq_line.as_ref().unwrap()
        ));
        for cpu in [&mut source, &mut target] {
            assert_eq!(cpu.current_el, 0);
            assert_eq!(cpu.daif, 15);
            assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
            assert_eq!(cpu.current_el, 2);
            assert_eq!(cpu.pc, if group == 0 { 0x500 } else { 0x480 });
            assert_eq!(cpu.insn_count, 0);
        }
        assert_eq!(
            crate::codec::serialize(&CoreCheckpoint::capture(&source).unwrap()).unwrap(),
            crate::codec::serialize(&CoreCheckpoint::capture(&target).unwrap()).unwrap()
        );
    }
}

#[test]
fn aarch32_hyp_keeps_local_physical_irq_and_fiq_routing() {
    for group in [0, 1] {
        let mut cpu = cpu(group, 0xd503_201f);
        cpu.sysregs.scr_el3 = 1; // EL2 configured in AArch32.
        cpu.sysregs.hcr_el2 = 0;
        let mut state = cpu.get_pstate();
        state.mode = 0x1a;
        state.i = false;
        state.f = false;
        cpu.set_pstate(state);
        assert_eq!(cpu.current_el, 2);
        assert!(matches!(cpu.step_system().unwrap(), CpuExit::Continue));
        assert_eq!(cpu.pc, if group == 0 { 0x1c } else { 0x18 });
        assert_eq!(cpu.aarch32.unwrap().mode, 0x1a);
        assert_eq!(cpu.sysregs.el2.elr, 0);
        assert_eq!(cpu.insn_count, 0);
    }
}

#[test]
fn msr_wrong_eoir_preserves_active_priority_in_both_modes() {
    for mode in [false, true] {
        for (group, wrong, right) in [
            (0, 0xd518_cc20, 0xd518_c820u32),
            (1, 0xd518_c820, 0xd518_cc20),
        ] {
            let mut cpu = cpu(group, wrong);
            let handle = cpu.gic_handle().unwrap();
            {
                let mut gic = handle.lock().unwrap();
                gic.cpu_mut(0).unwrap().eoi_mode = mode;
                assert_eq!(gic.acknowledge(0), 7);
            }
            cpu.set_x(0, 7);
            cpu.step().unwrap();
            {
                let gic = handle.lock().unwrap();
                assert_eq!(gic.cpu(0).unwrap().running_priority, 0xa0);
                assert!(gic.cpu(0).unwrap().private_interrupts[7].state.is_active());
            }
            cpu.write_memory(4, &right.to_le_bytes()).unwrap();
            cpu.step().unwrap();
            let gic = handle.lock().unwrap();
            assert_eq!(gic.cpu(0).unwrap().running_priority, 0xff);
            assert_eq!(
                gic.cpu(0).unwrap().private_interrupts[7].state.is_active(),
                mode
            );
        }
    }
}

#[test]
fn group_masks_and_vectors_match_on_direct_interpreted_and_native_system_entries() {
    for group in [0, 1] {
        for masks in 0..4 {
            for entry in 0..3 {
                let mut cpu = cpu(group, 0xd503_201f);
                cpu.daif = masks;
                let masked = masks & (if group == 0 { 1 } else { 2 }) != 0;
                let exit = match entry {
                    0 => cpu.step().unwrap(),
                    1 => cpu.step_system_interpreted(true).unwrap(),
                    _ => cpu.step_system_with_fault_exit().unwrap(),
                };
                if entry == 0 && !masked {
                    assert!(matches!(exit, CpuExit::InterruptPending));
                    assert_eq!(cpu.pc, 0);
                } else {
                    assert!(matches!(exit, CpuExit::Continue));
                    assert_eq!(
                        cpu.pc,
                        if masked {
                            4
                        } else if group == 0 {
                            0x300
                        } else {
                            0x280
                        }
                    );
                }
                assert_eq!(cpu.insn_count, u64::from(masked));
                if entry != 0 && !masked {
                    assert_eq!(cpu.sysregs.el1.elr, 0);
                    assert_eq!(cpu.sysregs.el1.spsr & 0xc0, u64::from(masks) << 6);
                }
            }
        }
    }
}

#[test]
fn masked_irq_and_fiq_wake_wfi_without_taking_an_exception() {
    for group in [0, 1] {
        for system in [false, true] {
            let step = |cpu: &mut AArch64Cpu| {
                if system {
                    cpu.step_system()
                } else {
                    cpu.step()
                }
            };
            for pending_at_entry in [false, true] {
                let mut cpu = cpu(group, 0xd503_207f);
                let handle = cpu.gic_handle().unwrap();
                if pending_at_entry {
                    assert_eq!(step(&mut cpu).unwrap(), CpuExit::Wfi);
                    assert!(!cpu.wfi);
                } else {
                    handle.lock().unwrap().write_redist(0, 0x10280, 1 << 7);
                    assert_eq!(step(&mut cpu).unwrap(), CpuExit::Wfi);
                    assert!(cpu.wfi);
                    handle.lock().unwrap().send_sgi(7, 1, false);
                }
                assert_eq!(step(&mut cpu).unwrap(), CpuExit::Continue);
                assert_eq!((cpu.pc, cpu.insn_count), (8, 2));
                assert_eq!(cpu.sysregs.el1.elr, 0);
                assert!(!cpu.wfi);
                assert!(
                    handle.lock().unwrap().cpu(0).unwrap().private_interrupts[7]
                        .state
                        .is_pending()
                );
            }
        }
    }
}

#[test]
fn unmasked_irq_and_fiq_wake_wfe_without_an_event_register_signal() {
    for group in [0, 1] {
        for system in [false, true] {
            let mut cpu = cpu(group, 0xd503_205f);
            let step = |cpu: &mut AArch64Cpu| {
                if system {
                    cpu.step_system()
                } else {
                    cpu.step()
                }
            };
            assert!(matches!(step(&mut cpu).unwrap(), CpuExit::Wfe));
            cpu.daif = if group == 0 { 2 } else { 1 };
            let exit = step(&mut cpu).unwrap();
            if system {
                assert!(matches!(exit, CpuExit::Continue));
                assert_eq!(cpu.pc, if group == 0 { 0x300 } else { 0x280 });
            } else {
                assert!(matches!(exit, CpuExit::InterruptPending));
                assert_eq!(cpu.pc, 4);
            }
            assert!(!cpu.wfe);
            assert!(!cpu.take_event());
        }
    }
}

#[test]
fn sgi_registers_follow_single_state_table_for_secure_and_nonsecure_sources() {
    for have_el3 in [false, true] {
        for secure in [false, true] {
            for (op2, secure_groups, nonsecure_groups) in [(5, 1, 3), (6, 2, 1), (7, 1, 1)] {
                for group in [0, 1] {
                    let mut cpu = cpu(group, 0xd518_cb00 | (op2 << 5));
                    cpu.sysregs.id_aa64pfr0_el1 &= !(15 << 12);
                    cpu.sysregs.id_aa64pfr0_el1 |= u64::from(have_el3) << 12;
                    cpu.sysregs.scr_el3 = (1 << 10) | u64::from(!secure);
                    let handle = cpu.gic_handle().unwrap();
                    handle.lock().unwrap().write_redist(0, 0x10280, 1 << 7);
                    cpu.set_x(0, (7 << 24) | 1);
                    assert!(matches!(cpu.step().unwrap(), CpuExit::Continue));
                    let groups = if have_el3 && secure {
                        secure_groups
                    } else {
                        nonsecure_groups
                    };
                    assert_eq!(
                        handle.lock().unwrap().cpu(0).unwrap().private_interrupts[7]
                            .state
                            .is_pending(),
                        groups & (1 << group) != 0,
                        "have_el3={have_el3} secure={secure} op2={op2} group={group}"
                    );
                }
            }
        }
    }
}
