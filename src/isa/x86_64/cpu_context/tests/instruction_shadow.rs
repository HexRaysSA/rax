use super::*;

#[test]
fn instruction_shadow_context_preserves_both_ioapic_policies_and_consumed_status() {
    for ioapic in [false, true] {
        let controller = Arc::new(std::sync::Mutex::new(crate::devices::ioapic::IoApic::new()));
        let (mut source, _) = cpu(&[0x90]);
        source.enable_user_mode(Arc::new(Identity));
        source.regs.rip = 0x100;
        source.user.as_mut().unwrap().instruction_debug_inhibit = true;
        source.sregs.dr6 = 0x4001;
        source.capture_user_debug_status();
        if ioapic {
            source.mmu.attach_ioapic(controller.clone());
        }
        let raw = source.save_context().unwrap();
        assert!(raw.starts_with(if ioapic {
            IOAPIC_SHADOW_TAG
        } else {
            SHADOW_TAG
        }));
        let (mut target, _) = cpu(&[0x90]);
        target.enable_user_mode(Arc::new(Identity));
        if ioapic {
            target.mmu.attach_ioapic(controller);
        }
        target.restore_context(&raw).unwrap();
        assert!(target.user.as_ref().unwrap().instruction_debug_inhibit);
        assert_eq!(target.last_user_debug_status(), 0x4001);
        assert_eq!(target.save_context().unwrap(), raw);
        assert!(target.step_with_faults().unwrap().is_none());
        assert!(!target.user.as_ref().unwrap().instruction_debug_inhibit);
        let next = target.save_context().unwrap();
        assert!(next.starts_with(if ioapic { IOAPIC_TAG } else { TAG }));
    }
}

#[test]
fn instruction_shadow_without_a_user_binding_rejects_before_mutation() {
    let (source, _) = cpu(&[0x90]);
    let mut target = cpu(&[0x90]).0;
    let before = target.save_context().unwrap();
    let context = Context::decode(&source.save_context().unwrap(), &source).unwrap();
    let malformed = Version5 {
        base: Version3 {
            base: Version2 {
                base: &context,
                user_debug_status: None,
            },
            apic_base: context.apic_base,
        },
        instruction_debug_inhibit: true,
    };
    let mut raw = SHADOW_TAG.to_vec();
    raw.extend_from_slice(&crate::codec::serialize(&malformed).unwrap());
    assert!(target.restore_context(&raw).is_err());
    assert_eq!(target.save_context().unwrap(), before);
}
