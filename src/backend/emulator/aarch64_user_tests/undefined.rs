//! User exceptions retain coherent raw/private and public retirement counts.
use super::*;
use crate::isa::arm::common::features::ArmFeatures;

#[test]
fn undefined_user_events_and_saved_contexts_retire_only_the_replacement() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-undefined-retirement/corpus.json"
    )))
    .unwrap();
    for record in corpus["records"].as_array().unwrap() {
        let word = record["word"].as_u64().unwrap() as u32;
        let (mut source, _) = user_vcpu(&[word]);
        source
            .set_aarch64_fp_features(
                (ArmFeatures::FP16
                    | ArmFeatures::FHM
                    | ArmFeatures::JSCVT
                    | ArmFeatures::FCMA
                    | ArmFeatures::FRINTTS
                    | ArmFeatures::BF16
                    | ArmFeatures::I8MM
                    | ArmFeatures::DOTPROD)
                    .bits(),
            )
            .unwrap();
        for _ in 0..2 {
            assert!(matches!(
                source.step_insn(),
                Err(Error::GuestEvent { vector: 0 })
            ));
            assert_eq!((source.current_pc(), source.instruction_count()), (CODE, 0));
            assert_eq!(
                source.take_user_trap(),
                Some(A64UserTrap::Exception {
                    ec: 0,
                    iss: 0,
                    pc: CODE
                })
            );
            assert_eq!(source.take_user_trap(), None);
        }
        assert!(matches!(
            source.step_insn(),
            Err(Error::GuestEvent { vector: 0 })
        ));
        let public = source.get_state().unwrap();
        let raw = source.capture_backend_context().unwrap().unwrap();
        let (mut target, memory) = user_vcpu(&[word]);
        target
            .restore_checkpoint_context(&public, &Default::default(), Some(&raw))
            .unwrap();
        assert_eq!((target.current_pc(), target.instruction_count()), (CODE, 0));
        assert_eq!(
            target.take_user_trap(),
            Some(A64UserTrap::Exception {
                ec: 0,
                iss: 0,
                pc: CODE
            })
        );
        assert_eq!(target.take_user_trap(), None);
        memory
            .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(CODE))
            .unwrap();
        assert!(target.step_insn().unwrap().is_none());
        assert_eq!(
            (target.current_pc(), target.instruction_count()),
            (CODE + 4, 1)
        );
        assert_eq!(state(&target).regs.x[9], 1);
    }
}

#[test]
fn actual_parent_undefined_contexts_preserve_historical_counter_compensation() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/development/a64-undefined-retirement/fixtures");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["producer_commit"],
        "1f1d33e4c628ed9fa0662d5b0cf4632aea2a99de"
    );
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let prefix = fixture["prefix"].as_u64().unwrap();
        let pc = fixture["pc"].as_u64().unwrap();
        let public: CpuState = crate::codec::deserialize_strict(
            &std::fs::read(root.join(format!("{name}.state.bin"))).unwrap(),
        )
        .unwrap();
        let raw = crate::vm::snapshot::BackendContext {
            kind: crate::vm::snapshot::AARCH64_CONTEXT,
            data: std::fs::read(root.join(format!("{name}.backend.bin"))).unwrap(),
        };
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
        memory
            .write_slice(&0xce02_9420u32.to_le_bytes(), GuestAddress(pc))
            .unwrap();
        let pages = Arc::new(Pages::default());
        pages.map(0, R | W | X);
        let mut target = Aarch64Vcpu::new_user(0, memory.clone(), pages);
        target
            .restore_checkpoint_context(&public, &Default::default(), Some(&raw))
            .unwrap();
        assert_eq!(
            (target.current_pc(), target.instruction_count()),
            (pc, prefix)
        );
        assert_eq!(state(&target).regs.x[20], prefix);
        let expected = A64UserTrap::Exception { ec: 0, iss: 0, pc };
        assert_eq!(target.take_user_trap(), Some(expected.clone()));
        assert_eq!(target.take_user_trap(), None);
        assert!(matches!(
            target.step_insn(),
            Err(Error::GuestEvent { vector: 0 })
        ));
        assert_eq!(
            (target.current_pc(), target.instruction_count()),
            (pc, prefix)
        );
        assert_eq!(target.take_user_trap(), Some(expected));
        memory
            .write_slice(&0x9100_0529u32.to_le_bytes(), GuestAddress(pc))
            .unwrap();
        assert!(target.step_insn().unwrap().is_none());
        assert_eq!(
            (target.current_pc(), target.instruction_count()),
            (pc + 4, prefix + 1)
        );
        assert_eq!(
            (state(&target).regs.x[9], state(&target).regs.x[20]),
            (1, prefix)
        );
    }
}
