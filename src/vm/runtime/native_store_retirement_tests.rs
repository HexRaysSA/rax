//! Acknowledged native output never replays an external effect after PC failure.
use super::*;
use crate::backend::hvf::HvfArm64Vm;
use crate::devices::bus::MmioDevice;
const OUTPUT: u64 = 0x0e00_0000;
type Writes = Arc<std::sync::Mutex<Vec<(u64, Vec<u8>)>>>;
struct ExternalOutput(Writes);
impl MmioDevice for ExternalOutput {
    fn read(&mut self, _address: u64, data: &mut [u8]) {
        data.fill(0);
    }
    fn write(&mut self, address: u64, data: &[u8]) {
        self.0.lock().unwrap().push((address, data.to_vec()));
    }
}
fn attach(vm: &mut Vmm, writes: &Writes) {
    vm.mmio_bus
        .register(
            MmioRange {
                base: OUTPUT,
                len: 8,
            },
            Box::new(ExternalOutput(writes.clone())),
        )
        .unwrap();
}

#[test]
#[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
fn acknowledged_store_file_retries_only_pc_without_replaying_external_output() {
    // The sink is host-owned external output, deliberately reattached after
    // restore. This does not claim serialization of arbitrary device callbacks.
    for (count, after_mutation) in [(1, false), (2, false), (4, false), (1, true)] {
        let fixture = Fixture::new();
        let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut source = Vmm::new_resume(fixture.config(count)).unwrap();
        psci::boot_native_secondaries(&mut source);
        attach(&mut source, &writes);
        let words = [
            0xf9000020u32,
            0xd297dde2,
            0x52800100,
            0x72b08000,
            0xd4000002,
        ];
        for (i, word) in words.into_iter().enumerate() {
            source
                .guest_mem
                .memory()
                .write_obj(word.to_le(), GuestAddress(CODE + i as u64 * 4))
                .unwrap();
        }
        publish_native_code(&source.guest_mem, CODE, 20);
        let payload = 0xfedc_ba98_7654_3210u64.to_le_bytes().to_vec();
        let expected = vec![(OUTPUT, payload.clone())];
        let CpuState::Aarch64(mut state) = source.vcpus[0].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.pstate = 0x3c5;
        state.regs.x[0] = u64::from_le_bytes(payload.try_into().unwrap());
        state.regs.x[1] = OUTPUT;
        state.regs.x[2] = 0;
        source.vcpus[0]
            .set_state(&CpuState::Aarch64(state))
            .unwrap();
        let native = source.vm.as_any().downcast_ref::<HvfArm64Vm>().unwrap();
        if after_mutation {
            native.fail_next_gpr_writes_after_mutation(0, 31, 1);
        } else {
            native.fail_next_gpr_writes(0, 31, 1);
        }
        let error = source.run().unwrap_err().to_string();
        assert!(
            error.contains(if after_mutation {
                "injected native GPR write failure after mutation"
            } else {
                "injected native GPR write failure"
            }),
            "the selected PC writer fault must escape dispatch: {error}"
        );
        assert_eq!(writes.lock().unwrap().as_slice(), expected.as_slice());
        let context = private_states(&source).remove(0);
        let phase = context
            .pending_write
            .as_ref()
            .unwrap()
            .retirement
            .as_ref()
            .unwrap();
        assert!(phase.acknowledged);
        assert_eq!(phase.next_pc, CODE + 4);
        assert_eq!(
            context.public.regs.pc,
            CODE + if after_mutation { 4 } else { 0 }
        );
        assert!(source.vcpus[0].io_completion_result().is_err());
        assert!(source.vcpus[0].set_current_pc(CODE + 0x100).is_err());
        assert_eq!(private_states(&source)[0], context);
        // Both PC frontiers above came from real owner-thread SDK writes.
        // Only their reported errors are injected by the test wrapper.
        let saved = source.take_snapshot_bundle(0).unwrap();
        saved.save(&fixture.checkpoint).unwrap();
        let loaded = SnapshotBundle::load(&fixture.checkpoint).unwrap();
        drop(source);
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut target = Vmm::new_resume_bundle(config, &loaded).unwrap();
        attach(&mut target, &writes);
        assert!(
            private_states(&target)[0]
                .pending_write
                .as_ref()
                .unwrap()
                .retirement
                .as_ref()
                .unwrap()
                .acknowledged
        );
        target.run().unwrap();
        assert_eq!(
            writes.lock().unwrap().as_slice(),
            expected.as_slice(),
            "acknowledged device output replayed"
        );
        let after = private_states(&target).remove(0);
        assert!(after.pending_write.is_none());
        assert_eq!(after.public.regs.pc, CODE + 20);
        assert_eq!(after.public.regs.x[2], 0xbeef);
        target.vcpus[0].io_completion_result().unwrap();
        assert!(target.vcpus[0].complete_io_out().is_err());
    }
}
