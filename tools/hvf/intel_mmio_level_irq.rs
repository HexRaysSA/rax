//! Native UART and I/O APIC level delivery across a stopped AP checkpoint.
use super::*;
use rax::config::{CliConfig, VmConfig};
use rax::vm::{Vmm, snapshot::SnapshotBundle};

const OBS: u64 = 0x27_0000;
const AP_HANDLER: u64 = 0x2_0100;
const IRQ_RESUME: u64 = AP_HANDLER + 0x1c;
const SUCCESS: u32 = 0x700d_1a51;
const RTE_ACTIVE: u32 = 0xc041;
const RTE_IDLE: u32 = 0x8041;

// Relocation-free sections assembled from docs/development/hvf-ioapic/level-irq-guest.S.
const BSP: &[u8] = &[
    0xc7, 0x04, 0x25, 0x08, 0x02, 0x24, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc7, 0x04, 0x25, 0x0c, 0x02,
    0x24, 0x00, 0x00, 0x8e, 0x02, 0x00, 0xb9, 0x00, 0x00, 0xc0, 0xfe, 0xc7, 0x01, 0x19, 0x00, 0x00,
    0x00, 0x8b, 0x04, 0x25, 0x20, 0x00, 0x27, 0x00, 0xc1, 0xe0, 0x18, 0x89, 0x41, 0x10, 0xc7, 0x01,
    0x18, 0x00, 0x00, 0x00, 0xc7, 0x41, 0x10, 0x41, 0x80, 0x00, 0x00, 0x66, 0xba, 0xfc, 0x03, 0xb0,
    0x08, 0xee, 0x66, 0xba, 0xf9, 0x03, 0xb0, 0x02, 0xee, 0xbf, 0xa0, 0x0f, 0x00, 0x00, 0x81, 0x3c,
    0x25, 0x0c, 0x00, 0x27, 0x00, 0x51, 0x1a, 0x0d, 0x70, 0x74, 0x13, 0xe6, 0x80, 0xff, 0xcf, 0x75,
    0xed, 0xc7, 0x04, 0x25, 0x10, 0x00, 0x27, 0x00, 0x51, 0x1a, 0xd1, 0xba, 0xeb, 0x14, 0xb9, 0x08,
    0x00, 0x00, 0x00, 0xe6, 0x80, 0xe2, 0xfc, 0xc7, 0x04, 0x25, 0x10, 0x00, 0x27, 0x00, 0x51, 0x1a,
    0x0d, 0x70, 0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, 0xf4,
];
const AP: &[u8] = &[
    0x60, 0xff, 0x04, 0xad, 0x40, 0x00, 0x27, 0x00, 0xa1, 0x10, 0x00, 0xc0, 0xfe, 0xa3, 0x00, 0x00,
    0x27, 0x00, 0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, 0x66, 0xba, 0xfa, 0x03,
    0xec, 0xa2, 0x08, 0x00, 0x27, 0x00, 0xc7, 0x05, 0xb0, 0x00, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00,
    0xa1, 0x10, 0x00, 0xc0, 0xfe, 0xa3, 0x04, 0x00, 0x27, 0x00, 0xc7, 0x05, 0x0c, 0x00, 0x27, 0x00,
    0x51, 0x1a, 0x0d, 0x70, 0x61, 0xcf,
];

fn read(vm: &Vmm, address: u64) -> u32 {
    vm.guest_mem()
        .memory()
        .read_obj(GuestAddress(address))
        .unwrap()
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let directory = output.parent().unwrap();
    let mut observations = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .unwrap();
    for (case, count) in [2, 4].into_iter().enumerate() {
        let (mut source, kernel) = startup::boot(count);
        let target = count - 1;
        let bsp_pc = source.capture_cpu_states().unwrap()[0].state.pc();
        let memory = source.guest_mem().memory();
        memory.write_slice(BSP, GuestAddress(bsp_pc)).unwrap();
        memory.write_slice(AP, GuestAddress(AP_HANDLER)).unwrap();
        memory
            .write_obj(u32::from(target), GuestAddress(OBS + 0x20))
            .unwrap();
        source.run().unwrap();

        let visits = |vm: &Vmm| -> Vec<u32> {
            (0..count)
                .map(|id| read(vm, OBS + 0x40 + u64::from(id) * 4))
                .collect()
        };
        let expected: Vec<_> = (0..count).map(|id| u32::from(id == target)).collect();
        let pc = source.capture_cpu_states().unwrap()[usize::from(target)]
            .state
            .pc();
        assert_eq!(pc, IRQ_RESUME);
        assert_eq!(read(&source, OBS), RTE_ACTIVE);
        assert_eq!(visits(&source), expected);
        assert_eq!(read(&source, OBS + 12), 0);
        assert_eq!(read(&source, OBS + 16), 0);

        let checkpoint = directory.join(format!("level-irq-{count}.rxc"));
        assert!(!checkpoint.exists(), "checkpoint path must be new");
        let bundle = source.take_snapshot_bundle(0).unwrap();
        assert!(bundle.vm_context().is_some() && bundle.physical_memory().is_some());
        bundle.save(&checkpoint).unwrap();
        drop(bundle);
        drop(source);
        let source_kernel = kernel.0.clone();
        drop(kernel);
        assert!(!source_kernel.exists());

        let loaded = SnapshotBundle::load(&checkpoint).unwrap();
        let config = VmConfig::from_checkpoint_bundle(&loaded, CliConfig::default()).unwrap();
        let mut restored = Vmm::new_resume_bundle(config, &loaded).unwrap();
        assert_eq!(
            restored.capture_cpu_states().unwrap()[usize::from(target)]
                .state
                .pc(),
            IRQ_RESUME
        );
        assert_eq!(visits(&restored), expected);
        restored.run().unwrap();
        let active = read(&restored, OBS);
        let idle = read(&restored, OBS + 4);
        let iir = read(&restored, OBS + 8) & 15;
        let marker = read(&restored, OBS + 16);
        let observed = visits(&restored);
        assert_eq!(active, RTE_ACTIVE);
        assert_eq!(idle, RTE_IDLE);
        assert_eq!(iir, 2);
        assert_eq!(marker, SUCCESS);
        assert_eq!(observed, expected);
        assert!(!source_kernel.exists());
        drop(restored);
        drop(loaded);
        std::fs::remove_file(checkpoint).unwrap();
        writeln!(
            observations,
            "{{\"case\":{case},\"name\":\"native-level-irq-checkpoint\",\"cpus\":{count},\"target\":{target},\"handler_pc\":{pc},\"active_rte\":{active},\"idle_rte\":{idle},\"iir\":{iir},\"visits\":{observed:?},\"marker\":{marker},\"source_kernel_absent\":true,\"passed\":true}}"
        ).unwrap();
    }
    println!("{{\"cases\":2,\"failed\":0,\"guest_execution_performed\":true}}");
}
