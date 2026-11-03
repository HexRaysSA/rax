//! A real Vmm::run guest checks scalar UART lanes in every REP INSD element.
use super::super::in_child;
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::Vmm;
use rax::vm::memory::vm::{Bytes, GuestAddress};
use std::io::Write;
use std::path::PathBuf;

// GNU as2.42; source, command, disassembly and exact byte digest are retained
// with the production I/O qualification. The raw PC loader enters at+0x200.
const CODE: &[u8] = &[
    0xba, 0xff, 0x03, 0x00, 0x00, 0xb0, 0x5a, 0xee, 0xba, 0xfc, 0x03, 0x00, 0x00, 0xbf, 0x00, 0x00,
    0x11, 0x00, 0xb9, 0x00, 0x01, 0x00, 0x00, 0xf3, 0x6d, 0xbe, 0x03, 0x00, 0x11, 0x00, 0xb9, 0x00,
    0x01, 0x00, 0x00, 0x80, 0x3e, 0x5a, 0x75, 0x13, 0x48, 0x83, 0xc6, 0x04, 0xe2, 0xf5, 0xc7, 0x04,
    0x25, 0x00, 0x04, 0x11, 0x00, 0x5a, 0x5a, 0x5a, 0x5a, 0xeb, 0x0b, 0xc7, 0x04, 0x25, 0x00, 0x04,
    0x11, 0x00, 0xd0, 0xba, 0xd0, 0xba, 0xba, 0x04, 0x06, 0x00, 0x00, 0xb8, 0x00, 0x20, 0x00, 0x00,
    0x66, 0xef, 0xf4,
];

struct Kernel(PathBuf);
impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn rep_input_uses_scalar_uart_register_lanes_in_the_actual_vmm_loop() {
    in_child(
        "io_completion::vmm::rep_input_uses_scalar_uart_register_lanes_in_the_actual_vmm_loop",
        || {
            let path =
                std::env::temp_dir().join(format!("rax-kvm-uart-rep-{}", std::process::id()));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let kernel = Kernel(path);
            let mut image = vec![0; 0x200];
            image.extend_from_slice(CODE);
            file.write_all(&image).unwrap();
            drop(file);
            let mut config = VmConfig::from_sources(
                CliConfig {
                    arch: Some(ArchKind::X86_64),
                    backend: Some(BackendKind::Kvm),
                    vcpus: Some(1),
                    kernel: Some(kernel.0.clone()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
            config.memory = MemorySize(64 * 1024 * 1024);
            let mut vm = Vmm::new(config).unwrap();
            vm.run().unwrap();
            let result: u32 = vm
                .guest_mem()
                .memory()
                .read_obj(GuestAddress(0x110400))
                .unwrap();
            assert_eq!(
                result, 0x5a5a5a5a,
                "the guest did not read UART.SCR=0x5a in the fourth byte of all256 input elements"
            );
            let mut bytes = vec![0; 1024];
            vm.guest_mem()
                .memory()
                .read_slice(&mut bytes, GuestAddress(0x110000))
                .unwrap();
            assert!(bytes.chunks_exact(4).all(|element| element[3] == 0x5a));
        },
    );
}
