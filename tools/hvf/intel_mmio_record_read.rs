//! Read native diagnostic CPU tuples without creating a VM or entering a guest.
use rax::vm::{snapshot::EmulatorState, vcpu::CpuState};

fn main() {
    for argument in std::env::args_os().skip(1) {
        let path = std::path::PathBuf::from(argument);
        let bytes = std::fs::read(&path).unwrap();
        let (public, _, kind, private): (CpuState, EmulatorState, u32, Vec<u8>) =
            rax::codec::deserialize_strict(&bytes).unwrap();
        let CpuState::X86_64(state) = public else {
            panic!("non-x86 diagnostic record")
        };
        assert!(private.len() >= 8);
        let tag = std::str::from_utf8(&private[..8]).unwrap();
        assert!(matches!(
            tag,
            "RAXHVI01" | "RAXHVI02" | "RAXHVI03" | "RAXHVI04" | "RAXHVI05"
        ));
        println!(
            "{{\"kind\":{kind},\"bytes\":{},\"private_bytes\":{},\"producer\":\"{tag}\",\"rip\":{},\"rflags\":{},\"rax\":{},\"marker\":{}}}",
            bytes.len(),
            private.len(),
            state.regs.rip,
            state.regs.rflags,
            state.regs.rax,
            state.regs.r10,
        );
    }
}
