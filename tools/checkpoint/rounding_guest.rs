//! Same original public API client across predecessor/current libraries.
use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::runtime::Vmm;
fn main() {
    let out = std::path::PathBuf::from(std::env::args_os().nth(1).expect("output directory"));
    let kernel = out.join("rounding.kernel");
    std::fs::write(&kernel, [0; 64]).unwrap();
    let requested = 128 * 1024 * 1024 + 1;
    let c = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            memory: Some(MemorySize(requested)),
            kernel: Some(kernel.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let vm = Vmm::new_resume(c).unwrap();
    let allocated = vm.guest_mem().size();
    vm.guest_mem()
        .memory()
        .write_slice(&[0xab], GuestAddress(allocated - 1))
        .unwrap();
    match vm.take_snapshot(53) {
        Ok(s) => {
            let decoded = s.decompress_memory();
            let cookie = decoded
                .as_ref()
                .ok()
                .and_then(|b| b.last())
                .map_or(-1, |b| i32::from(*b));
            let saved = s.save(out.join("rounding.rxc"));
            println!(
                "1\t{requested}\t{allocated}\t{}\t{}\t{}\t{cookie}\t{}",
                s.config.memory_bytes,
                s.memory_size,
                u8::from(decoded.is_ok()),
                u8::from(saved.is_ok())
            );
            if let Err(error) = decoded {
                eprintln!("decode:{error}");
            }
            if let Err(error) = saved {
                eprintln!("save:{error}");
            }
        }
        Err(e) => println!("0\t{requested}\t{allocated}\t{e}"),
    };
    std::fs::remove_file(kernel).unwrap();
}
