use rax::user::windows::memory::Mem;
use rax::user::windows::process::RunStatus;
use rax::user::windows::{WindowsConfig, WindowsProcess};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn snapshot(process: &WindowsProcess) {
    let state = process.state();
    println!(
        "DEPSET_PROCESS arch={} peb={:#x} guest-version={}.{}.{}",
        state.arch,
        state.peb,
        state.cfg.version.major,
        state.cfg.version.minor,
        state.cfg.version.build
    );
    for (tid, thread) in &state.threads {
        let sp = thread.cpu.sp();
        println!(
            "DEPSET_STOP tid={tid} pc={:#x} sp={sp:#x} eax={:#x} state={:?}",
            thread.cpu.pc(),
            thread.cpu.gpr(0),
            thread.state
        );
        let words: Vec<_> = (0..10).map(|i| state.space.u32(sp + i * 4)).collect();
        println!("DEPSET_STACK {words:#x?}");
        let args: Vec<_> = (0..4).map(|i| state.space.u32(sp + 8 + i * 4)).collect();
        println!("DEPSET_ARGS {args:#x?}");
        if let [Ok(handle), Ok(class), Ok(output), Ok(length)] = args.as_slice() {
            println!(
                "DEPSET_QUERY handle={handle:#x} class={class} input={output:#x} bytes={length}"
            );
            println!(
                "DEPSET_OUTPUT {:?}",
                state
                    .space
                    .bytes(u64::from(*output), (*length).min(64) as usize)
            );
            println!("DEPSET_FLAGS {:#x?}", state.space.u32(u64::from(*output)));
        }
        for i in 0..2 {
            if let Ok(value) = state.space.u32(sp + i * 4) {
                let address = u64::from(value);
                let owner = state
                    .modules
                    .by_address(address)
                    .map(|(_, m)| (m.name.as_str(), address - m.base));
                println!(
                    "DEPSET_CALLER index={i} address={address:#x} owner={owner:?} bytes={:?}",
                    state.space.bytes(address, 48)
                );
            }
        }
    }
}
fn main() {
    let image = std::fs::read(std::env::args().nth(1).expect("immutable fixture path"))
        .expect("read fixture");
    let mut config =
        WindowsConfig::embedded("C:\\native-fault.exe", vec![], vec![], 4096).expect("config");
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    config.slice_insns = 4096;
    let mut process = WindowsProcess::spawn_image(config, image).expect("spawn fixture");
    let deadline = Instant::now() + Duration::from_secs(60);
    let cancelled = AtomicBool::new(false);
    for turn in 0..16384 {
        assert!(Instant::now() < deadline, "original observation deadline");
        match process.run_slice(1, &cancelled) {
            RunStatus::BudgetExhausted => {}
            result => {
                println!("DEPSET_TERMINAL turn={turn} result={result:?}");
                snapshot(&process);
                return;
            }
        }
    }
    panic!("original observation instruction budget exhausted");
}
