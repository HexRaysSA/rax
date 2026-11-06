//! Native guest page-table replacement across deferred MMIO boundaries.
use super::*;
use std::sync::{
    Barrier,
    atomic::{AtomicBool, Ordering},
};

const PDE: u64 = 0x4000;
const OLD: u64 = MMIO & !0x1f_ffff;
const NEW: u64 = OLD + 0x20_0000;
const OBSERVED: u64 = 0xa000;
const WRITER_COUNT: u64 = 0xa008;
const WRITER_CODE: u64 = 0x1_8000;
const REPLY: u64 = 0x8877_6655_4433_2211;

fn next(cpu: &mut dyn VCpu) -> rax::error::Result<VcpuExit> {
    for _ in 0..100 {
        if let Some(exit) = cpu.run_host_slice(Duration::from_millis(100))? {
            return Ok(exit);
        }
    }
    Err(rax::error::Error::Emulator(
        "coherence probe exceeded 100 finite turns".into(),
    ))
}

fn program(mode: usize) -> (Vec<u8>, u64) {
    let mut code = vec![0x48, 0x8b, 0x07]; // First MOV RAX,[RDI] warms the translation.
    code.extend([0x48, 0xbb]); // MOV RBX,PDE.
    code.extend(PDE.to_le_bytes());
    code.extend([0x48, 0xba]); // MOV RDX,new or unchanged PDE.
    code.extend(((if mode == 0 { OLD } else { NEW }) | 0x83).to_le_bytes());
    code.extend([0x48, 0x89, 0x13, 0x0f, 0xae, 0xf0]); // MOV [RBX],RDX; MFENCE.
    if mode == 2 {
        code.extend([0x0f, 0x01, 0x3f]); // INVLPG [RDI].
    }
    if mode == 3 {
        // Observe the peer's guest-written counter inside the guest. Host RAM
        // inspection remains excluded until both native owners have stopped.
        code.extend([0x48, 0x83, 0x3c, 0x25]); // CMP qword [abs32],0.
        code.extend((WRITER_COUNT as u32).to_le_bytes());
        code.extend([0, 0x74, 0xf5]); // JE back to the nine-byte CMP.
    }
    let second_pc = CODE + code.len() as u64;
    code.extend([0x48, 0x8b, 0x07]); // Same linear address, old or new cached translation.
    code.extend([0x48, 0x89, 0x04, 0x25]); // MOV [abs32],RAX.
    code.extend((OBSERVED as u32).to_le_bytes());
    (code, second_pc)
}

fn writer(memory: &GuestMemoryWrapper, vm: &dyn Vm) -> Box<dyn VCpu> {
    // Only guest instructions modify the shared PDE while either CPU is entered.
    let mut code = vec![0x48, 0x89, 0x07, 0x48, 0x89, 0x17]; // MOV [RDI],RAX/RDX.
    code.extend([0x48, 0xff, 0x04, 0x25]); // INC qword [abs32].
    code.extend((WRITER_COUNT as u32).to_le_bytes());
    code.extend([0xeb, 0xf0]); // Back to the first store (16-byte loop).
    memory
        .memory()
        .write_slice(&code, GuestAddress(WRITER_CODE))
        .unwrap();
    let mut cpu = vm
        .create_vcpu(1, Arc::new(memory.memory().clone()))
        .unwrap();
    let CpuState::X86_64(mut state) = initial() else {
        unreachable!()
    };
    state.regs.rip = WRITER_CODE;
    state.regs.rdi = PDE;
    state.regs.rax = OLD | 0x83;
    state.regs.rdx = NEW | 0x83;
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
    cpu
}

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch < ' ' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn trial(output: &Path, case: usize, mode: usize, iteration: usize) -> bool {
    let (code, second_pc) = program(mode);
    let memory = guest_memory(&code);
    let backend = HvfBackend::new().unwrap();
    let vm = backend.create_vm().unwrap();
    vm.as_any()
        .downcast_ref::<HvfVm>()
        .unwrap()
        .register_memory(&memory)
        .unwrap();
    vm.configure_cpu_topology(if mode == 3 { 2 } else { 1 }, RAM)
        .unwrap();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    cpu.set_state(&initial()).unwrap();
    assert!(matches!(
        next(cpu.as_mut()).unwrap(),
        VcpuExit::MmioRead {
            addr: MMIO,
            size: 8
        }
    ));
    cpu.complete_io_in(&SEED.to_le_bytes());
    cpu.io_completion_result().unwrap();
    let peer = (mode == 3).then(|| writer(&memory, vm.as_ref()));
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let peer = peer.map(|mut peer| {
        let stop = stop.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let mut error = String::new();
            barrier.wait();
            while !stop.load(Ordering::Acquire) {
                match peer.run_host_slice(Duration::from_millis(100)) {
                    Ok(None) => {}
                    Ok(Some(exit)) => {
                        error = format!("unexpected peer exit: {exit:?}");
                        break;
                    }
                    Err(failure) => {
                        error = failure.to_string();
                        break;
                    }
                }
            }
            // Return the CPU so teardown occurs after the observer's request has ended.
            (peer, error)
        })
    });
    if mode == 3 {
        barrier.wait();
    }
    let mut address = 0;
    let result = (|| -> rax::error::Result<()> {
        match next(cpu.as_mut())? {
            VcpuExit::MmioRead { addr, size: 8 } => {
                address = addr;
                if addr != MMIO && addr != NEW + (MMIO - OLD) {
                    return Err(rax::error::Error::Emulator(format!(
                        "unexpected MMIO GPA {addr:#x}"
                    )));
                }
                if mode == 0 && addr != MMIO || mode == 2 && addr != NEW + (MMIO - OLD) {
                    return Err(rax::error::Error::Emulator(format!(
                        "coherent control GPA {addr:#x}"
                    )));
                }
            }
            exit => {
                return Err(rax::error::Error::Emulator(format!(
                    "unexpected observer exit: {exit:?}"
                )));
            }
        }
        cpu.complete_io_in(&REPLY.to_le_bytes());
        cpu.io_completion_result()?;
        if !matches!(next(cpu.as_mut())?, VcpuExit::Hlt) {
            return Err(rax::error::Error::Emulator(
                "observer did not reach HLT".into(),
            ));
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    let peer_error = peer
        .map(|peer| {
            let (peer, error) = peer.join().expect("peer thread panic");
            drop(peer);
            error
        })
        .unwrap_or_default();
    // Every guest writer is now stopped; inspect RAM through the public API.
    let pde = read_word(&memory, PDE);
    let writes = read_word(&memory, WRITER_COUNT);
    let observed = read_word(&memory, OBSERVED);
    let error = result
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    // Ordinary public reads intentionally reject a fenced owner. The stopped
    // capture API retains its complete readable terminal record instead.
    let captured = vm
        .checkpoint_boundary()
        .and_then(|boundary| cpu.capture_checkpoint_record(&boundary, None));
    let mut record_file = String::new();
    let (rip, marker, capture_error) = match captured {
        Ok((saved, Some(private))) => {
            let CpuState::X86_64(ref state) = saved.state else {
                unreachable!()
            };
            let bytes = rax::codec::serialize(&(
                &saved.state,
                &saved.emulator,
                private.kind,
                &private.data,
            ))
            .unwrap();
            record_file = format!("coherence-case-{case}.cpu");
            let path = output.parent().unwrap().join(&record_file);
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
            (state.regs.rip, state.regs.r10, String::new())
        }
        Ok((_, None)) => (0, 0, "native checkpoint record absent".into()),
        Err(error) => (0, 0, error.to_string()),
    };
    let mut retained = false;
    if error.contains("guest entry prohibited") {
        // All writers are stopped. Repairing the walk must not be mistaken for
        // recovery if the owner has already latched a permanent execution error.
        word(&memory, PDE, OLD | 0x83);
        retained = cpu.run_host_slice(Duration::from_millis(1)).is_err();
    }
    let passed = error.is_empty()
        && peer_error.is_empty()
        && capture_error.is_empty()
        && (mode != 3 || writes != 0)
        && observed == REPLY
        && marker == MARKER
        && rip == CODE + code.len() as u64 + 11;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output)
        .unwrap();
    writeln!(file, "{{\"case\":{case},\"name\":\"mmio-translation-coherence\",\"mode\":{mode},\"iteration\":{iteration},\"second_pc\":{second_pc},\"rip\":{rip},\"second_gpa\":{address},\"last_pde\":{pde},\"peer_iterations\":{writes},\"observed\":{observed},\"marker\":{marker},\"fence_retained_after_walk_repair\":{retained},\"error\":{},\"peer_error\":{},\"capture_error\":{},\"record_file\":{},\"passed\":{passed}}}", quoted(&error), quoted(&peer_error), quoted(&capture_error), quoted(&record_file)).unwrap();
    drop(cpu);
    drop(vm);
    passed
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut failed = 0;
    for mode in 0..4 {
        for iteration in 0..4 {
            failed += usize::from(!trial(output, mode * 4 + iteration, mode, iteration));
        }
    }
    println!("{{\"cases\":16,\"failed\":{failed},\"guest_execution_performed\":true}}");
    if failed != 0 {
        std::process::exit(1);
    }
}
