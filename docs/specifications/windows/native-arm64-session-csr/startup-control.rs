use rax::user::windows::{
    WindowsConfig, WindowsProcess, fs::DriveMap, memory::Mem, process::RunStatus,
};
use std::{collections::VecDeque, path::PathBuf, sync::atomic::AtomicBool};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLogicalDrives() -> u32;
}

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    let path = PathBuf::from(arguments.get(1).expect("program path"));
    let arena_bytes: u64 = arguments.get(2).expect("arena bytes").parse().unwrap();
    let seed: u64 = arguments.get(3).expect("seed").parse().unwrap();
    let mut config = WindowsConfig::new(
        &path,
        vec!["/d".into(), "/c".into(), "exit".into(), "0".into()],
    );
    config.native_libraries = true;
    config.arena_bytes = arena_bytes;
    config.slice_insns = 64;
    config.seed = Some(seed);
    // SAFETY: the native API takes no pointers and retains no resources.
    let mask = unsafe { GetLogicalDrives() };
    assert_ne!(mask, 0, "{}", std::io::Error::last_os_error());
    let mut drives = DriveMap::empty();
    for index in 0..26 {
        if mask & (1 << index) != 0 {
            let letter = char::from(b'A' + index);
            drives.set(letter, PathBuf::from(format!("{letter}:\\")));
        }
    }
    config.drives = drives;
    println!(
        "configuration file_backed_spawn=true arena_bytes={arena_bytes} seed={seed} observation_slice=64 instruction_budget_limit=10000000 program={path:?}"
    );
    let mut process = WindowsProcess::spawn(config).unwrap();
    for module in &process.state().modules.list {
        println!(
            "module name={} base={:#x} size={:#x} entry={:#x}",
            module.name, module.base, module.size, module.entry
        );
    }
    let cancelled = AtomicBool::new(false);
    let mut history = VecDeque::new();
    let mut exception_seen = false;
    for turn in 0..156_250u64 {
        let budget_bound = turn * 64;
        {
            let state = process.state();
            for (id, thread) in &state.threads {
                let pc = thread.cpu.pc();
                let bytes = state.space.bytes(pc, 4);
                if !exception_seen
                    && thread
                        .frames
                        .iter()
                        .any(|frame| frame.api.name == "KiUserExceptionDispatcher")
                {
                    println!(
                        "ACTIVE_EXCEPTION_SAMPLE sample={turn} instruction_budget_bound={budget_bound} thread={id} dispatcher_pc={pc:#x}"
                    );
                    for line in &history {
                        println!("previous {line}");
                    }
                    for frame in &thread.frames {
                        println!(
                            "exception_frame name={} entry_sp={:#x} cursor={:#x}",
                            frame.api.name, frame.entry_sp, frame.cursor
                        );
                        if let Some(caller) = frame.exception_caller.as_ref() {
                            println!(
                                "original_exception pc={:#x} sp={:#x} registers={:x?}",
                                caller.pc(),
                                caller.sp(),
                                (0..8).map(|r| caller.gpr(r)).collect::<Vec<_>>()
                            );
                            println!(
                                "original_instruction={:02x?}",
                                state.space.bytes(caller.pc(), 16)
                            );
                        }
                    }
                    println!(
                        "dispatcher_registers={:x?}",
                        (0..8).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>()
                    );
                    println!(
                        "dispatcher_stack={:02x?}",
                        state.space.bytes(thread.cpu.sp(), 512)
                    );
                    exception_seen = true;
                }
                if let Ok(bytes) = &bytes {
                    if bytes.len() == 4 {
                        let raw = u32::from_le_bytes(bytes.as_slice().try_into().unwrap());
                        if raw & 0xffe0_001f == 0xd400_0001
                            && (raw >> 5) & 0xffff == 0x1c
                            && thread.cpu.gpr(1) == 63
                        {
                            println!(
                                "FAULT_INFORMATION turn={turn} thread={id} exception_seen={exception_seen} pc={pc:#x} registers={:x?}",
                                (0..8).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>()
                            );
                            println!(
                                "fault_information_input={:02x?}",
                                state
                                    .space
                                    .bytes(thread.cpu.gpr(2), thread.cpu.gpr(3).min(256) as usize)
                            );
                            for line in &history {
                                println!("previous {line}");
                            }
                        }
                    }
                }
                history.push_back(format!("turn={turn} thread={id} pc={pc:#x} sp={:#x} bytes={bytes:02x?} registers={:x?}", thread.cpu.sp(), (0..8).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>()));
                if history.len() > 32 {
                    history.pop_front();
                }
            }
        }
        let result = process.run_slice(1, &cancelled);
        let after_budget_bound = (turn + 1) * 64;
        if matches!(result, RunStatus::Complete(_)) {
            println!(
                "TERMINAL sample={turn} instruction_budget_bound={after_budget_bound} active_exception_seen={exception_seen} status={result:?}"
            );
            let state = process.state();
            for module in &state.modules.list {
                println!("terminal_module name={} base={:#x} size={:#x}", module.name, module.base, module.size);
            }
            for (id, thread) in &state.threads {
                println!("terminal_all_registers thread={id} values={:x?}", (0..31).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>());
                let input = thread.cpu.gpr(2);
                let length = thread.cpu.gpr(3).min(256) as usize;
                println!("terminal_service_input thread={id} address={input:#x} length={length} bytes={:02x?}", state.space.bytes(input, length));
                let stack_page = thread.cpu.sp() & !0xfffu64;
                println!("terminal_stack_pages thread={id} base={stack_page:#x} bytes={:02x?}", state.space.bytes(stack_page, 8192));
                if let Ok(stack) = state.space.bytes(stack_page, 8192) {
                    for offset in (0..=stack.len() - 32).step_by(8) {
                        let code = u32::from_le_bytes(stack[offset..offset + 4].try_into().unwrap());
                        let flags = u32::from_le_bytes(stack[offset + 4..offset + 8].try_into().unwrap());
                        let pc = u64::from_le_bytes(stack[offset + 16..offset + 24].try_into().unwrap());
                        let parameters = u32::from_le_bytes(stack[offset + 24..offset + 28].try_into().unwrap());
                        if code == 0xc000001d && flags <= 0x1f && pc != 0 && parameters <= 15 {
                            println!("terminal_exception_candidate record={:#x} status={code:#x} pc={pc:#x} parameters={parameters} instruction={:02x?}", stack_page + offset as u64, state.space.bytes(pc, 32));
                        }
                    }
                }

                println!(
                    "terminal_thread id={id} pc={:#x} sp={:#x} registers={:x?}",
                    thread.cpu.pc(),
                    thread.cpu.sp(),
                    (0..8).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>()
                );
                for frame in &thread.frames {
                    println!(
                        "terminal_frame name={} entry_sp={:#x} cursor={:#x}",
                        frame.api.name, frame.entry_sp, frame.cursor
                    );
                    if let Some(caller) = frame.exception_caller.as_ref() {
                        println!(
                            "terminal_original_exception pc={:#x} sp={:#x} registers={:x?}",
                            caller.pc(),
                            caller.sp(),
                            (0..8).map(|r| caller.gpr(r)).collect::<Vec<_>>()
                        );
                        println!(
                            "terminal_original_instruction={:02x?}",
                            state.space.bytes(caller.pc(), 16)
                        );
                    }
                    println!(
                        "terminal_frame_stack={:02x?}",
                        state.space.bytes(frame.entry_sp, 512)
                    );
                }
            }
            for line in history {
                println!("last {line}");
            }
            return;
        }
        if turn % 15_625 == 0 {
            println!(
                "progress sample={turn} instruction_budget_bound={after_budget_bound} active_exception_seen={exception_seen}"
            );
        }
    }
    println!("DIAGNOSTIC_INSTRUCTION_LIMIT exception_seen={exception_seen}");
}
