use rax::user::windows::{
    WindowsConfig, WindowsProcess, fs::DriveMap, memory::Mem, process::RunStatus,
};
use std::{collections::VecDeque, path::PathBuf, sync::atomic::AtomicBool};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLogicalDrives() -> u32;
}

fn main() {
    println!("probe_library_sha256={}", env!("RAX_PROBE_LIBRARY_SHA256"));
    let arguments: Vec<_> = std::env::args().collect();
    let path = PathBuf::from(arguments.get(1).expect("program path"));
    let arena_bytes: u64 = arguments.get(2).expect("arena bytes").parse().unwrap();
    let seed: u64 = arguments.get(3).expect("seed").parse().unwrap();
    let command_arguments: Vec<String> = arguments.iter().skip(4).cloned().collect();
    assert!(
        !command_arguments.is_empty(),
        "explicit command arguments required"
    );
    println!("command_arguments={command_arguments:?}");
    let mut native = std::process::Command::new(&path)
        .args(&command_arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("native control spawn");
    // Drop only this disposable child's private writer to supply finite EOF.
    drop(native.stdin.take());
    let native_output = native
        .wait_with_output()
        .expect("native control completion");
    println!("NATIVE_EXIT={:?}", native_output.status.code());
    println!("NATIVE_STDOUT_HEX={}", encode(&native_output.stdout));
    println!("NATIVE_STDERR_HEX={}", encode(&native_output.stderr));
    let console = rax::user::console::CapturedConsole::new(Vec::new(), 65536).unwrap();
    let mut config = WindowsConfig::new(&path, command_arguments);
    config.console = rax::user::console::Console::Captured(console.clone());
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
        "authority host_filesystem={} native_libraries={} separate_sysroot=false",
        config.host_filesystem, config.native_libraries
    );
    println!(
        "configuration file_backed_spawn=true arena_bytes={arena_bytes} seed={seed} observation_slice=64 instruction_budget_limit=50000000 program={path:?}"
    );
    let mut process = WindowsProcess::spawn(config).unwrap();
    for module in &process.state().modules.list {
        println!(
            "module name={} base={:#x} size={:#x} entry={:#x}",
            module.name, module.base, module.size, module.entry
        );
    }
    dump_parameters(&process, "initial");
    let cancelled = AtomicBool::new(false);
    let mut history = VecDeque::new();
    let mut exception_seen = false;
    let mut last_parameters = process.state().params;
    for turn in 0..781_250u64 {
        let budget_bound = turn * 64;
        let state = process.state();
        let offsets = rax::user::windows::layout::offsets(state.arch);
        let current = state
            .space
            .ptr(state.peb + offsets.peb_process_parameters, offsets.ptr)
            .unwrap();
        if current != last_parameters {
            println!(
                "PARAMETER_MIGRATION sample={turn} previous={last_parameters:#x} current={current:#x}"
            );
            dump_parameters(&process, "migration");
            for line in &history {
                println!("migration_previous {line}");
            }
            last_parameters = current;
        }
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
        if matches!(result, RunStatus::Complete(_)) || turn + 1 == 781_250 {
            println!(
                "TERMINAL sample={turn} instruction_budget_bound={after_budget_bound} active_exception_seen={exception_seen} status={result:?}"
            );
            let state = process.state();
            for module in &state.modules.list {
                println!(
                    "terminal_module name={} base={:#x} size={:#x}",
                    module.name, module.base, module.size
                );
            }
            for (id, thread) in &state.threads {
                let handle = thread.cpu.gpr(0);
                let grant = state.objects.access(handle);
                use rax::user::windows::objects::Object;
                match state.objects.get(handle) {
                    Some(Object::Console(stream)) => println!(
                        "terminal_resource handle={handle:#x} grant={grant:x?} kind=Console({stream:?})"
                    ),
                    Some(Object::File(file)) => println!(
                        "terminal_resource handle={handle:#x} grant={grant:x?} kind=File directory={} null={} overlapped={} access={:#x} share={:#x}",
                        file.directory, file.null, file.overlapped, file.access, file.share
                    ),
                    Some(Object::Pipe { write, .. }) => println!(
                        "terminal_resource handle={handle:#x} grant={grant:x?} kind=Pipe write={write}"
                    ),
                    Some(object) => println!(
                        "terminal_resource handle={handle:#x} grant={grant:x?} kind={}",
                        object.type_name()
                    ),
                    None => println!("terminal_resource handle={handle:#x} kind=Missing"),
                }
                println!(
                    "terminal_all_registers thread={id} values={:x?}",
                    (0..31).map(|r| thread.cpu.gpr(r)).collect::<Vec<_>>()
                );
                if thread.cpu.gpr(0) == 134 && thread.cpu.gpr(2) == 32 {
                    let descriptor = thread.cpu.gpr(1);
                    if let Ok(header) = state.space.bytes(descriptor, 32) {
                        let input = u64::from_le_bytes(header[0..8].try_into().unwrap());
                        let output = u64::from_le_bytes(header[8..16].try_into().unwrap());
                        let input_bytes = u32::from_le_bytes(header[16..20].try_into().unwrap());
                        let output_bytes = u32::from_le_bytes(header[20..24].try_into().unwrap());
                        let version = u32::from_le_bytes(header[24..28].try_into().unwrap());
                        println!(
                            "policy_descriptor thread={id} address={descriptor:#x} input={input:#x} output={output:#x} input_bytes={input_bytes} output_bytes={output_bytes} version={version} header={header:02x?}"
                        );
                        if input_bytes <= 65536 && output_bytes <= 65536 {
                            println!(
                                "policy_input={:02x?}",
                                state.space.bytes(input, input_bytes as usize)
                            );
                            println!(
                                "policy_output={:02x?}",
                                state.space.bytes(output, output_bytes as usize)
                            );
                        }
                    }
                }
                // Read-only terminal evidence: ARM64 arguments8 onward are
                // stack arguments, not volatile registers x8 onward.
                println!(
                    "terminal_stack_arguments thread={id} sp={:#x} bytes={:02x?}",
                    thread.cpu.sp(),
                    state.space.bytes(thread.cpu.sp(), 64)
                );
                if let RunStatus::Complete(reason) = &result {
                    if format!("{reason:?}").contains("NtQueryDirectoryFileEx") {
                        let sp = thread.cpu.sp();
                        let flags = state.space.u32(sp).unwrap();
                        let descriptor = state.space.u64(sp + 8).unwrap();
                        let length = state.space.u16(descriptor).unwrap();
                        let maximum = state.space.u16(descriptor + 2).unwrap();
                        let buffer = state.space.u64(descriptor + 8).unwrap();
                        assert!(length <= 32766 && length % 2 == 0);
                        let raw = state.space.bytes(buffer, usize::from(length)).unwrap();
                        let units: Vec<_> = raw
                            .chunks_exact(2)
                            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                            .collect();
                        println!(
                            "DIRECTORY_REQUEST flags={flags:#x} descriptor={descriptor:#x} length={length} maximum={maximum} buffer={buffer:#x} units={units:x?} text={:?}",
                            String::from_utf16(&units)
                        );
                        if let Some(Object::File(file)) = state.objects.get(handle) {
                            println!(
                                "DIRECTORY_OWNER path={:?} host_path={:?} identity={:?}",
                                file.path, file.host_path, file.lifetime.identity
                            );
                        }
                    }
                }
                let object_attributes = thread.cpu.gpr(2);
                if let Ok(attrs) = state.space.bytes(object_attributes, 48) {
                    let name_ptr = u64::from_le_bytes(attrs[16..24].try_into().unwrap());
                    let root_handle = u64::from_le_bytes(attrs[8..16].try_into().unwrap());
                    if let Some(rax::user::windows::objects::Object::Key(key)) =
                        state.objects.get(root_handle)
                    {
                        // Diagnostic only: print the first derived Key.path field,
                        // without serializing captured registry values or descendants.
                        let debug = format!("{key:?}");
                        let raw = debug
                            .split_once("path: [")
                            .expect("derived Key path")
                            .1
                            .split_once(']')
                            .expect("path terminator")
                            .0;
                        let units: Vec<u16> = raw
                            .split(',')
                            .filter(|p| !p.trim().is_empty())
                            .map(|p| p.trim().parse().expect("u16 path unit"))
                            .collect();
                        assert!(units.len() <= 32767);
                        println!(
                            "terminal_root_key handle={root_handle:#x} grant={:#x} path={:?}",
                            state.objects.access(root_handle).unwrap(),
                            String::from_utf16(&units)
                        );
                    }
                    let flags = u32::from_le_bytes(attrs[24..28].try_into().unwrap());
                    println!(
                        "terminal_object_attributes thread={id} address={object_attributes:#x} root={root_handle:#x} flags={flags:#x} bytes={attrs:02x?}"
                    );
                    if let Ok(name) = state.space.bytes(name_ptr, 16) {
                        let bytes = u16::from_le_bytes(name[..2].try_into().unwrap()) as usize;
                        let maximum = u16::from_le_bytes(name[2..4].try_into().unwrap());
                        let buffer = u64::from_le_bytes(name[8..16].try_into().unwrap());
                        println!(
                            "terminal_object_name thread={id} descriptor={name_ptr:#x} buffer={buffer:#x} bytes={bytes} maximum={maximum}"
                        );
                        if bytes <= 4096 && bytes % 2 == 0 {
                            if let Ok(raw) = state.space.bytes(buffer, bytes) {
                                let units: Vec<_> = raw
                                    .chunks_exact(2)
                                    .map(|p| u16::from_le_bytes([p[0], p[1]]))
                                    .collect();
                                println!(
                                    "terminal_object_name_units thread={id} units={units:x?} text={:?}",
                                    String::from_utf16(&units)
                                );
                            }
                        }
                    }
                }
                let input = thread.cpu.gpr(2);
                let length = thread.cpu.gpr(3).min(256) as usize;
                println!(
                    "terminal_service_input thread={id} address={input:#x} length={length} bytes={:02x?}",
                    state.space.bytes(input, length)
                );
                let stack_page = thread.cpu.sp() & !0xfffu64;
                // Heap descriptor capture above owns this diagnostic; omit the large stack dump.
                if let Ok(stack) = state.space.bytes(stack_page, 8192) {
                    for offset in (0..=stack.len() - 32).step_by(8) {
                        let code =
                            u32::from_le_bytes(stack[offset..offset + 4].try_into().unwrap());
                        let flags =
                            u32::from_le_bytes(stack[offset + 4..offset + 8].try_into().unwrap());
                        let pc =
                            u64::from_le_bytes(stack[offset + 16..offset + 24].try_into().unwrap());
                        let parameters =
                            u32::from_le_bytes(stack[offset + 24..offset + 28].try_into().unwrap());
                        if code == 0xc000001d && flags <= 0x1f && pc != 0 && parameters <= 15 {
                            println!(
                                "terminal_exception_candidate record={:#x} status={code:#x} pc={pc:#x} parameters={parameters} instruction={:02x?}",
                                stack_page + offset as u64,
                                state.space.bytes(pc, 32)
                            );
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
            for (label, stream) in [
                ("STDOUT", rax::user::console::OutputStream::Stdout),
                ("STDERR", rax::user::console::OutputStream::Stderr),
            ] {
                let mut buffer = vec![0; 65536];
                let count = console.drain(stream, &mut buffer).unwrap();
                println!("GUEST_{label}_HEX={}", encode(&buffer[..count]));
            }
            dump_parameters(&process, "terminal");
            println!("MATRIX_NATIVE_CONTROL_COMPLETE=true");
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

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dump_parameters(process: &WindowsProcess, phase: &str) {
    let p = process.state();
    let o = rax::user::windows::layout::offsets(p.arch);
    let live = p
        .space
        .ptr(p.peb + o.peb_process_parameters, o.ptr)
        .unwrap();
    println!(
        "PARAMETER_BASE phase={phase} peb={:#x} initial={:#x} live={live:#x}",
        p.peb, p.params
    );
    for at in if live == p.params {
        vec![live]
    } else {
        vec![p.params, live]
    } {
        println!(
            "PARAMETER_HEADER phase={phase} base={at:#x} length={:x?} maximum={:x?} flags={:x?} env={:x?} env_size={:x?}",
            p.space.u32(at + o.pp_length),
            p.space.u32(at + o.pp_maximum_length),
            p.space.u32(at + o.pp_flags),
            p.space.ptr(at + o.pp_environment, o.ptr),
            p.space.ptr(at + o.pp_environment_size, o.ptr)
        );
        for (name, offset) in [
            ("command", o.pp_command_line),
            ("image", o.pp_image_path_name),
            ("cwd", o.pp_current_directory),
        ] {
            let length = p.space.u16(at + offset).unwrap();
            let buffer = p.space.ptr(at + offset + o.ptr, o.ptr).unwrap();
            println!(
                "PARAMETER_STRING phase={phase} base={at:#x} name={name} length={length} pointer={buffer:#x} raw={:02x?} text={:?}",
                p.space.bytes(buffer, usize::from(length).min(384)),
                p.space
                    .wstr(buffer, 192)
                    .map(|u| String::from_utf16_lossy(&u))
            );
        }
    }
}
