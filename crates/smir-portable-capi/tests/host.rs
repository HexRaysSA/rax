//! The host interface, called as a C program calls it, and from a C program.

use rax_smir_portable_capi::*;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A module whose `main` writes the first five bytes of its second argument
/// and returns its argument count plus 100.
fn object() -> PathBuf {
    repository().join("crates/smir-portable/tests/interp/programs/services.smo")
}

fn bytes(text: &[u8]) -> RaxPortableBytesV1 {
    RaxPortableBytesV1 {
        data: text.as_ptr(),
        length: text.len() as u64,
    }
}

fn config(grants: &[RaxPortableBytesV1], profile: &[u8]) -> RaxPortableConfigV1 {
    RaxPortableConfigV1 {
        size: size_of::<RaxPortableConfigV1>() as u32,
        version: 1,
        workers: 0,
        memory_bytes: 0,
        stack_bytes: 0,
        atomic_bytes: 0,
        code_bytes: 0,
        profile: bytes(profile),
        personality: bytes(b"portable"),
        capabilities: grants.as_ptr(),
        capability_count: grants.len() as u64,
        imports: std::ptr::null(),
        import_count: 0,
    }
}

fn context(grants: &[&[u8]], profile: &[u8]) -> Result<RaxPortableHandleV1, u32> {
    let grants: Vec<_> = grants.iter().map(|name| bytes(name)).collect();
    let mut handle = RaxPortableHandleV1::default();
    // SAFETY: the structures are whole and outlive the call.
    match unsafe { rax_portable_v1_context_create(&config(&grants, profile), &mut handle) } {
        0 => Ok(handle),
        status => Err(status),
    }
}

/// A spawn record for the module at hand with these arguments.
fn spawn(arguments: &[&str]) -> Vec<u8> {
    let mut record = vec![1, 0, 0, 0];
    record.extend([0_u8; 32]);
    record.extend((arguments.len() as u32).to_le_bytes());
    for argument in arguments {
        record.extend((argument.len() as u32).to_le_bytes());
        record.extend(argument.as_bytes());
    }
    // No environment, no directory, nothing inherited.
    record.extend([0_u8; 12]);
    record
}

/// Run the module in a context and return the state it ended in and the
/// record of that.
fn run(context: RaxPortableHandleV1, spawn: &[u8]) -> (String, String) {
    let image = std::fs::read(object()).unwrap();
    let (mut module, mut process, mut request) = Default::default();
    let mut poll = RaxPortablePollV1 {
        size: size_of::<RaxPortablePollV1>() as u32,
        version: 1,
        state: bytes(b""),
        result: RaxPortableHandleV1::default(),
        error: 0,
        reserved0: 0,
    };
    let mut text = [0_u8; 512];
    let mut buffer = RaxPortableBufferV1 {
        data: text.as_mut_ptr(),
        capacity: text.len() as u64,
        written: 0,
    };
    // SAFETY: every pointer is to a live value of the type it is passed as.
    unsafe {
        assert_eq!(
            rax_portable_v1_module_verify(context, bytes(&image), &mut module),
            0
        );
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(spawn), &mut process),
            0
        );
        assert_eq!(rax_portable_v1_process_run(process, &mut request), 0);
        assert_eq!(rax_portable_v1_process_join(process, &mut poll), 0);
        assert_eq!(rax_portable_v1_record_read(poll.result, &mut buffer), 0);
        let state = std::slice::from_raw_parts(poll.state.data, poll.state.length as usize);
        for handle in [poll.result, request, process, module] {
            assert_eq!(rax_portable_v1_release(handle), 0);
        }
        (
            String::from_utf8(state.to_vec()).unwrap(),
            String::from_utf8(text[..buffer.written as usize].to_vec()).unwrap(),
        )
    }
}

#[test]
fn a_process_ends_with_what_its_program_returned() {
    for profile in [&b""[..], b"interpreter", b"native"] {
        let context = context(&[b"file", b"process"], profile).unwrap();
        // Three arguments, so `main` returns 103.
        assert_eq!(
            run(context, &spawn(&["host", "second", "third"])),
            (
                "exited".into(),
                r#"{"version":1,"reason":"normal","code":103,"thread":1,"trap":null}"#.into()
            )
        );
        // Without a spawn record there is one argument, and this program
        // reads its second: the fault is the record.
        let (state, record) = run(context, b"");
        assert_eq!(state, "failed");
        assert!(
            record.contains(r#""reason":"trap""#) && record.contains("pointer_provenance"),
            "{record}"
        );
        assert_eq!(rax_portable_v1_release(context), 0);
    }
}

#[test]
fn a_program_gets_only_what_its_context_grants() {
    // The module declares `file` and `process`; a context without one of
    // them does not run it.
    let context = context(&[b"file"], b"").unwrap();
    let (state, record) = run(context, b"");
    assert_eq!(state, "failed");
    assert_eq!(
        record,
        r#"{"version":1,"reason":"failed","code":13,"thread":1,"trap":{"code":"EXEC_CAPABILITY"}}"#
    );
}

#[test]
fn a_context_is_made_only_of_what_is_known() {
    assert!(
        context(
            &[b"clock", b"file", b"memory", b"process", b"sync", b"thread"],
            b""
        )
        .is_ok()
    );
    // Out of order, twice, or unknown.
    assert_eq!(context(&[b"process", b"file"], b""), Err(22));
    assert_eq!(context(&[b"file", b"file"], b""), Err(22));
    assert_eq!(context(&[b"network"], b""), Err(22));
    assert_eq!(context(&[], b"fast"), Err(22));
    let mut handle = RaxPortableHandleV1::default();
    let mut other = config(&[], b"");
    other.size -= 8;
    // SAFETY: the size says the structure is another; it is not read further.
    assert_eq!(
        unsafe { rax_portable_v1_context_create(&other, &mut handle) },
        22
    );
    let mut imports = config(&[], b"");
    imports.import_count = 1;
    // SAFETY: a count of functions with none there is refused before any
    // is looked at.
    assert_eq!(
        unsafe { rax_portable_v1_context_create(&imports, &mut handle) },
        22
    );
    // SAFETY: null pointers are refused.
    assert_eq!(
        unsafe { rax_portable_v1_context_create(std::ptr::null(), &mut handle) },
        22
    );
}

#[test]
fn a_context_runs_programs_of_the_personality_its_host_chose() {
    // The module of these tests says it is for `linux`. A context is for
    // one personality, if its host says which, and no program of another
    // is made a process there; where the machine is what, plays no part.
    let image = std::fs::read(object()).unwrap();
    for (personality, status) in [
        (&b""[..], 0),
        (b"portable", 0),
        (b"linux", 0),
        (b"darwin", 8),
        (b"windows", 8),
    ] {
        let mut chosen = config(&[], b"");
        chosen.personality = bytes(personality);
        let (mut context, mut module, mut process) = Default::default();
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(rax_portable_v1_context_create(&chosen, &mut context), 0);
            assert_eq!(
                rax_portable_v1_module_verify(context, bytes(&image), &mut module),
                0
            );
            assert_eq!(
                rax_portable_v1_process_create(context, module, bytes(b""), &mut process),
                status,
                "{}",
                String::from_utf8_lossy(personality)
            );
        }
        if status == 0 {
            assert_eq!(rax_portable_v1_release(process), 0);
        }
        assert_eq!(rax_portable_v1_release(module), 0);
        assert_eq!(rax_portable_v1_release(context), 0);
    }
    let mut unknown = config(&[], b"");
    unknown.personality = bytes(b"plan9");
    let mut handle = RaxPortableHandleV1::default();
    // SAFETY: a whole structure.
    assert_eq!(
        unsafe { rax_portable_v1_context_create(&unknown, &mut handle) },
        22
    );
}

#[test]
fn a_handle_names_one_thing_once() {
    let context = context(&[b"file", b"process"], b"").unwrap();
    let image = std::fs::read(object()).unwrap();
    let mut module = RaxPortableHandleV1::default();
    // SAFETY: live values of the right types.
    unsafe {
        assert_eq!(
            rax_portable_v1_module_verify(context, bytes(&image), &mut module),
            0
        );
        // A context is no module, and a module no context.
        let mut process = RaxPortableHandleV1::default();
        assert_eq!(
            rax_portable_v1_process_create(module, context, bytes(b""), &mut process),
            9
        );
        assert_eq!(
            rax_portable_v1_module_verify(module, bytes(&image), &mut process),
            9
        );
        // Another runtime's handle, another slot, another use of the slot.
        for stranger in [
            RaxPortableHandleV1 {
                instance: module.instance ^ 1,
                ..module
            },
            RaxPortableHandleV1 {
                slot: module.slot + 1000,
                ..module
            },
            RaxPortableHandleV1 {
                generation: module.generation + 1,
                ..module
            },
        ] {
            assert_eq!(rax_portable_v1_release(stranger), 9);
            assert_eq!(rax_portable_v1_retain(stranger), 9);
        }
        // A module of one context makes no process in another.
        let second = self::context(&[b"file", b"process"], b"").unwrap();
        assert_eq!(
            rax_portable_v1_process_create(second, module, bytes(b""), &mut process),
            9
        );
        // A spawn record that is none, or for another module.
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(b"\x01\0\0"), &mut process),
            22
        );
        let mut other = vec![1, 0, 0, 0];
        other.extend([7_u8; 32]);
        other.extend([0_u8; 16]);
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(&other), &mut process),
            22
        );
        // A process that was never started is not waited for, and a
        // request is not a process.
        let arguments = spawn(&["host", "second"]);
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(&arguments), &mut process),
            0
        );
        let mut poll = RaxPortablePollV1 {
            size: size_of::<RaxPortablePollV1>() as u32,
            version: 1,
            state: bytes(b""),
            result: RaxPortableHandleV1::default(),
            error: 0,
            reserved0: 0,
        };
        assert_eq!(rax_portable_v1_process_join(process, &mut poll), 22);
        assert_eq!(rax_portable_v1_poll(process, &mut poll), 9);
        poll.version = 3;
        assert_eq!(rax_portable_v1_process_join(process, &mut poll), 22);
        assert_eq!(rax_portable_v1_release(module), 0);
        assert_eq!(rax_portable_v1_release(module), 9);
        // The process keeps its module, released or not.
        let mut request = RaxPortableHandleV1::default();
        poll.version = 1;
        assert_eq!(rax_portable_v1_process_run(process, &mut request), 0);
        assert_eq!(rax_portable_v1_process_join(process, &mut poll), 0);
        assert_eq!(
            std::slice::from_raw_parts(poll.state.data, poll.state.length as usize),
            b"exited"
        );
    }
}

/// The directory the test's own executable is in, where the static library
/// is built too.
#[cfg(unix)]
fn built() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    executable.parent().unwrap().parent().unwrap().to_owned()
}

/// A module of functions over integers, which needs no capability:
/// `program_bump_counter(x)` adds `x` to a counter that starts at 100 and
/// returns the new value xor the old; `program_through_pointer(x)` faults
/// when `x` is odd.
fn library() -> PathBuf {
    repository().join("crates/smir-portable/tests/interp/programs/programs.smo")
}

/// The identifiers of the 32-bit and the 64-bit integer type in that module.
const INT32: u32 = 1;
const INT64: u32 = 5;

fn empty_poll() -> RaxPortablePollV1 {
    RaxPortablePollV1 {
        size: size_of::<RaxPortablePollV1>() as u32,
        version: 1,
        state: bytes(b""),
        result: RaxPortableHandleV1::default(),
        error: 0,
        reserved0: 0,
    }
}

/// Poll a request until it is no longer pending; the state and what it
/// came with.
fn settled(request: RaxPortableHandleV1) -> (String, RaxPortableHandleV1) {
    loop {
        let mut poll = empty_poll();
        // SAFETY: a poll structure of this version.
        let state = unsafe {
            assert_eq!(rax_portable_v1_poll(request, &mut poll), 0);
            std::slice::from_raw_parts(poll.state.data, poll.state.length as usize)
        };
        if state != b"pending" {
            return (String::from_utf8(state.to_vec()).unwrap(), poll.result);
        }
        assert_eq!(poll.result, RaxPortableHandleV1::default());
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// A loaded library, a process of it, and two of its functions.
struct Library {
    context: RaxPortableHandleV1,
    module: RaxPortableHandleV1,
    process: RaxPortableHandleV1,
    bump: RaxPortableHandleV1,
    through: RaxPortableHandleV1,
}

fn open(profile: &[u8]) -> Library {
    let context = context(&[], profile).unwrap();
    let image = std::fs::read(library()).unwrap();
    let (mut module, mut process, mut bump, mut through) = Default::default();
    // SAFETY: live values of the right types.
    unsafe {
        assert_eq!(
            rax_portable_v1_module_verify(context, bytes(&image), &mut module),
            0
        );
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(b""), &mut process),
            0
        );
        assert_eq!(
            rax_portable_v1_symbol(
                module,
                bytes(b""),
                bytes(b"program_bump_counter"),
                &mut bump
            ),
            0
        );
        assert_eq!(
            rax_portable_v1_symbol(
                module,
                bytes(b"example"),
                bytes(b"program_through_pointer"),
                &mut through
            ),
            0
        );
    }
    Library {
        context,
        module,
        process,
        bump,
        through,
    }
}

/// A value of a type of the module from its bytes.
fn value(module: RaxPortableHandleV1, ty: u32, bits: &[u8]) -> Result<RaxPortableHandleV1, u32> {
    let mut handle = RaxPortableHandleV1::default();
    // SAFETY: live values of the right types.
    match unsafe { rax_portable_v1_value_bits(module, ty, 0, bytes(bits), &mut handle) } {
        0 => Ok(handle),
        status => Err(status),
    }
}

/// Call a function with one argument and return how the call stood when it
/// had settled.
fn call(
    library: &Library,
    code: RaxPortableHandleV1,
    argument: RaxPortableHandleV1,
) -> (String, RaxPortableHandleV1) {
    let mut request = RaxPortableHandleV1::default();
    // SAFETY: one argument, and room for the request.
    assert_eq!(
        unsafe { rax_portable_v1_start(library.process, code, &argument, 1, &mut request) },
        0
    );
    let outcome = settled(request);
    assert_eq!(rax_portable_v1_release(request), 0);
    outcome
}

/// The one 64-bit value a call returned.
fn returned64(result: RaxPortableHandleV1) -> u64 {
    let (mut count, mut value) = (0_u64, RaxPortableHandleV1::default());
    let mut bits = [0_u8; 8];
    let mut buffer = RaxPortableBufferV1 {
        data: bits.as_mut_ptr(),
        capacity: 8,
        written: 0,
    };
    // SAFETY: live values of the right types.
    unsafe {
        assert_eq!(rax_portable_v1_result_count(result, &mut count), 0);
        assert_eq!(count, 1);
        assert_eq!(rax_portable_v1_result_at(result, 1, &mut value), 34);
        assert_eq!(rax_portable_v1_result_at(result, 0, &mut value), 0);
        assert_eq!(rax_portable_v1_value_read_bits(value, &mut buffer), 0);
        assert_eq!(buffer.written, 8);
        // The size alone, and too little room.
        let mut small = RaxPortableBufferV1 {
            data: std::ptr::null_mut(),
            capacity: 0,
            written: 0,
        };
        assert_eq!(rax_portable_v1_value_read_bits(value, &mut small), 0);
        assert_eq!(small.written, 8);
        small.capacity = 4;
        small.data = bits.as_mut_ptr();
        assert_eq!(rax_portable_v1_value_read_bits(value, &mut small), 34);
        // A result is no value, and a value no result.
        assert_eq!(rax_portable_v1_value_read_bits(result, &mut buffer), 9);
        assert_eq!(rax_portable_v1_result_count(value, &mut count), 9);
    }
    assert_eq!(rax_portable_v1_release(value), 0);
    assert_eq!(rax_portable_v1_release(result), 0);
    u64::from_le_bytes(bits)
}

#[test]
fn a_library_is_called_again_and_again_on_what_it_left() {
    for profile in [&b""[..], b"native"] {
        let library = open(profile);
        let mut counter = 100_u64;
        for x in [3_u64, 3, 1000] {
            let argument = value(library.module, INT64, &x.to_le_bytes()).unwrap();
            let (state, result) = call(&library, library.bump, argument);
            assert_eq!(state, "returned");
            assert_eq!(returned64(result), (counter + x) ^ counter);
            counter += x;
            assert_eq!(rax_portable_v1_release(argument), 0);
        }
        // It ends when it is joined, in good order, and takes no call after.
        let mut poll = empty_poll();
        let mut request = RaxPortableHandleV1::default();
        let argument = value(library.module, INT64, &[0; 8]).unwrap();
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(rax_portable_v1_process_join(library.process, &mut poll), 0);
            assert_eq!(
                std::slice::from_raw_parts(poll.state.data, poll.state.length as usize),
                b"exited"
            );
            assert_eq!(
                rax_portable_v1_start(library.process, library.bump, &argument, 1, &mut request),
                16
            );
            assert_eq!(
                rax_portable_v1_process_run(library.process, &mut request),
                16
            );
        }
        for handle in [
            poll.result,
            argument,
            library.bump,
            library.through,
            library.process,
            library.module,
            library.context,
        ] {
            assert_eq!(rax_portable_v1_release(handle), 0);
        }
    }
}

#[test]
fn a_call_that_faults_ends_the_library() {
    let library = open(b"");
    let odd = value(library.module, INT32, &1_u32.to_le_bytes()).unwrap();
    let (state, record) = call(&library, library.through, odd);
    assert_eq!(state, "failed");
    let mut text = [0_u8; 256];
    let mut buffer = RaxPortableBufferV1 {
        data: text.as_mut_ptr(),
        capacity: 256,
        written: 0,
    };
    // SAFETY: live values of the right types.
    unsafe {
        assert_eq!(rax_portable_v1_record_read(record, &mut buffer), 0);
    }
    let text = std::str::from_utf8(&text[..buffer.written as usize]).unwrap();
    assert!(
        text.contains(r#""reason":"trap""#) && text.contains("memory_permission"),
        "{text}"
    );
    // Whatever is called next finds the program ended, in the same way.
    let even = value(library.module, INT32, &2_u32.to_le_bytes()).unwrap();
    assert_eq!(call(&library, library.through, even).0, "failed");
    let mut poll = empty_poll();
    // SAFETY: a poll structure of this version.
    unsafe {
        assert_eq!(rax_portable_v1_process_join(library.process, &mut poll), 0);
        assert_eq!(
            std::slice::from_raw_parts(poll.state.data, poll.state.length as usize),
            b"failed"
        );
    }
}

#[test]
fn a_call_is_made_only_with_what_the_function_takes() {
    let library = open(b"");
    let mut request = RaxPortableHandleV1::default();
    let wide = value(library.module, INT64, &[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let narrow = value(library.module, INT32, &[7, 0, 0, 0]).unwrap();
    // SAFETY: live values of the right types; the counts are what is passed.
    unsafe {
        // Too few, too many, and one of another width.
        assert_eq!(
            rax_portable_v1_start(library.process, library.bump, &wide, 0, &mut request),
            22
        );
        let two = [wide, wide];
        assert_eq!(
            rax_portable_v1_start(library.process, library.bump, two.as_ptr(), 2, &mut request),
            22
        );
        assert_eq!(
            rax_portable_v1_start(library.process, library.bump, &narrow, 1, &mut request),
            22
        );
        // What is no value, and what is no function.
        assert_eq!(
            rax_portable_v1_start(
                library.process,
                library.bump,
                &library.module,
                1,
                &mut request
            ),
            9
        );
        assert_eq!(
            rax_portable_v1_start(library.process, wide, &wide, 1, &mut request),
            9
        );
        // A function of another module, though it is the same file.
        let other = open(b"");
        assert_eq!(
            rax_portable_v1_start(library.process, other.bump, &wide, 1, &mut request),
            9
        );
        // A name the module does not export.
        let mut code = RaxPortableHandleV1::default();
        assert_eq!(
            rax_portable_v1_symbol(library.module, bytes(b""), bytes(b"absent"), &mut code),
            2
        );
        assert_eq!(
            rax_portable_v1_symbol(library.process, bytes(b""), bytes(b"main"), &mut code),
            9
        );
    }
    // A value is made of a type the module has, with exactly its bytes and
    // no bit beyond its width.
    assert_eq!(value(library.module, 999_999, &[0]).err(), Some(22));
    assert_eq!(value(library.module, INT64, &[0; 4]).err(), Some(22));
    assert_eq!(value(library.module, INT32, &[0; 8]).err(), Some(22));
    const INT1: u32 = 2001;
    assert!(value(library.module, INT1, &[1]).is_ok());
    assert_eq!(value(library.module, INT1, &[2]).err(), Some(22));
    // None of that started the library: it can still run as an image, if
    // it has an entry, which this module has not.
    let mut poll = empty_poll();
    // SAFETY: a poll structure of this version.
    assert_eq!(
        unsafe { rax_portable_v1_process_join(library.process, &mut poll) },
        22
    );
}

/// One of the modules that are linked: `main` calls functions of `shapes`
/// and of `base`, and `shapes` functions of `base`.
fn part(context: RaxPortableHandleV1, name: &str) -> RaxPortableHandleV1 {
    let path = repository().join(format!(
        "crates/smir-portable/tests/interp/programs/linked-{name}.smo"
    ));
    let image = std::fs::read(path).unwrap();
    let mut module = RaxPortableHandleV1::default();
    // SAFETY: live values of the right types.
    assert_eq!(
        unsafe { rax_portable_v1_module_verify(context, bytes(&image), &mut module) },
        0,
        "{name}"
    );
    module
}

fn link(
    context: RaxPortableHandleV1,
    modules: &[RaxPortableHandleV1],
) -> Result<RaxPortableHandleV1, u32> {
    let mut linked = RaxPortableHandleV1::default();
    // SAFETY: as many handles as are counted, and room for one.
    match unsafe {
        rax_portable_x1_module_link(context, modules.as_ptr(), modules.len() as u64, &mut linked)
    } {
        0 => Ok(linked),
        status => Err(status),
    }
}

#[test]
fn modules_are_linked_into_one_program() {
    for profile in [&b""[..], b"native"] {
        let context = context(&[], profile).unwrap();
        let (main, shapes, base) = (
            part(context, "main"),
            part(context, "shapes"),
            part(context, "base"),
        );
        let (mut process, mut entry, mut order) = Default::default();
        // By itself `main` is a module and no program.
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(
                rax_portable_v1_process_create(context, main, bytes(b""), &mut process),
                8
            );
        }
        // Linked with what it needs, in whatever order, it is one.
        let program = link(context, &[main, base, shapes]).unwrap();
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(
                rax_portable_v1_process_create(context, program, bytes(b""), &mut process),
                0
            );
            assert_eq!(
                rax_portable_v1_symbol(program, bytes(b""), bytes(b"entry"), &mut entry),
                0
            );
            assert_eq!(
                rax_portable_v1_symbol(program, bytes(b""), bytes(b"order"), &mut order),
                0
            );
            // The functions of the others are theirs: `scale` is of `base`.
            let mut other = RaxPortableHandleV1::default();
            assert_eq!(
                rax_portable_v1_symbol(program, bytes(b""), bytes(b"scale"), &mut other),
                2
            );
        }
        let library = Library {
            context,
            module: program,
            process,
            bump: entry,
            through: order,
        };
        // entry(x) is area(x, 2) of `shapes` plus scale(x) of `base`: 9x.
        let argument = value(program, INT32, &5_u32.to_le_bytes()).unwrap();
        let (state, result) = call(&library, entry, argument);
        assert_eq!(state, "returned");
        let (mut value_handle, mut bits) = (RaxPortableHandleV1::default(), [0_u8; 4]);
        let mut buffer = RaxPortableBufferV1 {
            data: bits.as_mut_ptr(),
            capacity: 4,
            written: 0,
        };
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(rax_portable_v1_result_at(result, 0, &mut value_handle), 0);
            assert_eq!(
                rax_portable_v1_value_read_bits(value_handle, &mut buffer),
                0
            );
        }
        assert_eq!(u32::from_le_bytes(bits), 45);
        // order() is what the initializer of `shapes` found in `base`, plus
        // one: each module was initialized after what it needs.
        let mut request = RaxPortableHandleV1::default();
        // SAFETY: no arguments, and room for the request.
        assert_eq!(
            unsafe { rax_portable_v1_start(process, order, std::ptr::null(), 0, &mut request) },
            0
        );
        let (state, ordered) = settled(request);
        assert_eq!(state, "returned");
        assert_eq!(returned64(ordered), 8);

        // What does not link is no program: a module that is missing, one
        // given twice, one nobody needs, and none at all.
        assert_eq!(link(context, &[main, shapes]), Err(8));
        assert_eq!(link(context, &[main, shapes, base, base]), Err(8));
        assert_eq!(link(context, &[base, shapes]), Err(8));
        assert_eq!(link(context, &[]), Err(22));
        // Nor do modules of two contexts make one, or what is no module.
        let elsewhere = context_of_another();
        let foreign = part(elsewhere, "base");
        assert_eq!(link(context, &[main, shapes, foreign]), Err(9));
        assert_eq!(link(context, &[main, shapes, process]), Err(9));
        // A linked module is one like any other, and may be linked on.
        let again = link(context, &[program]).unwrap();
        assert_eq!(rax_portable_v1_release(again), 0);

        let mut poll = empty_poll();
        // SAFETY: a poll structure of this version.
        assert_eq!(
            unsafe { rax_portable_v1_process_join(process, &mut poll) },
            0
        );
        for handle in [
            poll.result,
            request,
            value_handle,
            result,
            argument,
            entry,
            order,
            process,
            program,
            foreign,
            elsewhere,
            main,
            shapes,
            base,
            context,
        ] {
            assert_eq!(rax_portable_v1_release(handle), 0);
        }
    }
}

/// A second context, which grants nothing.
fn context_of_another() -> RaxPortableHandleV1 {
    context(&[], b"").unwrap()
}

/// A library of the module that gives out and takes pointers: `open()` is
/// its store of two words, the first of which holds 5; `put(where, value)`
/// and `get(where)` write and read one word; `nothing()` is the null
/// pointer and `local()` the address of an object that ended with the call.
struct Handles {
    context: RaxPortableHandleV1,
    module: RaxPortableHandleV1,
    process: RaxPortableHandleV1,
}

impl Handles {
    fn open(profile: &[u8]) -> Self {
        let context = context(&[], profile).unwrap();
        let image = std::fs::read(
            repository().join("crates/smir-portable/tests/interp/programs/handles.smo"),
        )
        .unwrap();
        let (mut module, mut process) = Default::default();
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(
                rax_portable_v1_module_verify(context, bytes(&image), &mut module),
                0
            );
            assert_eq!(
                rax_portable_v1_process_create(context, module, bytes(b""), &mut process),
                0
            );
        }
        Self {
            context,
            module,
            process,
        }
    }

    /// Call a function and say how the call stood when it had settled.
    fn call(
        &self,
        name: &str,
        arguments: &[RaxPortableHandleV1],
    ) -> Result<(String, RaxPortableHandleV1), u32> {
        let (mut code, mut request) = Default::default();
        // SAFETY: live values of the right types, and as many arguments as
        // are counted.
        unsafe {
            assert_eq!(
                rax_portable_v1_symbol(self.module, bytes(b""), bytes(name.as_bytes()), &mut code),
                0
            );
            let status = rax_portable_v1_start(
                self.process,
                code,
                arguments.as_ptr(),
                arguments.len() as u64,
                &mut request,
            );
            assert_eq!(rax_portable_v1_release(code), 0);
            if status != 0 {
                return Err(status);
            }
        }
        let outcome = settled(request);
        assert_eq!(rax_portable_v1_release(request), 0);
        Ok(outcome)
    }

    /// The one value a call returns.
    fn value(&self, name: &str, arguments: &[RaxPortableHandleV1]) -> RaxPortableHandleV1 {
        let (state, result) = self.call(name, arguments).unwrap();
        assert_eq!(state, "returned", "{name}");
        let mut value = RaxPortableHandleV1::default();
        // SAFETY: room for a handle.
        assert_eq!(
            unsafe { rax_portable_v1_result_at(result, 0, &mut value) },
            0
        );
        assert_eq!(rax_portable_v1_release(result), 0);
        value
    }

    /// The word a pointer points at.
    fn word(&self, at: RaxPortableHandleV1) -> u64 {
        let (state, result) = self.call("get", &[at]).unwrap();
        assert_eq!(state, "returned");
        returned64(result)
    }
}

/// A pointer some bytes on from another.
fn moved(pointer: RaxPortableHandleV1, offset: u64) -> Result<RaxPortableHandleV1, u32> {
    let mut value = RaxPortableHandleV1::default();
    // SAFETY: room for a handle.
    match unsafe { rax_portable_v1_value_pointer(pointer, offset, &mut value) } {
        0 => Ok(value),
        status => Err(status),
    }
}

#[test]
fn a_pointer_a_call_returned_is_handed_back_and_moved() {
    for profile in [&b""[..], b"native"] {
        let library = Handles::open(profile);
        let store = library.value("open", &[]);
        assert_eq!(library.word(store), 5);
        // The second word of the store, written through the pointer to it.
        let second = moved(store, 8).unwrap();
        let seventy_seven = value(library.module, INT64, &77_u64.to_le_bytes()).unwrap();
        let (state, nothing) = library.call("put", &[second, seventy_seven]).unwrap();
        assert_eq!(state, "returned");
        let mut count = 1_u64;
        // SAFETY: room for a number.
        assert_eq!(
            unsafe { rax_portable_v1_result_count(nothing, &mut count) },
            0
        );
        assert_eq!(count, 0);
        assert_eq!((library.word(second), library.word(store)), (77, 5));
        // To one past the end and no further, from wherever in the object.
        let end = moved(store, 16).unwrap();
        assert_eq!(
            moved(second, 8).map(|same| rax_portable_v1_release(same)),
            Ok(0)
        );
        for (from, offset) in [(store, 17), (second, 9), (end, 1), (store, u64::MAX)] {
            assert_eq!(moved(from, offset), Err(34), "{offset}");
        }
        // The null pointer is moved by nothing; an object that ended with
        // its call is gone.
        let null = library.value("nothing", &[]);
        assert_eq!(
            moved(null, 0).map(|same| rax_portable_v1_release(same)),
            Ok(0)
        );
        assert_eq!(moved(null, 1), Err(34));
        let local = library.value("local", &[]);
        assert_eq!(moved(local, 0), Err(9));

        // A pointer has no bits for the host, and is no number to a function.
        let mut bits = [0_u8; 8];
        let mut buffer = RaxPortableBufferV1 {
            data: bits.as_mut_ptr(),
            capacity: 8,
            written: 0,
        };
        // SAFETY: a buffer of eight bytes.
        assert_eq!(
            unsafe { rax_portable_v1_value_read_bits(store, &mut buffer) },
            22
        );
        assert_eq!(library.call("put", &[store, store]).unwrap_err(), 22);
        assert_eq!(
            library
                .call("put", &[seventy_seven, seventy_seven])
                .unwrap_err(),
            22
        );
        assert_eq!(library.call("get", &[]).unwrap_err(), 22);
        // What is no pointer is not moved.
        assert_eq!(moved(seventy_seven, 0), Err(9));
        assert_eq!(moved(library.process, 0), Err(9));
        // SAFETY: nowhere to put the value.
        assert_eq!(
            unsafe { rax_portable_v1_value_pointer(store, 0, std::ptr::null_mut()) },
            22
        );
        // A pointer is of its process: another process of the same module
        // does not take it.
        let other = Handles::open(profile);
        assert_eq!(other.call("get", &[store]).unwrap_err(), 9);
        let theirs = other.value("open", &[]);
        assert_eq!(library.call("get", &[theirs]).unwrap_err(), 9);
        assert_eq!(other.word(theirs), 5);

        // When the process has ended its pointers are of nothing.
        let mut poll = empty_poll();
        // SAFETY: a poll structure of this version.
        assert_eq!(
            unsafe { rax_portable_v1_process_join(library.process, &mut poll) },
            0
        );
        assert_eq!(moved(store, 0), Err(9));
        assert_eq!(library.call("get", &[store]).unwrap_err(), 16);
        let mut other_poll = empty_poll();
        // SAFETY: as above.
        assert_eq!(
            unsafe { rax_portable_v1_process_join(other.process, &mut other_poll) },
            0
        );
        for handle in [
            poll.result,
            other_poll.result,
            store,
            second,
            end,
            null,
            local,
            theirs,
            seventy_seven,
            nothing,
            library.process,
            library.module,
            library.context,
            other.process,
            other.module,
            other.context,
        ] {
            assert_eq!(rax_portable_v1_release(handle), 0);
        }
    }
}

#[test]
fn a_runtime_describes_itself() {
    let blank = RaxPortableRuntimeX1 {
        size: size_of::<RaxPortableRuntimeX1>() as u32,
        version: 1,
        abi_major: 0,
        abi_minor: 0,
        revision: 0,
        profile: 0,
        implementation: [0; 32],
        helpers: [0; 32],
        service_catalogs: 0,
        reserved0: 0,
        services: [[0; 32]; RAX_PORTABLE_SERVICE_CATALOGS],
    };
    let mut runtime = blank;
    // SAFETY: a structure of this size and version.
    assert_eq!(unsafe { rax_portable_x1_runtime(&mut runtime) }, 0);
    assert_eq!(
        (runtime.abi_major, runtime.abi_minor, runtime.profile),
        (RAX_PORTABLE_ABI_MAJOR, RAX_PORTABLE_ABI_MINOR, 2)
    );
    let described = rax_smir_portable::runtime::describe().unwrap();
    assert_eq!(runtime.revision, described.revision);
    assert_eq!(runtime.implementation, described.implementation);
    assert_eq!(runtime.helpers, described.helpers);
    // Two catalogs of services so far, and zeros where there is none.
    assert_eq!(runtime.service_catalogs, 2);
    assert_eq!(runtime.services[..2], described.services[..]);
    assert_eq!(runtime.services[2..], [[0; 32]; 2]);
    // Another size or version, and nothing is written.
    for (size, version) in [(blank.size, 2), (blank.size - 8, 1), (0, 0)] {
        let mut other = RaxPortableRuntimeX1 {
            size,
            version,
            ..blank
        };
        // SAFETY: the structure is whole, whatever it says of itself.
        assert_eq!(unsafe { rax_portable_x1_runtime(&mut other) }, 22);
        assert_eq!(other.implementation, [0; 32]);
    }
    // SAFETY: no structure at all.
    assert_eq!(unsafe { rax_portable_x1_runtime(std::ptr::null_mut()) }, 22);
}

use std::sync::atomic::Ordering::SeqCst;

/// The identifier of the binary64 type in the modules the builders author.
const BINARY64: u32 = 2071;

/// Where the builders' modules are.
fn authored(name: &str) -> PathBuf {
    repository()
        .join("crates/smir-portable/tests/interp/programs")
        .join(name)
}

/// What the application of the host-function tests keeps: how often its
/// functions were called and released, what its misuses of a call were
/// answered with, and the calls it has yet to answer.
#[derive(Default)]
struct Application {
    calls: std::sync::atomic::AtomicU32,
    released: std::sync::atomic::AtomicU32,
    statuses: std::sync::Mutex<Vec<u32>>,
    waiting: std::sync::Mutex<Vec<RaxPortableHandleV1>>,
    fails: std::sync::atomic::AtomicBool,
}

type HostCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    RaxPortableHandleV1,
    *const RaxPortableHandleV1,
    u64,
    *mut RaxPortablePollV1,
) -> u32;

/// The bits of a value, as a number.
unsafe fn bits_of(value: RaxPortableHandleV1) -> u64 {
    let mut bits = [0_u8; 8];
    let mut buffer = RaxPortableBufferV1 {
        data: bits.as_mut_ptr(),
        capacity: 8,
        written: 0,
    };
    // SAFETY: a buffer of eight bytes.
    assert_eq!(
        unsafe { rax_portable_v1_value_read_bits(value, &mut buffer) },
        0
    );
    u64::from_le_bytes(bits)
}

/// Answer a call with one result of `width` bytes.
unsafe fn answer(
    call: RaxPortableHandleV1,
    result: u64,
    width: usize,
    poll: *mut RaxPortablePollV1,
) -> u32 {
    let mut value = RaxPortableHandleV1::default();
    // SAFETY: live values of the right types.
    unsafe {
        let made = rax_portable_v1_call_result_bits(
            call,
            0,
            bytes(&result.to_le_bytes()[..width]),
            &mut value,
        );
        if made != 0 {
            return made;
        }
        let status = rax_portable_v1_call_return(call, &value, 1, poll);
        rax_portable_v1_release(value);
        status
    }
}

/// `app:add`: answers before it returns, and tries what a call refuses.
unsafe extern "C" fn add_function(
    user: *mut std::ffi::c_void,
    call: RaxPortableHandleV1,
    arguments: *const RaxPortableHandleV1,
    count: u64,
    result: *mut RaxPortablePollV1,
) -> u32 {
    // SAFETY: `user` is the application of the test, which outlives its
    // context; the arguments are as many as are counted.
    unsafe {
        let application = &*user.cast::<Application>();
        application.calls.fetch_add(1, SeqCst);
        if application.fails.load(SeqCst) {
            return 5;
        }
        assert_eq!(count, 2);
        let sum = bits_of(*arguments) + bits_of(*arguments.add(1));
        let mut value = RaxPortableHandleV1::default();
        let mut other = empty_poll();
        let refused = [
            // A result the function has not, and bytes of another length
            // than the result has.
            rax_portable_v1_call_result_bits(call, 1, bytes(&[0; 4]), &mut value),
            rax_portable_v1_call_result_bits(call, 0, bytes(&[0; 8]), &mut value),
            // Fewer and more values than the function returns.
            rax_portable_v1_call_return(call, std::ptr::null(), 0, &mut other),
            rax_portable_v1_call_return(call, arguments, 2, &mut other),
            // What is no call.
            rax_portable_v1_call_result_bits(*arguments, 0, bytes(&[0; 4]), &mut value),
            rax_portable_v1_host_complete(*arguments, &other),
        ];
        let status = answer(call, sum & 0xffff_ffff, 4, result);
        // The call has its results: it takes no others.
        let again = answer(call, 0, 4, &mut other);
        let mut statuses = application.statuses.lock().unwrap();
        statuses.extend(refused);
        statuses.push(again);
        status
    }
}

/// `app:tick`: leaves the call pending, for the thread that answers.
unsafe extern "C" fn tick_function(
    user: *mut std::ffi::c_void,
    call: RaxPortableHandleV1,
    _arguments: *const RaxPortableHandleV1,
    count: u64,
    result: *mut RaxPortablePollV1,
) -> u32 {
    assert_eq!(count, 0);
    // SAFETY: as for `add_function`; the structure is the runtime's.
    unsafe {
        let application = &*user.cast::<Application>();
        application.calls.fetch_add(1, SeqCst);
        application.waiting.lock().unwrap().push(call);
        (*result).state = bytes(b"pending");
    }
    0
}

/// `app.math:scale`: a float times a number.
unsafe extern "C" fn scale_function(
    user: *mut std::ffi::c_void,
    call: RaxPortableHandleV1,
    arguments: *const RaxPortableHandleV1,
    _count: u64,
    result: *mut RaxPortablePollV1,
) -> u32 {
    // SAFETY: as for `add_function`.
    unsafe {
        let application = &*user.cast::<Application>();
        application.calls.fetch_add(1, SeqCst);
        let scaled = f64::from_bits(bits_of(*arguments)) * bits_of(*arguments.add(1)) as f64;
        answer(call, scaled.to_bits(), 8, result)
    }
}

unsafe extern "C" fn released_function(user: *mut std::ffi::c_void) {
    // SAFETY: as for `add_function`.
    let application = unsafe { &*user.cast::<Application>() };
    application.released.fetch_add(1, SeqCst);
}

/// The descriptors of the three functions, by name.
fn descriptors() -> std::collections::BTreeMap<String, Vec<u8>> {
    let text = std::fs::read_to_string(authored("hosts.descriptors.json")).unwrap();
    // A flat object of names and hex: read without a JSON library.
    text.lines()
        .filter_map(|line| line.trim().trim_end_matches(',').split_once(": "))
        .map(|(name, hex)| {
            let hex = hex.trim_matches('"');
            let record = (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
                .collect();
            (name.trim_matches('"').to_owned(), record)
        })
        .collect()
}

/// A registration of one of the functions.
fn import(
    name: &'static [u8],
    record: &[u8],
    call: HostCallback,
    application: &Application,
) -> RaxPortableHostImportV1 {
    RaxPortableHostImportV1 {
        size: size_of::<RaxPortableHostImportV1>() as u32,
        version: 1,
        name: bytes(name),
        admitted_descriptor: bytes(record),
        call: call as *const std::ffi::c_void,
        release: released_function as *const std::ffi::c_void,
        user: std::ptr::from_ref(application).cast_mut().cast(),
    }
}

/// A context that has these functions; its status if it is not made.
fn hosting(
    imports: &[RaxPortableHostImportV1],
    profile: &[u8],
) -> Result<RaxPortableHandleV1, u32> {
    let mut chosen = config(&[], profile);
    chosen.imports = imports.as_ptr();
    chosen.import_count = imports.len() as u64;
    let mut context = RaxPortableHandleV1::default();
    // SAFETY: whole structures that outlive the call.
    match unsafe { rax_portable_v1_context_create(&chosen, &mut context) } {
        0 => Ok(context),
        status => Err(status),
    }
}

#[test]
fn a_program_calls_functions_its_host_registered() {
    let records = descriptors();
    let module_bytes = std::fs::read(authored("hosts.smo")).unwrap();
    for profile in [&b""[..], b"native"] {
        let application = Application::default();
        let all = [
            import(b"app:add", &records["add"], add_function, &application),
            import(b"", &records["tick"], tick_function, &application),
            import(
                b"app.math:scale",
                &records["scale"],
                scale_function,
                &application,
            ),
        ];
        let context = hosting(&all, profile).unwrap();
        let (mut module, mut process) = Default::default();
        // SAFETY: live values of the right types.
        unsafe {
            assert_eq!(
                rax_portable_v1_module_verify(context, bytes(&module_bytes), &mut module),
                0
            );
            assert_eq!(
                rax_portable_v1_process_create(context, module, bytes(b""), &mut process),
                0
            );
        }
        let library = Handles {
            context,
            module,
            process,
        };
        let number = |bits: u32| value(module, INT32, &bits.to_le_bytes()).unwrap();
        let (one, two, three) = (number(1), number(2), number(3));
        // sum3(1, 2, 3): the host adds twice, answering before it returns.
        let (state, result) = library.call("sum3", &[one, two, three]).unwrap();
        assert_eq!(state, "returned");
        let mut sum = RaxPortableHandleV1::default();
        // SAFETY: room for a handle.
        unsafe {
            assert_eq!(rax_portable_v1_result_at(result, 0, &mut sum), 0);
            assert_eq!(bits_of(sum), 6);
        }
        assert_eq!(application.calls.load(SeqCst), 2);
        // What each call refused of the host: see `add_function`.
        assert_eq!(
            *application.statuses.lock().unwrap(),
            [34, 22, 22, 22, 9, 9, 16, 34, 22, 22, 22, 9, 9, 16]
        );
        // ticks(): the host leaves each call pending, and another thread
        // answers it; the program waits for each answer.
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for tick in 1..=2_u64 {
                    let call = loop {
                        if let Some(call) = application.waiting.lock().unwrap().pop() {
                            break call;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    };
                    let mut completion = empty_poll();
                    // SAFETY: live values of the right types.
                    unsafe {
                        // Nothing to complete it with yet.
                        assert_eq!(rax_portable_v1_host_complete(call, &completion), 22);
                        assert_eq!(answer(call, tick, 8, &mut completion), 0);
                        assert_eq!(rax_portable_v1_host_complete(call, &completion), 0);
                        // Once, and no more.
                        assert_eq!(rax_portable_v1_host_complete(call, &completion), 16);
                    }
                }
            });
            let (state, ticks) = library.call("ticks", &[]).unwrap();
            assert_eq!(state, "returned");
            assert_eq!(returned64(ticks), 3);
        });
        // scaled(1.5, 4): a float there and back.
        let half = value(module, BINARY64, &1.5_f64.to_bits().to_le_bytes()).unwrap();
        let four = value(module, INT64, &4_u64.to_le_bytes()).unwrap();
        let (state, scaled) = library.call("scaled", &[half, four]).unwrap();
        assert_eq!(state, "returned");
        assert_eq!(f64::from_bits(returned64(scaled)), 6.0);
        assert_eq!(rax_portable_v1_release(half), 0);
        // A host that fails ends the program: its functions have no way to
        // say so in what they return.
        application.fails.store(true, SeqCst);
        let (state, record) = library.call("sum3", &[one, two, three]).unwrap();
        assert_eq!(state, "failed");
        let mut text = [0_u8; 512];
        let mut buffer = RaxPortableBufferV1 {
            data: text.as_mut_ptr(),
            capacity: 512,
            written: 0,
        };
        // SAFETY: a buffer of that many bytes.
        assert_eq!(
            unsafe { rax_portable_v1_record_read(record, &mut buffer) },
            0
        );
        let text = String::from_utf8_lossy(&text[..buffer.written as usize]).into_owned();
        assert!(
            text.contains(r#""reason":"trap""#) && text.contains("host_call"),
            "{text}"
        );

        let mut poll = empty_poll();
        // SAFETY: a poll structure of this version.
        assert_eq!(
            unsafe { rax_portable_v1_process_join(process, &mut poll) },
            0
        );
        for handle in [
            poll.result,
            record,
            result,
            sum,
            one,
            two,
            three,
            four,
            process,
            module,
        ] {
            assert_eq!(rax_portable_v1_release(handle), 0);
        }
        // The host is told when its functions are no longer used: once
        // each, when the context and all it made are gone.
        assert_eq!(application.released.load(SeqCst), 0);
        assert_eq!(rax_portable_v1_release(context), 0);
        assert_eq!(application.released.load(SeqCst), 3);
    }
}

#[test]
fn a_context_has_only_functions_that_are_registered_as_described() {
    let records = descriptors();
    let application = Application::default();
    let module_bytes = std::fs::read(authored("hosts.smo")).unwrap();
    // A program whose host lacks one of its functions is no program there.
    let two = [
        import(b"", &records["add"], add_function, &application),
        import(b"", &records["scale"], scale_function, &application),
    ];
    let context = hosting(&two, b"").unwrap();
    let (mut module, mut process) = Default::default();
    // SAFETY: live values of the right types.
    unsafe {
        assert_eq!(
            rax_portable_v1_module_verify(context, bytes(&module_bytes), &mut module),
            0
        );
        assert_eq!(
            rax_portable_v1_process_create(context, module, bytes(b""), &mut process),
            8
        );
    }
    assert_eq!(rax_portable_v1_release(module), 0);
    assert_eq!(rax_portable_v1_release(context), 0);
    assert_eq!(application.released.load(SeqCst), 2);
    // What is no registration: bytes that are no descriptor, a name that
    // is not the descriptor's, no function, one function twice, a
    // structure of another version.
    let good = import(b"", &records["add"], add_function, &application);
    let mut nameless = import(b"", &records["add"], add_function, &application);
    nameless.call = std::ptr::null();
    let mut versioned = import(b"", &records["add"], add_function, &application);
    versioned.version = 2;
    for wrong in [
        vec![import(
            b"",
            &records["add"][1..],
            add_function,
            &application,
        )],
        vec![import(
            b"app:sub",
            &records["add"],
            add_function,
            &application,
        )],
        vec![nameless],
        vec![
            good,
            import(b"", &records["add"], scale_function, &application),
        ],
        vec![versioned],
    ] {
        assert_eq!(hosting(&wrong, b""), Err(22));
    }
    // Nothing was registered, so nothing is released.
    assert_eq!(application.released.load(SeqCst), 2);
}

// The command line is that of a Unix C compiler.
#[cfg(unix)]
#[test]
fn a_c_program_links_the_runtime_and_runs_a_module() {
    let library = built().join("librax_smir_portable_capi.a");
    assert!(library.exists(), "{} is not built", library.display());
    let consumer = built().join("capi-consumer");
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compiled = Command::new(&compiler)
        .args(["-std=c11", "-Wall", "-Werror", "-o"])
        .arg(&consumer)
        // The library may be built for x86-64 on a machine of the other
        // kind, which then runs the program under Rosetta.
        .args(if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            &["-arch", "x86_64"][..]
        } else {
            &[]
        })
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/consumer.c"))
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("include"))
        .arg("-I")
        .arg(repository().join("tools/smir-runtime-contract/include"))
        .arg(&library)
        .args(if cfg!(target_os = "macos") {
            &["-lSystem", "-lc", "-lm"][..]
        } else {
            &["-lpthread", "-ldl", "-lm"][..]
        })
        .output()
        .expect("a C compiler");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let ran = Command::new(&consumer)
        .arg(object())
        .arg("carried")
        .output()
        .expect("the consumer runs");
    assert_eq!(
        String::from_utf8_lossy(&ran.stdout),
        "context 0\nother version 22\nmodule 0\ngarbage 8\nprocess 0\ncarri\nrun 0\nrun again 16\n\
         join 0 exited\nsize 0 1\nsmall 34\n\
         record 0 {\"version\":1,\"reason\":\"normal\",\"code\":102,\"thread\":1,\"trap\":null}\n\
         poll 0 exited\nrecords differ 1\nsymbol 0 2\nstart 22\nrelease 0\nretain 0\nrelease 0 0 9\nread released 9\n\
         release others 0 0 0 0 0\nuse released 9\naggregate 38\n"
    );
    assert!(ran.status.success());
}
