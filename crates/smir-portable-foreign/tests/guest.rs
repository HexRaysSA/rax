//! Foreign code for real: the engine's own modules that call foreign code,
//! and the images they name, run with this crate's processor.
//!
//! The modules are `foreign-*.smo` of the engine's tests, and the images
//! `guest-*.elf` there, compiled from `guest.c` for x86-64 and for AArch64.
//! The engine's tests run the modules against a model of the image's stubs;
//! here the stubs themselves run, as machine code, on both engines and for
//! both machines, whatever machine this is.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rax_smir_portable::interp::{
    Called, Code, Crossing, ENTRY_BYTES, Engine, Exit, FRAME_BYTES, FRAME_REVISION, Foreign,
    ForeignFault, Instance, MAX_NESTED, NoHost, Outcome, Policy, STATUS_ENTERED, STATUS_RETURNED,
    run_on,
};
use rax_smir_portable::ir::{BridgeConvention, ForeignIsa, Module, Value};
use rax_smir_portable::{Error, Limits as Bounds};
use rax_smir_portable_foreign::{Hosting, Limits, Processor, Record, Refusal};
use serde_json::Value as Json;

const MACHINES: [(&str, ForeignIsa, BridgeConvention); 2] = [
    ("x86_64", ForeignIsa::X86_64, BridgeConvention::SysV64),
    ("aarch64", ForeignIsa::Aarch64, BridgeConvention::Aapcs64),
];

fn engine_tests() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../smir-portable/tests/interp")
}

fn module(machine: &str) -> Arc<Module> {
    let path = engine_tests().join(format!("programs/foreign-{machine}.smo"));
    let bytes = std::fs::read(path).expect("the object is there");
    Arc::new(Module::load(&bytes, Bounds::default()).expect("the object verifies and lowers"))
}

fn image(machine: &str) -> Vec<u8> {
    std::fs::read(engine_tests().join(format!("foreign/guest-{machine}.elf")))
        .expect("the image is there")
}

/// What `guest.json` says of the image for a machine: its SHA-256, and
/// where in the file each function is.
fn described(machine: &str) -> ([u8; 32], BTreeMap<String, (u64, u64)>) {
    let text = std::fs::read(engine_tests().join("foreign/guest.json")).unwrap();
    let all: Json = serde_json::from_slice(&text).unwrap();
    let hex = all[machine]["sha256"].as_str().unwrap();
    let mut identity = [0; 32];
    for (index, byte) in identity.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
    }
    let functions = all[machine]["functions"].as_object().unwrap();
    let ranges = functions.iter().map(|(name, range)| {
        let range = (
            range["offset"].as_u64().unwrap(),
            range["size"].as_u64().unwrap(),
        );
        (name.clone(), range)
    });
    (identity, ranges.collect())
}

/// A processor that has the image for a machine.
fn processor(machine: &str, isa: ForeignIsa, limits: Limits) -> Processor {
    let mut processor = Processor::new(isa, limits).expect("a processor within the limits");
    let identity = processor.load(&image(machine)).expect("the image loads");
    assert_eq!(identity, described(machine).0, "{machine}");
    processor
}

/// Run an exported function on both engines, each with a processor of its
/// own, and return how the run ended and what the processor recorded; the
/// engines must agree on how it ended.
fn ran(
    machine: &str,
    isa: ForeignIsa,
    function: &str,
    argument: u128,
    limits: Limits,
) -> Result<(Outcome, Record), Error> {
    let module = module(machine);
    let code = Code::compile(&module).expect("the module compiles for this host");
    let entry = module.export(function).expect("the function is exported");
    let on = |engine| {
        let processor = processor(machine, isa, limits);
        let record = processor.record();
        let mut host = Hosting::new(NoHost, processor);
        run_on(
            engine,
            &module,
            entry,
            &[Value::Int(argument)],
            Policy::default(),
            &mut host,
        )
        .map(|outcome| (outcome, record))
    };
    let (interpreted, compiled) = (on(Engine::Interpreter), on(Engine::Native(&code)));
    match (&interpreted, &compiled) {
        (Ok(one), Ok(other)) => {
            assert_eq!(one.0, other.0, "{machine} {function}");
            assert_eq!(
                one.1.crossings(),
                other.1.crossings(),
                "{machine} {function}"
            );
        }
        (Err(one), Err(other)) => assert_eq!(one.code(), other.code(), "{machine} {function}"),
        _ => panic!("{machine} {function}: the engines differ"),
    }
    interpreted
}

fn trapped(exit: &Exit) -> &str {
    match exit {
        Exit::Trap(fault) => &fault.code,
        other => panic!("{other:?} is no trap"),
    }
}

#[test]
fn portable_code_calls_machine_code_of_another_processor() {
    for (machine, isa, _) in MACHINES {
        for x in [5_i32, 0, -7, 715_827_882, i32::MIN] {
            let (outcome, record) = ran(
                machine,
                isa,
                "call_scale",
                u128::from(x as u32),
                Limits::default(),
            )
            .unwrap();
            let scaled = x.wrapping_mul(3).wrapping_add(1);
            assert_eq!(
                outcome.exit,
                Exit::Return(vec![Value::Int(u128::from(scaled as u32))]),
                "{machine} {x}"
            );
            // One crossing, nothing gone wrong, and the memory of the call
            // given back.
            assert_eq!((record.crossings(), record.held()), (1, 0));
            assert_eq!(record.reasons(), [""; 0]);
        }
    }
}

#[test]
fn an_image_keeps_its_data_as_long_as_its_process_lasts() {
    for (machine, isa, _) in MACHINES {
        let module = module(machine);
        let count = module.export("call_count").unwrap();
        for code in [None, Some(Arc::new(Code::compile(&module).unwrap()))] {
            // Twice: what one process counted, the next does not find.
            for _ in 0..2 {
                let processor = processor(machine, isa, Limits::default());
                let record = processor.record();
                let host = Hosting::new(NoHost, processor);
                let instance = Instance::start(
                    Arc::clone(&module),
                    code.clone(),
                    Policy::default(),
                    Box::new(host),
                )
                .unwrap();
                let mut counted = 100_u128;
                for by in [1_u128, 2, 40] {
                    counted += by;
                    assert_eq!(
                        instance.call(count, &[Value::Int(by)]).unwrap(),
                        Called::Returned(vec![Value::Int(counted)]),
                        "{machine}"
                    );
                }
                instance.finish().unwrap();
                assert_eq!((record.crossings(), record.held()), (3, 0));
            }
        }
    }
}

#[test]
fn code_that_does_not_come_back_as_a_bridge_does_ends_the_program() {
    let limits = Limits {
        time: Some(Duration::from_millis(50)),
        ..Limits::default()
    };
    for (machine, isa, _) in MACHINES {
        for (function, code, crossings, reason) in [
            // Code that reads where nothing is, and code that never returns:
            // neither comes back.
            ("call_fault", "foreign_fault", 0, "a read at 0x10 "),
            ("call_spin", "foreign_fault", 0, "ran longer than it may"),
            // A stub that returns without saying so, and one that returns
            // into another transition than it was entered for: both come
            // back, and the engine does not take what they bring.
            ("call_silent", "foreign_return", 1, ""),
            ("call_stale", "foreign_return", 1, ""),
        ] {
            let (outcome, record) = ran(machine, isa, function, 1, limits).unwrap();
            assert_eq!(trapped(&outcome.exit), code, "{machine} {function}");
            assert_eq!(
                (record.crossings(), record.held()),
                (crossings, 0),
                "{machine} {function}"
            );
            let reasons = record.reasons();
            if reason.is_empty() {
                assert_eq!(reasons, [""; 0], "{machine} {function}");
            } else {
                let [why] = &reasons[..] else {
                    panic!("{machine} {function}: one reason, not {reasons:?}")
                };
                assert!(
                    why.starts_with("thread 1: ") && why.contains(reason),
                    "{machine} {function}: {why}"
                );
            }
        }
    }
}

#[test]
fn a_module_runs_only_where_its_image_is() {
    let (machine, isa, _) = MACHINES[0];
    let module = module(machine);
    let entry = module.export("call_scale").unwrap();
    // A processor of the right kind that has no image: the module's bridges
    // name code it has not.
    let empty = Processor::new(isa, Limits::default()).unwrap();
    let refused = run_on(
        Engine::Interpreter,
        &module,
        entry,
        &[Value::Int(1)],
        Policy::default(),
        &mut Hosting::new(NoHost, empty),
    )
    .unwrap_err();
    assert_eq!(refused.code(), "EXEC_FOREIGN");
    assert!(
        refused.context().starts_with("no code at "),
        "{}",
        refused.context()
    );
    // An image is for one kind of processor, is loaded once, and is what a
    // module names by where in the file the code is.
    let mut processor = Processor::new(isa, Limits::default()).unwrap();
    assert_eq!(processor.load(&image("aarch64")), Err(Refusal::Machine));
    assert_eq!(
        processor.load(b"no image at all"),
        Err(Refusal::Format("no ELF file"))
    );
    let (identity, functions) = described(machine);
    assert_eq!(processor.load(&image(machine)), Ok(identity));
    assert_eq!(processor.load(&image(machine)), Ok(identity));
    let (offset, size) = functions["bridge_scale"];
    let at = processor.code(&identity, offset, size).unwrap();
    assert_eq!(
        processor.code(&identity, offset + 1, size - 1),
        Some(at + 1)
    );
    assert_eq!(processor.code(&[0; 32], offset, size), None);
    assert_eq!(processor.code(&identity, 0, 16), None, "the file's header");
    // An image that would lie where another is has no place.
    let mut other = image(machine);
    *other.last_mut().unwrap() ^= 1;
    assert!(matches!(processor.load(&other), Err(Refusal::Place(_))));
}

/// The frame the engine would make in the block at `block` for a call with
/// one `int`: the arena after the frame, the result at 128, and a
/// transition and a generation, which are any numbers here.
fn frame_in(block: u64) -> [u8; FRAME_BYTES] {
    let mut frame = [0; FRAME_BYTES];
    frame[0..4].copy_from_slice(&FRAME_REVISION.to_le_bytes());
    frame[64..68].copy_from_slice(&STATUS_ENTERED.to_le_bytes());
    let (arena, result) = (block + FRAME_BYTES as u64, block + 128);
    let places = [(16, arena), (24, 40), (32, result), (40, 4)];
    for (at, word) in places.into_iter().chain([(48, 9), (72, 9)]) {
        frame[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    frame
}

/// The first half of a crossing as the engine makes it, by hand: a block
/// with the frame, one `int` argument in the arena, and room for an `int`
/// result; and the code of the image's function `name` entered with it on
/// `thread`. The block, and how the code came back.
fn entered(
    processor: &mut Processor,
    machine: &str,
    thread: u64,
    convention: BridgeConvention,
    name: &str,
    x: i32,
) -> Result<(u64, Crossing), ForeignFault> {
    let (identity, functions) = described(machine);
    let (offset, size) = functions[name];
    let entry = processor
        .code(&identity, offset, size)
        .expect("the image has the function");
    let block = processor.allocate(144)?;
    let mut argument = [0; 40];
    for (at, word) in [(8, 4_u64), (16, 4), (24, 40)] {
        argument[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    argument[ENTRY_BYTES..ENTRY_BYTES + 4].copy_from_slice(&x.to_le_bytes());
    processor.write(block, &frame_in(block))?;
    processor.write(block + FRAME_BYTES as u64, &argument)?;
    match processor.enter(thread, convention, entry, block) {
        Ok(crossing) => Ok((block, crossing)),
        Err(fault) => {
            processor.release(block);
            Err(fault)
        }
    }
}

/// The second half, when the code has returned: the stub changed the
/// status in its frame and nothing else, and the result is in its place.
fn left(processor: &mut Processor, block: u64) -> i32 {
    let mut after = [0; FRAME_BYTES];
    let mut bytes = [0; 4];
    processor.read(block, &mut after).unwrap();
    processor.read(block + 128, &mut bytes).unwrap();
    processor.release(block);
    let mut frame = frame_in(block);
    frame[64..68].copy_from_slice(&STATUS_RETURNED.to_le_bytes());
    assert_eq!(after, frame);
    i32::from_le_bytes(bytes)
}

/// A whole crossing of a function that does not call back.
fn crossed(
    processor: &mut Processor,
    machine: &str,
    thread: u64,
    convention: BridgeConvention,
    name: &str,
    x: i32,
) -> Result<i32, ForeignFault> {
    let (block, crossing) = entered(processor, machine, thread, convention, name, x)?;
    assert_eq!(crossing, Crossing::Returned, "{machine} {name}");
    Ok(left(processor, block))
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// What the code that waits at the entry of a callback brought: its frame
/// names the callback `bridge` and is as a wrapper of the image makes it,
/// and its arena has one `int`, which is returned.
fn asked(processor: &mut Processor, frame_at: u64, bridge: u64) -> i32 {
    let mut frame = [0; FRAME_BYTES];
    processor.read(frame_at, &mut frame).unwrap();
    let half = |at: usize| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
    let words = |bytes: &[u8], places: [usize; 4]| places.map(|at| word(bytes, at));
    assert_eq!(frame_at % 16, 0);
    assert_eq!((half(0), half(4)), (FRAME_REVISION, 0));
    assert_eq!((half(64), half(68)), (STATUS_ENTERED, 0));
    // The callback, the sizes of the arena and of the result, and no
    // transition, lease or generation yet.
    assert_eq!(words(&frame, [8, 24, 40, 48]), [bridge, 40, 4, 0]);
    assert_eq!((word(&frame, 56), word(&frame, 72)), (0, 0));
    let mut arena = [0; 40];
    processor.read(word(&frame, 16), &mut arena).unwrap();
    assert_eq!(words(&arena, [0, 8, 16, 24]), [1, 4, 4, 40]);
    i32::from_le_bytes(arena[32..36].try_into().unwrap())
}

/// Give the code that waits with the frame at `frame_at` what the function
/// it called returned, as the engine does.
fn answered(processor: &mut Processor, frame_at: u64, result: i32) {
    let mut frame = [0; FRAME_BYTES];
    processor.read(frame_at, &mut frame).unwrap();
    let returned = STATUS_RETURNED.to_le_bytes();
    let written = processor
        .write(word(&frame, 32), &result.to_le_bytes())
        .and_then(|()| processor.write(frame_at + 64, &returned));
    assert_eq!(written, Ok(()));
}

#[test]
fn foreign_code_calls_portable_code_back() {
    for (machine, isa, _) in MACHINES {
        for x in [5_i32, 0, -7] {
            // apply(x) is one more than what the module's `twice` makes of x.
            let (outcome, record) = ran(
                machine,
                isa,
                "call_apply",
                u128::from(x as u32),
                Limits::default(),
            )
            .unwrap();
            assert_eq!(
                outcome.exit,
                Exit::Return(vec![Value::Int(u128::from((2 * x + 1) as u32))]),
                "{machine} {x}"
            );
            assert_eq!((record.crossings(), record.held()), (1, 0));
            assert_eq!(record.reasons(), [""; 0]);
        }
    }
}

#[test]
fn portable_and_foreign_code_call_each_other_by_turns() {
    // down(n) in the image is one more than the module's step(n), which is
    // the image's down(n - 1): n calls of foreign code, one inside another
    // on one stack, and one more that returns at once.
    let deepest = MAX_NESTED as u128 - 1;
    for (machine, isa, _) in MACHINES {
        for n in [0, 1, 3, deepest] {
            let (outcome, record) = ran(machine, isa, "call_down", n, Limits::default()).unwrap();
            let returned = Exit::Return(vec![Value::Int(n)]);
            assert_eq!(outcome.exit, returned, "{machine} {n}");
            assert_eq!((record.crossings(), record.held()), (n as u64 + 1, 0));
            assert_eq!(record.reasons(), [""; 0]);
        }
        // One call deeper than a thread goes ends the program at that limit.
        let (outcome, _) = ran(machine, isa, "call_down", deepest + 1, Limits::default()).unwrap();
        assert_eq!(outcome.exit, Exit::Resource("crossings"), "{machine}");
    }
}

#[test]
fn what_is_no_callback_of_the_module_ends_the_program() {
    for (machine, isa, _) in MACHINES {
        // Code whose bridge says that it does not call back; a frame that
        // names another callback than the one whose entry the code is at;
        // an arena whose argument is not declared as the callback's is.
        for function in ["call_quiet", "call_other", "call_crooked"] {
            let (outcome, record) = ran(machine, isa, function, 5, Limits::default()).unwrap();
            assert_eq!(
                trapped(&outcome.exit),
                "foreign_callback",
                "{machine} {function}"
            );
            // The code got to the entry and no further: it did not return.
            assert_eq!((record.crossings(), record.held()), (0, 0));
        }
    }
}

#[test]
fn code_waits_at_the_entry_of_a_callback_and_goes_on_from_there() {
    const TWICE: u64 = 100;
    const STEP: u64 = 101;
    for (machine, isa, convention) in MACHINES {
        let mut processor = processor(machine, isa, Limits::default());
        let record = processor.record();
        let (identity, functions) = described(machine);
        let mut entry = |name: &str| {
            let (offset, size) = functions[name];
            processor.intercept(&identity, offset, size).unwrap()
        };
        let (twice, step) = (entry("callback_twice"), entry("callback_step"));
        assert_ne!(twice, step);
        // An entry is code of the image: not data, not the file's header,
        // and not of an image the processor has not.
        let (offset, size) = functions["callback_twice"];
        assert_eq!(processor.intercept(&[0; 32], offset, size), None);
        assert_eq!(processor.intercept(&identity, 0, 16), None);

        // apply(5): the code stops at the entry of `twice` with a frame of
        // its own making on its stack, which has 5 in its arena.
        let (block, crossing) =
            entered(&mut processor, machine, 1, convention, "bridge_apply", 5).unwrap();
        let Crossing::Called { entry, frame } = crossing else {
            panic!("{machine}: the code calls back")
        };
        assert_eq!(entry, twice, "{machine}");
        let stacks = 0x6000_0000_0000..0x7000_0000_0000;
        assert!(stacks.contains(&frame), "{frame:#x}");
        assert_eq!(asked(&mut processor, frame, TWICE), 5);
        // Gone on with what the function returned, it returns one more.
        answered(&mut processor, frame, 10);
        assert_eq!(processor.resume(1), Ok(Crossing::Returned), "{machine}");
        assert_eq!(left(&mut processor, block), 11);
        // Nothing waits now.
        assert_eq!(processor.resume(1), Err(ForeignFault));
        assert_eq!(processor.resume(7), Err(ForeignFault));

        // down(2): foreign and portable code by turns, as the engine would
        // run them. Each call of `down` inside another is lower on the same
        // stack, and what waits last goes on first.
        let down = "bridge_down";
        let (outer, crossing) = entered(&mut processor, machine, 1, convention, down, 2).unwrap();
        let Crossing::Called { entry, frame } = crossing else {
            panic!("{machine}: down(2) calls back")
        };
        let first = frame;
        assert_eq!((entry, asked(&mut processor, first, STEP)), (step, 2));
        let (middle, crossing) = entered(&mut processor, machine, 1, convention, down, 1).unwrap();
        let Crossing::Called { entry, frame } = crossing else {
            panic!("{machine}: down(1) calls back")
        };
        let second = frame;
        assert_eq!((entry, asked(&mut processor, second, STEP)), (step, 1));
        assert!(second < first, "{second:#x} is below {first:#x}");
        // Another thread's code runs meanwhile, on its own stack.
        assert_eq!(
            crossed(&mut processor, machine, 2, convention, "bridge_scale", 5),
            Ok(16)
        );
        let (inner, crossing) = entered(&mut processor, machine, 1, convention, down, 0).unwrap();
        assert_eq!(crossing, Crossing::Returned, "{machine}: down(0) returns");
        assert_eq!(left(&mut processor, inner), 0);
        // step(1) was down(0); down(1) goes on and returns 1.
        answered(&mut processor, second, 0);
        assert_eq!(processor.resume(1), Ok(Crossing::Returned), "{machine}");
        assert_eq!(left(&mut processor, middle), 1);
        answered(&mut processor, first, 1);
        assert_eq!(processor.resume(1), Ok(Crossing::Returned), "{machine}");
        assert_eq!(left(&mut processor, outer), 2);
        // Nothing went wrong but the two that had nothing to go on with.
        assert_eq!(record.reasons().len(), 2, "{machine}");

        // Code that is gone on with though its frame does not say that the
        // function returned: the wrapper finds that out and does not go on.
        let (block, crossing) =
            entered(&mut processor, machine, 1, convention, "bridge_apply", 5).unwrap();
        assert!(matches!(crossing, Crossing::Called { .. }));
        assert_eq!(processor.resume(1), Err(ForeignFault), "{machine}");
        processor.release(block);
        // The thread has nothing that waits after that, and runs again.
        assert_eq!(processor.resume(1), Err(ForeignFault));
        assert_eq!(
            crossed(&mut processor, machine, 1, convention, "bridge_scale", 5),
            Ok(16)
        );
        assert_eq!(record.held(), 0);
    }
}

#[test]
fn every_thread_has_a_stack_and_runs_out_of_its_own_alone() {
    for (machine, isa, convention) in MACHINES {
        let limits = Limits {
            stack: 64 << 10,
            ..Limits::default()
        };
        let mut processor = processor(machine, isa, limits);
        let record = processor.record();
        let name = "bridge_deep";
        let mut deep = |thread, n| crossed(&mut processor, machine, thread, convention, name, n);
        // A function that goes a hundred levels down, on two threads.
        assert_eq!(deep(1, 100), Ok(5050), "{machine}");
        assert_eq!(deep(2, 100), Ok(5050), "{machine}");
        // A thousand levels are more than 64 KiB: the code writes below its
        // stack, where nothing is, and does not come back.
        assert_eq!(deep(1, 1000), Err(ForeignFault), "{machine}");
        let reasons = record.reasons();
        let [why] = &reasons[..] else {
            panic!("{machine}: one reason, not {reasons:?}")
        };
        assert!(
            why.starts_with("thread 1: a write at 0x6000") && why.ends_with("nothing is there"),
            "{machine}: {why}"
        );
        // The other thread's stack is as it was, and the thread that ran out
        // has its own again for its next call.
        assert_eq!(deep(2, 100), Ok(5050), "{machine}");
        assert_eq!(deep(1, 100), Ok(5050), "{machine}");
        assert_eq!((record.crossings(), record.held()), (4, 0), "{machine}");
    }
}

#[test]
fn code_is_entered_as_its_convention_has_it() {
    // Code for Windows takes the frame in RCX and has 32 bytes above its
    // return address to write, which this stub does; it also saves vector
    // registers with instructions that fault on a stack that is not aligned.
    let mut intel = processor("x86_64", ForeignIsa::X86_64, Limits::default());
    let record = intel.record();
    let windows = BridgeConvention::Win64;
    for x in [5, -7] {
        assert_eq!(
            crossed(&mut intel, "x86_64", 1, windows, "bridge_scale_ms", x),
            Ok(3 * x + 1)
        );
    }
    // A convention of another processor is none of this one's.
    let other = BridgeConvention::Aapcs64;
    assert_eq!(
        crossed(&mut intel, "x86_64", 1, other, "bridge_scale", 5),
        Err(ForeignFault)
    );
    assert_eq!(
        record.reasons(),
        ["Aapcs64 is no convention of x86_64 code"]
    );
    let mut arm = processor("aarch64", ForeignIsa::Aarch64, Limits::default());
    assert_eq!(
        crossed(&mut arm, "aarch64", 1, windows, "bridge_scale", 5),
        Err(ForeignFault)
    );
}

#[test]
fn the_engine_reads_and_writes_what_foreign_code_may() {
    for (machine, isa, _) in MACHINES {
        let mut processor = processor(machine, isa, Limits::default());
        let record = processor.record();
        let (identity, functions) = described(machine);
        let (offset, size) = functions["bridge_scale"];
        let code = processor.code(&identity, offset, size).unwrap();
        let block = processor.allocate(100).unwrap();
        assert_eq!(block % 16, 0);
        let mut found = [1; 112];
        assert_eq!(processor.read(block, &mut found), Ok(()));
        assert_eq!(found, [0; 112], "a block is zero and a multiple of 16 long");
        assert_eq!(processor.write(block + 96, &[7; 16]), Ok(()));
        // Code is read and not written, and where nothing is, nothing is
        // read or written.
        assert_eq!(processor.read(code, &mut found[..4]), Ok(()));
        assert_eq!(processor.write(code, &[0; 4]), Err(ForeignFault));
        assert_eq!(processor.read(16, &mut found[..4]), Err(ForeignFault));
        assert_eq!(processor.write(16, &[0; 4]), Err(ForeignFault));
        assert_eq!(
            record.reasons(),
            [
                format!("{code:#x} is no memory to write"),
                "0x10 is no memory to read".to_owned(),
                "0x10 is no memory to write".to_owned(),
            ]
        );
        // What a call left in its block, the next call does not find.
        processor.release(block);
        assert_eq!(processor.allocate(100), Ok(block));
        assert_eq!(processor.read(block + 96, &mut found[..16]), Ok(()));
        assert_eq!(found[..16], [0; 16]);
    }
}

#[test]
fn a_processor_has_no_more_memory_than_its_limits_allow() {
    let (machine, isa, convention) = MACHINES[1];
    let tight = Limits {
        memory: 1 << 20,
        stack: 64 << 10,
        time: None,
    };
    let mut small = processor(machine, isa, tight);
    let record = small.record();
    assert_eq!(small.allocate(2 << 20), Err(ForeignFault));
    assert_eq!(
        record.reasons(),
        ["no memory for a call that needs 2097152 bytes"]
    );
    // Within them it works as any other.
    assert_eq!(
        crossed(&mut small, machine, 1, convention, "bridge_scale", 5),
        Ok(16)
    );
    // Limits that leave no room for a stack, or for the image, are refused
    // before anything runs.
    let none = Limits {
        memory: 4096,
        stack: 8192,
        time: None,
    };
    assert_eq!(Processor::new(isa, none).err(), Some(Refusal::Memory));
    let page = Limits {
        memory: 4096,
        stack: 4096,
        time: None,
    };
    let mut cramped = Processor::new(isa, page).unwrap();
    assert_eq!(cramped.load(&image(machine)), Err(Refusal::Memory));
}
