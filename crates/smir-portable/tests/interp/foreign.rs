//! Calls of foreign code: `programs/foreign-*.smo` under a model of a
//! foreign processor.
//!
//! Each module names the functions of one image of `foreign/` by byte
//! range and has a bridge to each. The engine has no processor for such
//! code; here the embedder's is a model in Rust that does what the image's
//! stubs do (`foreign/guest.c`), reading and writing the frame as they
//! would. What is tested is the engine's side of a crossing, on both
//! engines: the frame and the arena it makes, and what it accepts as a
//! return. No machine code runs here.

use super::{checked, crate_dir, python};
use rax_smir_portable::interp::{
    Called, Clock, Code, ENTRY_BYTES, Engine, Errno, Exit, FRAME_BYTES, FRAME_REVISION, Foreign,
    ForeignFault, Host, Instance, Outcome, Policy, STATUS_ENTERED, STATUS_RETURNED, run_on,
};
use rax_smir_portable::ir::{BridgeConvention, ForeignIsa, Module, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const MACHINES: [(&str, ForeignIsa, BridgeConvention); 2] = [
    ("x86_64", ForeignIsa::X86_64, BridgeConvention::SysV64),
    ("aarch64", ForeignIsa::Aarch64, BridgeConvention::Aapcs64),
];

fn load(machine: &str) -> Arc<Module> {
    let path = crate_dir().join(format!("tests/interp/programs/foreign-{machine}.smo"));
    let bytes = std::fs::read(path).expect("the object is there");
    Arc::new(Module::load(&bytes, Limits::default()).expect("the object verifies and lowers"))
}

/// What `foreign/guest.json` says of the image for a machine: its SHA-256,
/// and each function's byte range by name.
fn image(machine: &str) -> ([u8; 32], BTreeMap<String, (u64, u64)>) {
    let text = std::fs::read(crate_dir().join("tests/interp/foreign/guest.json")).unwrap();
    let all: Json = serde_json::from_slice(&text).unwrap();
    let hex = all[machine]["sha256"].as_str().unwrap();
    let mut identity = [0; 32];
    for (index, byte) in identity.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
    }
    let functions = all[machine]["functions"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, range)| {
            (
                name.clone(),
                (
                    range["offset"].as_u64().unwrap(),
                    range["size"].as_u64().unwrap(),
                ),
            )
        })
        .collect();
    (identity, functions)
}

/// What the model keeps, where the test can see it while a process has the
/// model.
#[derive(Default)]
struct Kept {
    /// The model's memory: what was allocated and not released, by address.
    blocks: BTreeMap<u64, Vec<u8>>,
    allocated: u64,
    /// The image's own data: what `count` has counted.
    counted: i32,
    /// Every entry: the thread, the convention, the stub, and the frame and
    /// the arena as the stub found them.
    entries: Vec<(u64, BridgeConvention, String, Vec<u8>, Vec<u8>)>,
}

/// A model of a foreign processor that has one image.
struct Model {
    isa: ForeignIsa,
    identity: [u8; 32],
    functions: BTreeMap<String, (u64, u64)>,
    kept: Arc<Mutex<Kept>>,
}

/// Where the model has its image, and where its memory for calls begins.
const IMAGE_AT: u64 = 0x0100_0000;
const MEMORY_AT: u64 = 0x7000_0000;

impl Model {
    fn new(machine: &str, isa: ForeignIsa) -> (Self, Arc<Mutex<Kept>>) {
        let (identity, functions) = image(machine);
        let kept = Arc::new(Mutex::new(Kept {
            counted: 100,
            ..Kept::default()
        }));
        let model = Self {
            isa,
            identity,
            functions,
            kept: Arc::clone(&kept),
        };
        (model, kept)
    }
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

impl Foreign for Model {
    fn isa(&self) -> ForeignIsa {
        self.isa
    }

    fn code(&mut self, image: &[u8; 32], offset: u64, size: u64) -> Option<u64> {
        (*image == self.identity
            && self
                .functions
                .values()
                .any(|range| *range == (offset, size)))
        .then_some(IMAGE_AT + offset)
    }

    fn allocate(&mut self, bytes: u64) -> Result<u64, ForeignFault> {
        let mut kept = self.kept.lock().unwrap();
        let address = MEMORY_AT + kept.allocated;
        kept.allocated += bytes.next_multiple_of(16);
        kept.blocks.insert(address, vec![0; bytes as usize]);
        Ok(address)
    }

    fn release(&mut self, address: u64) {
        self.kept.lock().unwrap().blocks.remove(&address);
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ForeignFault> {
        let mut kept = self.kept.lock().unwrap();
        let (base, block) = kept
            .blocks
            .range_mut(..=address)
            .next_back()
            .ok_or(ForeignFault)?;
        let at = (address - base) as usize;
        block
            .get_mut(at..at + bytes.len())
            .ok_or(ForeignFault)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), ForeignFault> {
        let kept = self.kept.lock().unwrap();
        let (base, block) = kept
            .blocks
            .range(..=address)
            .next_back()
            .ok_or(ForeignFault)?;
        let at = (address - base) as usize;
        buffer.copy_from_slice(block.get(at..at + buffer.len()).ok_or(ForeignFault)?);
        Ok(())
    }

    fn enter(
        &mut self,
        thread: u64,
        convention: BridgeConvention,
        entry: u64,
        frame_at: u64,
    ) -> Result<(), ForeignFault> {
        let name = self
            .functions
            .iter()
            .find(|(_, range)| IMAGE_AT + range.0 == entry)
            .map(|(name, _)| name.trim_start_matches("bridge_").to_owned())
            .ok_or(ForeignFault)?;
        let mut frame = [0; FRAME_BYTES];
        self.read(frame_at, &mut frame)?;
        let mut arena = vec![0; word(&frame, 24) as usize];
        self.read(word(&frame, 16), &mut arena)?;
        // The one argument, as the stubs of the image find it: after its
        // header, at the next offset that has its alignment.
        let alignment = word(&arena, 16) as usize;
        let payload = ENTRY_BYTES.next_multiple_of(alignment);
        let x = i32::from_le_bytes(arena[payload..payload + 4].try_into().unwrap());
        let mut kept = self.kept.lock().unwrap();
        kept.entries
            .push((thread, convention, name.clone(), frame.to_vec(), arena));
        let result = match name.as_str() {
            "scale" => 3 * x + 1,
            "count" => {
                kept.counted += x;
                kept.counted
            }
            "silent" | "stale" => 7,
            // A fault, and a stub that never comes back.
            _ => return Err(ForeignFault),
        };
        drop(kept);
        self.write(word(&frame, 32), &result.to_le_bytes())?;
        if name == "stale" {
            let generation = word(&frame, 72) + 1;
            self.write(frame_at + 72, &generation.to_le_bytes())?;
        }
        if name != "silent" {
            self.write(frame_at + 64, &STATUS_RETURNED.to_le_bytes())?;
        }
        Ok(())
    }
}

/// A host that has a processor, or has none, and grants `foreign` or not.
struct Hosting {
    processor: Option<Box<dyn Foreign>>,
    grants: bool,
}

impl Host for Hosting {
    fn grants(&self, capability: &str) -> bool {
        self.grants && capability == "foreign"
    }
    fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    fn write(&mut self, _handle: u64, _bytes: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    fn now(&mut self, _clock: Clock) -> Result<u64, Errno> {
        Err(Errno::EINVAL)
    }
    fn foreign(&mut self) -> Option<Box<dyn Foreign>> {
        self.processor.take()
    }
}

/// Run an exported function on both engines, each under a host with a
/// model of its own, and return how the run ended and what the model kept;
/// the engines must agree on how it ended and on what the model was
/// entered with.
fn ran(
    machine: &str,
    isa: ForeignIsa,
    function: &str,
    argument: u128,
) -> Result<(Outcome, Arc<Mutex<Kept>>), Error> {
    let module = load(machine);
    let code = Code::compile(&module).expect("the module compiles for this host");
    let entry = module.export(function).expect("the function is exported");
    let on = |engine| {
        let (model, kept) = Model::new(machine, isa);
        let mut host = Hosting {
            processor: Some(Box::new(model)),
            grants: true,
        };
        run_on(
            engine,
            &module,
            entry,
            &[Value::Int(argument)],
            Policy::default(),
            &mut host,
        )
        .map(|outcome| (outcome, kept))
    };
    let (interpreted, compiled) = (on(Engine::Interpreter), on(Engine::Native(&code)));
    match (&interpreted, &compiled) {
        (Ok(one), Ok(other)) => {
            assert_eq!(one.0, other.0, "{function}");
            assert_eq!(
                one.1.lock().unwrap().entries,
                other.1.lock().unwrap().entries,
                "{function}"
            );
        }
        (Err(one), Err(other)) => assert_eq!(one.code(), other.code(), "{function}"),
        _ => panic!("{function}: the engines differ"),
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
fn the_committed_objects_are_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    // The description of the images is of the images, and the modules are
    // made of the description.
    for builder in ["foreign/build_guest.py", "programs/build_foreign.py"] {
        let mut build = python();
        build
            .arg(crate_dir().join("tests/interp").join(builder))
            .arg("--check");
        checked(build, None, builder);
    }
    for (machine, _, _) in MACHINES {
        let mut assemble = python();
        assemble
            .arg(crate_dir().join("tests/interp/oracle.py"))
            .arg("assemble")
            .arg(directory.join(format!("foreign-{machine}.json")))
            .arg(directory.join(format!("foreign-{machine}.smo")));
        checked(assemble, None, "oracle.py assemble");
    }
}

#[test]
fn a_module_names_its_foreign_code_by_image_and_byte_range() {
    for (machine, isa, convention) in MACHINES {
        let module = load(machine);
        let (identity, functions) = image(machine);
        let bridges = module.bridges();
        assert_eq!(bridges.len(), 6, "{machine}");
        for (bridge, name) in bridges
            .iter()
            .zip(["scale", "count", "fault", "silent", "stale", "spin"])
        {
            assert_eq!((bridge.isa, bridge.convention), (isa, convention));
            assert_eq!(bridge.image, identity);
            assert_eq!(
                (bridge.offset, bridge.size),
                functions[&format!("bridge_{name}")],
                "{machine} {name}"
            );
            let signature = module.bridge_signature(bridge);
            assert_eq!(
                (signature.params().len(), signature.results().len()),
                (1, 1)
            );
        }
        assert_eq!(module.capabilities().collect::<Vec<_>>(), ["foreign"]);
    }
}

#[test]
fn a_call_crosses_into_foreign_code_with_a_frame_and_comes_back_with_a_result() {
    for (machine, isa, convention) in MACHINES {
        for x in [5_i32, 0, -7] {
            let (outcome, kept) = ran(machine, isa, "call_scale", u128::from(x as u32)).unwrap();
            assert_eq!(
                outcome.exit,
                Exit::Return(vec![Value::Int(u128::from((3 * x + 1) as u32))]),
                "{machine} {x}"
            );
            let kept = kept.lock().unwrap();
            // One crossing, on the program's first thread, with the frame's
            // address passed as the machine's code takes it.
            let [(thread, passed, name, frame, arena)] = &kept.entries[..] else {
                panic!("one entry")
            };
            assert_eq!((*thread, *passed, name.as_str()), (1, convention, "scale"));
            // The frame: this revision, no flags, the bridge, entered, and
            // nothing where nothing is.
            let half = |at: usize| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
            assert_eq!((half(0), half(4)), (FRAME_REVISION, 0));
            assert_eq!(word(frame, 8), 0, "the bridge's identifier");
            assert_eq!(
                (half(64), half(68), word(frame, 56)),
                (STATUS_ENTERED, 0, 0)
            );
            // The arena follows the frame, and the result the arena, at the
            // next multiple of 16.
            let block = word(frame, 16) - FRAME_BYTES as u64;
            assert_eq!((block % 16, word(frame, 24)), (0, 40));
            assert_eq!((word(frame, 32), word(frame, 40)), (block + 128, 4));
            assert_ne!((word(frame, 48), word(frame, 72)), (0, 0));
            // The arena: one argument of four bytes, aligned to four, after
            // a header that says so and that the arena ends 40 bytes on.
            assert_eq!(arena.len(), 40);
            assert_eq!(
                (word(arena, 8), word(arena, 16), word(arena, 24)),
                (4, 4, 40)
            );
            assert_eq!(arena[32..36], x.to_le_bytes());
            assert_eq!(arena[36..], [0; 4]);
            // What the call used of the processor's memory is given back.
            assert!(kept.blocks.is_empty());
        }
    }
}

#[test]
fn every_crossing_is_a_transition_of_its_own() {
    // A process that lasts calls `count` three times: the image's data
    // lasts with it, and no two crossings have one identity or generation.
    for (machine, isa, _) in MACHINES {
        let module = load(machine);
        let count = module.export("call_count").unwrap();
        for code in [None, Some(Arc::new(Code::compile(&module).unwrap()))] {
            let (model, kept) = Model::new(machine, isa);
            let host = Hosting {
                processor: Some(Box::new(model)),
                grants: true,
            };
            let instance =
                Instance::start(Arc::clone(&module), code, Policy::default(), Box::new(host))
                    .unwrap();
            let mut counted = 100_u128;
            for by in [1_u128, 2, 40] {
                counted += by;
                assert_eq!(
                    instance.call(count, &[Value::Int(by)]).unwrap(),
                    Called::Returned(vec![Value::Int(counted)])
                );
            }
            instance.finish().unwrap();
            let kept = kept.lock().unwrap();
            let identities: Vec<(u64, u64)> = kept
                .entries
                .iter()
                .map(|(_, _, _, frame, _)| (word(frame, 48), word(frame, 72)))
                .collect();
            assert_eq!(identities.len(), 3);
            for (position, (transition, generation)) in identities.iter().enumerate() {
                assert!(
                    identities[..position]
                        .iter()
                        .all(|(other, earlier)| other != transition && earlier != generation)
                );
            }
        }
    }
}

#[test]
fn foreign_code_that_does_not_return_as_a_bridge_does_ends_the_program() {
    for (machine, isa, _) in MACHINES {
        for (function, code) in [
            // Code that faults, and code that never comes back.
            ("call_fault", "foreign_fault"),
            ("call_spin", "foreign_fault"),
            // A stub that returns without saying so, and one that returns
            // into another transition than it was entered for.
            ("call_silent", "foreign_return"),
            ("call_stale", "foreign_return"),
        ] {
            let (outcome, kept) = ran(machine, isa, function, 1).unwrap();
            assert_eq!(trapped(&outcome.exit), code, "{machine} {function}");
            // The call's memory is given back all the same.
            assert!(kept.lock().unwrap().blocks.is_empty());
        }
    }
}

#[test]
fn a_program_with_foreign_code_runs_only_where_there_is_a_processor_for_it() {
    let module = load("x86_64");
    let entry = module.export("call_scale").unwrap();
    let refusal = |processor: Option<Box<dyn Foreign>>, grants: bool| {
        let mut host = Hosting { processor, grants };
        let refused = run_on(
            Engine::Interpreter,
            &module,
            entry,
            &[Value::Int(1)],
            Policy::default(),
            &mut host,
        )
        .unwrap_err();
        (refused.code().to_owned(), refused.context().to_owned())
    };
    let model = |machine: &str, isa| -> Option<Box<dyn Foreign>> {
        Some(Box::new(Model::new(machine, isa).0))
    };
    // No processor; one of another kind; one that has not the image.
    assert_eq!(
        refusal(None, true),
        (
            "EXEC_FOREIGN".into(),
            "no processor for foreign code".into()
        )
    );
    assert_eq!(
        refusal(model("aarch64", ForeignIsa::Aarch64), true),
        (
            "EXEC_FOREIGN".into(),
            "the foreign code is for x86_64".into()
        )
    );
    let (code, detail) = refusal(model("aarch64", ForeignIsa::X86_64), true);
    assert_eq!(code, "EXEC_FOREIGN");
    assert!(detail.starts_with("no code at "), "{detail}");
    // And the capability the module declares.
    assert_eq!(
        refusal(model("x86_64", ForeignIsa::X86_64), false).0,
        "EXEC_CAPABILITY"
    );
}
