//! Functions a program imports from its host: `programs/hosts.smo` under
//! hosts that have them, and under hosts that do not.
//!
//! The module imports `app:add`, `app:tick` and `app.math:scale`, each
//! with the identity of the descriptor `programs/hosts.descriptors.json`
//! has for it. A host that registers those descriptors has the functions;
//! both engines must call it alike.

use super::{checked, crate_dir, python};
use rax_smir_portable::interp::{Clock, Code, Engine, Errno, Exit, Host, Outcome, Policy, run_on};
use rax_smir_portable::ir::{HostDescriptor, HostImport, Module, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::Value as Json;
use std::collections::BTreeMap;

fn load(name: &str) -> Module {
    let path = crate_dir().join(format!("tests/interp/programs/{name}.smo"));
    Module::load(
        &std::fs::read(path).expect("the object is there"),
        Limits::default(),
    )
    .expect("the object verifies and lowers")
}

/// The descriptors the builder wrote, by the function's name.
fn descriptors() -> BTreeMap<String, Vec<u8>> {
    let path = crate_dir().join("tests/interp/programs/hosts.descriptors.json");
    let document: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let hex = |text: &str| -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    };
    document
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, bytes)| (name.clone(), hex(bytes.as_str().unwrap())))
        .collect()
}

/// How the application's `add` answers.
#[derive(Clone, Copy, PartialEq)]
enum Add {
    Sum,
    Fails,
    TwoResults,
    TooWide,
}

/// An application: it has the functions it registered descriptors for, and
/// keeps what it was called with.
struct App {
    /// The functions it has, by the identity of each one's descriptor.
    registered: BTreeMap<[u8; 32], String>,
    grants: bool,
    add: Add,
    ticks: u128,
    calls: Vec<(String, Vec<u128>)>,
}

impl App {
    /// An application with the functions named, for `module`: each must be
    /// described by its descriptor as the module imports it.
    fn with(module: &Module, names: &[&str]) -> Self {
        let all = descriptors();
        let registered = names
            .iter()
            .map(|name| {
                let descriptor = HostDescriptor::decode(&all[*name]).expect("a descriptor");
                assert!(
                    module
                        .host_imports()
                        .iter()
                        .any(|import| descriptor.describes(module, import)),
                    "{name} is imported as described"
                );
                (descriptor.identity, (*name).to_owned())
            })
            .collect();
        Self {
            registered,
            grants: true,
            add: Add::Sum,
            ticks: 0,
            calls: Vec::new(),
        }
    }
}

impl Host for App {
    fn grants(&self, capability: &str) -> bool {
        self.grants && capability == "host_value"
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
    fn provides(&self, import: &HostImport) -> bool {
        self.registered.contains_key(&import.descriptor)
    }
    fn call(&mut self, import: &HostImport, arguments: &[u128]) -> Result<Vec<u128>, Errno> {
        let name = self.registered[&import.descriptor].clone();
        self.calls.push((name.clone(), arguments.to_vec()));
        match (name.as_str(), self.add) {
            ("add", Add::Sum) => Ok(vec![(arguments[0] + arguments[1]) & 0xffff_ffff]),
            ("add", Add::Fails) => Err(Errno::EIO),
            ("add", Add::TwoResults) => Ok(vec![1, 2]),
            ("add", Add::TooWide) => Ok(vec![1 << 40]),
            ("tick", _) => {
                self.ticks += 1;
                Ok(vec![self.ticks])
            }
            ("scale", _) => {
                let scaled = f64::from_bits(arguments[0] as u64) * arguments[1] as f64;
                Ok(vec![u128::from(scaled.to_bits())])
            }
            _ => Err(Errno::EIO),
        }
    }
}

/// Run an exported function on both engines, each with a host of its own
/// that `prepare` has set up, and return how the run ended and what the
/// host was called with; the two engines must agree on both.
fn ran(
    module: &Module,
    names: &[&str],
    prepare: impl Fn(&mut App),
    function: &str,
    arguments: &[u128],
) -> Result<(Outcome, Vec<(String, Vec<u128>)>), Error> {
    let code = Code::compile(module).expect("the module compiles for this host");
    let values: Vec<Value> = arguments.iter().map(|bits| Value::Int(*bits)).collect();
    let entry = module.export(function).expect("the function is exported");
    let on = |engine| {
        let mut app = App::with(module, names);
        prepare(&mut app);
        run_on(engine, module, entry, &values, Policy::default(), &mut app)
            .map(|outcome| (outcome, app.calls))
    };
    let (interpreted, compiled) = (on(Engine::Interpreter), on(Engine::Native(&code)));
    match (&interpreted, &compiled) {
        (Ok(one), Ok(other)) => assert_eq!(one, other, "{function}"),
        (Err(one), Err(other)) => assert_eq!(one.code(), other.code(), "{function}"),
        _ => panic!("{function}: the engines differ"),
    }
    interpreted
}

const ALL: [&str; 3] = ["add", "tick", "scale"];

fn returned(values: &[u128]) -> Exit {
    Exit::Return(values.iter().map(|bits| Value::Int(*bits)).collect())
}

fn called(name: &str, arguments: &[u128]) -> (String, Vec<u128>) {
    (name.to_owned(), arguments.to_vec())
}

#[test]
fn the_committed_objects_are_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    let mut build = python();
    build.arg(directory.join("build_hosts.py")).arg("--check");
    checked(build, None, "programs/build_hosts.py --check");
    for name in ["hosts", "hosts-user"] {
        let mut assemble = python();
        assemble
            .arg(crate_dir().join("tests/interp/oracle.py"))
            .arg("assemble")
            .arg(directory.join(format!("{name}.json")))
            .arg(directory.join(format!("{name}.smo")));
        checked(assemble, None, "oracle.py assemble");
    }
}

#[test]
fn a_program_calls_the_functions_its_host_has() {
    let module = load("hosts");
    assert_eq!(
        module
            .host_imports()
            .iter()
            .map(|import| (
                import.namespace.as_str(),
                import.name.as_str(),
                import.version
            ))
            .collect::<Vec<_>>(),
        [
            ("app", "add", 1),
            ("app", "tick", 1),
            ("app.math", "scale", 3)
        ]
    );
    // sum3(1, 2, 3) is add(add(1, 2), 3): two calls, in that order.
    let (outcome, calls) = ran(&module, &ALL, |_| {}, "sum3", &[1, 2, 3]).unwrap();
    assert_eq!(outcome.exit, returned(&[6]));
    assert_eq!(calls, [called("add", &[1, 2]), called("add", &[3, 3])]);
    // What the host keeps between calls, it keeps: its count goes on.
    let (outcome, calls) = ran(&module, &ALL, |_| {}, "ticks", &[]).unwrap();
    assert_eq!(outcome.exit, returned(&[3]));
    assert_eq!(calls, [called("tick", &[]), called("tick", &[])]);
    // A float goes to the host and comes back as its bits.
    let bits = |number: f64| u128::from(number.to_bits());
    let (outcome, calls) = ran(&module, &ALL, |_| {}, "scaled", &[bits(1.5), 4]).unwrap();
    assert_eq!(outcome.exit, returned(&[bits(6.0)]));
    assert_eq!(calls, [called("scale", &[bits(1.5), 4])]);
    // Of an unspecified value the host gets zero, and of poison nothing:
    // that is the program's fault, before the host is asked.
    let (outcome, calls) = ran(&module, &ALL, |_| {}, "unspecified", &[]).unwrap();
    assert_eq!(outcome.exit, returned(&[5]));
    assert_eq!(calls, [called("add", &[0, 5])]);
    let (outcome, calls) = ran(&module, &ALL, |_| {}, "poisoned", &[]).unwrap();
    assert!(
        matches!(&outcome.exit, Exit::LanguageUb(fault) if fault.code == "ub_host_argument"),
        "{:?}",
        outcome.exit
    );
    assert_eq!(calls, []);
}

#[test]
fn a_program_runs_only_under_a_host_that_has_what_it_imports() {
    let module = load("hosts");
    // Without one of the functions, and without the capability.
    let refused = ran(&module, &["add", "scale"], |_| {}, "sum3", &[1, 2, 3]).unwrap_err();
    assert_eq!(
        (refused.code(), refused.context()),
        ("EXEC_IMPORT", "app:tick version 1")
    );
    let refused = ran(&module, &ALL, |app| app.grants = false, "sum3", &[1, 2, 3]).unwrap_err();
    assert_eq!(refused.code(), "EXEC_CAPABILITY");
}

#[test]
fn a_host_that_fails_or_answers_amiss_ends_the_program() {
    let module = load("hosts");
    // The function's results have no room for a failure, nor for another
    // number of values, nor for bits beyond their width.
    for answer in [Add::Fails, Add::TwoResults, Add::TooWide] {
        let (outcome, calls) =
            ran(&module, &ALL, |app| app.add = answer, "sum3", &[1, 2, 3]).unwrap();
        assert!(
            matches!(&outcome.exit, Exit::Trap(fault) if fault.code == "host_call"),
            "{:?}",
            outcome.exit
        );
        assert_eq!(calls, [called("add", &[1, 2])]);
    }
}

#[test]
fn a_descriptor_describes_one_function_as_one_module_imports_it() {
    let module = load("hosts");
    let all = descriptors();
    let add = HostDescriptor::decode(&all["add"]).unwrap();
    assert_eq!(
        (add.namespace.as_str(), add.name.as_str(), add.version),
        ("app", "add", 1)
    );
    assert_eq!(add.widths(), (vec![32, 32], vec![32]));
    assert_eq!(
        HostDescriptor::decode(&all["scale"]).unwrap().widths(),
        (vec![64, 64], vec![64])
    );
    let imports = module.host_imports();
    assert_eq!(
        imports
            .iter()
            .map(|import| add.describes(&module, import))
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    assert_eq!(add.identity, imports[0].descriptor);
    // Bytes that are no descriptor, or not the one way to write one.
    let record = &all["add"];
    for wrong in [
        &record[..record.len() - 1],
        &[record.as_slice(), &[0]].concat()[..],
        &[][..],
    ] {
        assert!(HostDescriptor::decode(wrong).is_err());
    }
    // A descriptor with another name is another function: the module that
    // imports `add` does not import it.
    let mut renamed = record.clone();
    let at = renamed
        .windows(3)
        .position(|bytes| bytes == b"add")
        .unwrap();
    renamed[at..at + 3].copy_from_slice(b"sub");
    let sub = HostDescriptor::decode(&renamed).unwrap();
    assert_eq!(sub.name, "sub");
    assert_ne!(sub.identity, add.identity);
    assert!(!imports.iter().any(|import| sub.describes(&module, import)));
    // Nor is a function in the runtime's own namespace a host's to have.
    let mut reserved = record.clone();
    let at = reserved
        .windows(3)
        .position(|bytes| bytes == b"app")
        .unwrap();
    reserved.splice(at - 4..at + 3, [5, 0, 0, 0].into_iter().chain(*b"smir."));
    assert_eq!(
        HostDescriptor::decode(&reserved).unwrap_err().code(),
        "HOST_DESCRIPTOR"
    );
}

#[test]
fn linked_modules_keep_their_host_functions() {
    // `hosts-user` imports `add` itself and calls `sum3` of `hosts`, which
    // imports it too: linked, each module's calls go to the host by that
    // module's import.
    let program = Module::link(vec![load("hosts-user"), load("hosts")]).unwrap();
    assert_eq!(program.host_imports().len(), 6);
    let (outcome, calls) = ran(&program, &ALL, |_| {}, "both", &[2, 3]).unwrap();
    // add(2, 3) + sum3(2, 3, 0).
    assert_eq!(outcome.exit, returned(&[10]));
    assert_eq!(
        calls,
        [
            called("add", &[2, 3]),
            called("add", &[2, 3]),
            called("add", &[5, 0])
        ]
    );
}
