//! Modules linked into one program: `Module::link`, on
//! `programs/linked-*.smo`.
//!
//! `main` calls functions of `shapes` and of `base`, and `shapes` calls
//! functions of `base`. Each is an object of its own, verified by itself;
//! linked, they are one program that both engines run alike.

use super::{checked, crate_dir, python};
use rax_smir_portable::interp::{Called, Code, Exit, Instance, NoHost, Policy, run};
use rax_smir_portable::ir::{Module, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::Value as Json;
use std::process::Command;
use std::sync::Arc;

const NAMES: [&str; 10] = [
    "base", "shapes", "main", "absent", "mistyped", "prying", "newer", "left", "right", "abroad",
];

/// Functions of `linked-main`.
const ENTRY: u32 = 300;
const COUNTS: u32 = 301;
const ORDER: u32 = 302;

fn load(name: &str) -> Module {
    let path = crate_dir().join(format!("tests/interp/programs/linked-{name}.smo"));
    Module::load(
        &std::fs::read(path).expect("the object is there"),
        Limits::default(),
    )
    .expect("the object verifies and lowers")
}

fn link(names: &[&str]) -> Result<Module, Error> {
    Module::link(names.iter().map(|name| load(name)).collect())
}

fn refusal(names: &[&str]) -> String {
    link(names)
        .err()
        .map(|error| error.code().to_owned())
        .unwrap_or_else(|| panic!("{names:?} link"))
}

fn returned(values: &[u128]) -> Exit {
    Exit::Return(values.iter().map(|bits| Value::Int(*bits)).collect())
}

/// Run a function of a program on both engines, which must do the same.
fn call(program: &Module, function: u32, arguments: &[u128]) -> Exit {
    super::native::on_both(program, function, arguments, b"", Policy::default(), true)
        .outcome
        .exit
}

#[test]
fn the_committed_objects_are_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    let mut build = python();
    build.arg(directory.join("build_linked.py")).arg("--check");
    checked(build, None, "programs/build_linked.py --check");
    for name in NAMES {
        let mut assemble = python();
        assemble
            .arg(crate_dir().join("tests/interp/oracle.py"))
            .arg("assemble")
            .arg(directory.join(format!("linked-{name}.json")))
            .arg(directory.join(format!("linked-{name}.smo")));
        checked(assemble, None, "oracle.py assemble");
    }
}

#[test]
fn a_module_that_needs_another_runs_only_once_linked() {
    let main = load("main");
    assert!(main.needs_linking());
    assert_eq!((main.key().name.as_str(), main.key().major), ("main", 1));
    let entry = main.function(ENTRY).unwrap();
    let refused = run(&main, entry, &[Value::Int(5)], Policy::default()).unwrap_err();
    assert_eq!(refused.code(), "EXEC_UNLINKED");
    assert_eq!(
        Code::compile(&main)
            .err()
            .map(|error| error.code().to_owned()),
        Some("EXEC_UNLINKED".into())
    );
    assert_eq!(
        Instance::start(Arc::new(main), None, Policy::default(), Box::new(NoHost))
            .err()
            .map(|error| error.code().to_owned()),
        Some("EXEC_UNLINKED".into())
    );
    // A module that needs none is a program by itself: scale(5).
    let base = load("base");
    assert!(!base.needs_linking());
    assert_eq!((base.key().name.as_str(), base.key().minor), ("base", 2));
    assert_eq!(call(&base, 300, &[5]), returned(&[15]));
}

#[test]
fn a_call_of_a_dependency_reaches_its_function() {
    // The order the other modules are given in does not matter.
    for names in [["main", "shapes", "base"], ["main", "base", "shapes"]] {
        let program = link(&names).unwrap();
        assert!(!program.needs_linking());
        // area(x, 2) + scale(x): through `shapes` to `base`, and straight
        // to `base`, whose `scale` it is and not the one `shapes` has.
        for x in [0_u128, 5, 1000] {
            assert_eq!(call(&program, ENTRY, &[x]), returned(&[9 * x]), "{names:?}");
        }
    }
}

#[test]
fn two_modules_that_need_a_third_have_the_one() {
    let program = link(&["main", "shapes", "base"]).unwrap();
    // `main` counts once in `base`, then `shapes` twice: one counter.
    assert_eq!(call(&program, COUNTS, &[]), returned(&[1, 3]));
    // And the counter lasts as long as the process does.
    for code in [None, Some(Arc::new(Code::compile(&program).unwrap()))] {
        let counts = program.function(COUNTS).unwrap();
        let instance = Instance::start(
            Arc::new(program.clone()),
            code,
            Policy::default(),
            Box::new(NoHost),
        )
        .unwrap();
        for round in 0..3_u128 {
            assert_eq!(
                instance.call(counts, &[]).unwrap(),
                Called::Returned(vec![Value::Int(3 * round + 1), Value::Int(3 * round + 3)])
            );
        }
    }
}

#[test]
fn a_module_is_initialized_after_what_it_needs() {
    // The initializer of `shapes` stores one more than what the
    // initializer of `base` stored, which is 7; before that ran it is 0.
    for names in [["main", "shapes", "base"], ["main", "base", "shapes"]] {
        assert_eq!(call(&link(&names).unwrap(), ORDER, &[]), returned(&[8]));
    }
}

#[test]
fn a_linked_program_is_known_by_its_modules() {
    let one = link(&["main", "shapes", "base"]).unwrap();
    assert_eq!(
        one.identity(),
        link(&["main", "shapes", "base"]).unwrap().identity()
    );
    assert_ne!(one.identity(), load("main").identity());
    assert_eq!(one.key(), load("main").key());
    // Its functions are the first module's, by their identifiers and names.
    assert_eq!(one.export("entry"), one.function(ENTRY));
    assert!(one.export("scale").is_none());
    // Code compiled for it is code for it alone.
    let code = Code::compile(&one).unwrap();
    let base = load("base");
    let refused = rax_smir_portable::interp::run_on(
        rax_smir_portable::interp::Engine::Native(&code),
        &base,
        base.function(300).unwrap(),
        &[Value::Int(1)],
        Policy::default(),
        &mut NoHost,
    );
    assert_eq!(refused.unwrap_err().code(), "EXEC_ENGINE");
}

/// `smir-run` on `linked-main` with these libraries: its exit status and
/// its one line of JSON.
fn runner(libraries: &[&str], more: &[&str]) -> (Option<i32>, Json) {
    let file = |name: &str| {
        let path = crate_dir().join(format!("tests/interp/programs/linked-{name}.smo"));
        path.to_str().expect("a path").to_owned()
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_smir-run"));
    command.arg(file("main"));
    for library in libraries {
        // A name with a separator is a file of its own.
        let library = if library.contains('/') {
            (*library).to_owned()
        } else {
            file(library)
        };
        command.arg("--library").arg(library);
    }
    command.args(["--entry-function", "300", "--argument-bits", "05000000"]);
    let output = command.args(more).output().expect("start smir-run");
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).expect("one line of JSON"),
    )
}

#[test]
fn the_command_line_runner_links_the_libraries_it_is_given() {
    let (status, alone) = runner(&[], &[]);
    assert_eq!(
        (status, alone["code"].as_str()),
        (Some(1), Some("EXEC_UNLINKED"))
    );
    let program = link(&["main", "shapes", "base"]).unwrap();
    for engine in [&[][..], &["--native"][..]] {
        let (status, report) = runner(&["shapes", "base"], engine);
        assert_eq!(status, Some(0), "{report}");
        assert_eq!(report["status"], "return");
        assert_eq!(report["values"][0]["bits_le"], "2d000000");
        // The program that ran is the linked one, not its first module.
        let identity: String = program
            .identity()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(report["content_digest"], identity.as_str());
    }
    // A library may be what a native file carries.
    let carried = std::env::temp_dir().join(format!("smir-linking-{}", std::process::id()));
    let base = crate_dir().join("tests/interp/programs/linked-base.smo");
    let packed = Command::new(env!("CARGO_BIN_EXE_smir-pack"))
        .arg(&base)
        .args(["--carrier", "elf", "--machine", "aarch64", "-o"])
        .arg(&carried)
        .output()
        .expect("start smir-pack");
    assert!(packed.status.success());
    let (status, report) = runner(&["shapes", carried.to_str().expect("a path")], &[]);
    let _ = std::fs::remove_file(&carried);
    assert_eq!(
        (status, report["values"][0]["bits_le"].as_str()),
        (Some(0), Some("2d000000"))
    );
    // The process is of the personality that was asked for, which must be
    // the program's.
    let (status, report) = runner(&["shapes", "base"], &["--personality", "linux"]);
    assert_eq!(
        (status, report["values"][0]["bits_le"].as_str()),
        (Some(0), Some("2d000000"))
    );
    let (status, report) = runner(&["shapes", "base"], &["--personality", "windows"]);
    assert_eq!(
        (status, report["code"].as_str()),
        (Some(1), Some("EXEC_PERSONALITY"))
    );
    let unknown = Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .args(["x.smo", "--entry-function", "0", "--personality", "plan9"])
        .output()
        .expect("start smir-run");
    assert_eq!(unknown.status.code(), Some(2));
    // What does not link is reported as an object that does not verify is.
    let (status, report) = runner(&["shapes"], &[]);
    assert_eq!(
        (status, report["status"].as_str(), report["code"].as_str()),
        (Some(1), Some("rejected"), Some("LINK_DEPENDENCY"))
    );
    let (status, report) = runner(&["shapes", "/nowhere/base.smo"], &[]);
    assert_eq!(
        (status, report["code"].as_str()),
        (Some(1), Some("OBJECT_READ"))
    );
}

#[test]
fn modules_that_do_not_fit_are_not_linked() {
    // A dependency nothing answers, and one two modules answer.
    assert_eq!(refusal(&["main", "shapes"]), "LINK_DEPENDENCY");
    assert_eq!(
        refusal(&["main", "shapes", "base", "base"]),
        "LINK_DEPENDENCY"
    );
    // A later version of a module than there is.
    assert_eq!(refusal(&["newer", "base"]), "LINK_DEPENDENCY");
    // A function the module that answers has not, or has with another type.
    assert_eq!(refusal(&["absent", "base"]), "LINK_UNDEFINED");
    assert_eq!(refusal(&["mistyped", "base"]), "LINK_TYPE");
    // A function the module that answers has and keeps to itself: the host
    // may call it by name, another module may not.
    assert!(load("shapes").export("inner").is_some());
    assert_eq!(refusal(&["prying", "shapes", "base"]), "LINK_UNDEFINED");
    // Modules that need one another in a circle.
    assert_eq!(refusal(&["left", "right"]), "LINK_CYCLE");
    // Modules that are not for one system: a process has one personality,
    // which is its program's and that of everything linked with it.
    assert_eq!(
        (load("abroad").personality(), load("base").personality()),
        ("darwin", "linux")
    );
    assert_eq!(refusal(&["abroad", "base"]), "LINK_PERSONALITY");
    assert_eq!(
        link(&["main", "shapes", "base"]).unwrap().personality(),
        "linux"
    );
    // A module the program does not need.
    assert_eq!(refusal(&["base", "shapes"]), "LINK_UNUSED");
    assert_eq!(refusal(&[]), "LINK_DEPENDENCY");
}
