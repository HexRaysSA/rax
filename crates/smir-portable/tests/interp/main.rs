//! The interpreter against the Python reference machine.
//!
//! Two corpora are compared report for report: status, result values, step
//! count and, for faults, the code and its function, block and operation.
//!
//! 1. `programs/programs.smo`, authored by `programs/build.py`: loops, phis,
//!    recursion, every integer operation, poison, undef, stack memory,
//!    pointer provenance, data segments with relocations, bulk memory
//!    operations, code pointers, binary32 and binary64 arithmetic,
//!    comparison and conversion, and each kind of fault. The oracle is `oracle.py`, which runs the reference Machine in
//!    one process.
//! 2. Every object under the specification's `reference-execution` and
//!    `conformance/llvm` directories that both sides accept. The oracle is
//!    the reference command-line runner, started once per function.
//!
//! Python 3 is required. A missing or failing oracle fails the test; nothing
//! is skipped.
//!
//! Runtime services are outside the reference machine; `services.rs` tests
//! them on their own object.

mod services;

use rax_smir_portable::Limits;
use rax_smir_portable::interp::faults::{FAULTS, fault_info};
use rax_smir_portable::interp::{Exit, Fault, Outcome, Policy, run};
use rax_smir_portable::ir::{Module, Type, Value};
use serde_json::{Value as Json, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Limits for the authored programs. They bound the oracle's work, and several
/// programs are meant to reach them.
const POLICY: Policy = Policy {
    fuel: 2_000,
    max_frames: 64,
    // Small, so that the programs meant to exhaust memory do it cheaply: the
    // reference machine builds one object per guest byte.
    max_memory_bytes: 4096,
};
/// Limits in the reference runner's `policy.json`, used for existing objects.
const REFERENCE_POLICY: Policy = Policy {
    fuel: 10_000,
    max_frames: 128,
    max_memory_bytes: 1 << 20,
};

/// Oracle processes to run at once. The reference machine executes about
/// five thousand steps a second and its command-line runner takes several
/// seconds to start, so the oracle dominates this test's run time.
fn workers() -> usize {
    std::thread::available_parallelism()
        .map_or(2, |count| count.get())
        .clamp(2, 16)
}

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn specification() -> PathBuf {
    crate_dir().join("../../docs/specifications/smir/portable")
}

fn python() -> Command {
    let mut command = Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()));
    command.arg("-B").env("PYTHONDONTWRITEBYTECODE", "1");
    command
}

/// What both engines report about one run.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    status: String,
    steps: u64,
    values: Option<Vec<Json>>,
    code: Option<String>,
    /// Function, block and operation of a fault.
    location: Option<(u64, u64, i64)>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn little_endian(value: u128, bits: u32) -> String {
    hex(&value.to_le_bytes()[..bits.div_ceil(8) as usize])
}

fn located(status: &str, fault: Fault, steps: u64) -> Report {
    Report {
        status: status.into(),
        steps,
        values: None,
        code: Some(fault.code),
        location: Some((fault.function.into(), fault.block.into(), fault.operation)),
    }
}

fn from_outcome(outcome: Outcome, result_bits: &[u32]) -> Report {
    let steps = outcome.steps;
    match outcome.exit {
        Exit::Return(values) => Report {
            status: "return".into(),
            steps,
            values: Some(
                values
                    .iter()
                    .zip(result_bits)
                    .map(|(value, bits)| match value {
                        Value::Int(payload) => json!({"bits_le": little_endian(*payload, *bits)}),
                        Value::Poison => json!({"state": "poison"}),
                        Value::Undef => json!({"state": "undef"}),
                        other => panic!("non-integer result {other:?}"),
                    })
                    .collect(),
            ),
            code: None,
            location: None,
        },
        Exit::Trap(fault) => located("trap", fault, steps),
        Exit::LanguageUb(fault) => located("language_ub", fault, steps),
        Exit::Resource(reason) => Report {
            status: "resource".into(),
            steps,
            values: None,
            code: Some(reason.into()),
            location: None,
        },
        // These programs import no service that ends the program.
        other @ (Exit::Exited(_) | Exit::Aborted) => panic!("unexpected end {other:?}"),
    }
}

fn from_json(report: &Json) -> Report {
    let status = report["status"].as_str().expect("report status");
    let located = report.get("function").is_some();
    Report {
        status: status.strip_prefix("reference-").unwrap_or(status).into(),
        steps: report["steps"].as_u64().expect("report steps"),
        values: report
            .get("values")
            .map(|values| values.as_array().expect("values array").clone()),
        code: report
            .get("code")
            .map(|code| code.as_str().expect("code string").to_owned()),
        location: located.then(|| {
            (
                report["function"].as_u64().expect("fault function"),
                report["block"].as_u64().expect("fault block"),
                report["operation"].as_i64().expect("fault operation"),
            )
        }),
    }
}

/// Deterministic generator (SplitMix64); the corpus must not vary between runs.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn mask(bits: u32) -> u64 {
    u64::MAX >> (64 - bits)
}

/// Boundary values of a width, then values that keep loops short.
fn edges(bits: u32) -> Vec<u64> {
    let mask = mask(bits);
    let sign = 1_u64 << (bits - 1);
    let mut values = vec![
        0,
        1,
        2,
        3,
        mask,
        mask - 1,
        sign,
        sign - 1,
        sign + 1,
        u64::from(bits),
        u64::from(bits) - 1,
    ];
    values.extend([5, 7, 10, 27, 48, 100, 127, 200]);
    for value in &mut values {
        *value &= mask;
    }
    values.sort_unstable();
    values.dedup();
    values
}

/// Bit patterns that exercise a float format: zeros, infinities, quiet and
/// signaling NaNs of both signs with and without payloads, the smallest and
/// largest subnormal and normal magnitudes, and values around the limits of
/// the integer types.
fn float_edges(bits: u32) -> Vec<u64> {
    let values = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.0,
        0.5,
        1.5,
        -2.5,
        0.1,
        1.0e10,
        -3.0e-10,
        255.5,
        256.0,
        -128.5,
        -129.0,
        2147483648.0,
        -2147483648.0,
        4294967296.0,
        9223372036854775808.0,
        18446744073709551616.0,
    ];
    let mut edges: Vec<u64> = if bits == 32 {
        let mut edges: Vec<u64> = values
            .iter()
            .map(|value| u64::from((*value as f32).to_bits()))
            .collect();
        edges.extend([
            0x7f80_0000,
            0xff80_0000,
            0x7fc0_0000,
            0x7fc1_2345,
            0xffc0_0001,
            0x7f80_0001,
            0xffa0_0123,
            0x0000_0001,
            0x807f_ffff,
            0x0080_0000,
            0x7f7f_ffff,
            0xff7f_ffff,
            // Just below 2^31 and just below -2^31.
            0x4eff_ffff,
            0xcf00_0001,
        ]);
        edges
    } else {
        let mut edges: Vec<u64> = values.iter().map(|value: &f64| value.to_bits()).collect();
        edges.extend([
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0x7ff8_0000_0000_0000,
            0x7ff8_0012_3456_789a,
            0xfff8_0000_0000_0001,
            0x7ff0_0000_0000_0001,
            0xfff4_0000_0000_0123,
            0x0000_0000_0000_0001,
            0x800f_ffff_ffff_ffff,
            0x0010_0000_0000_0000,
            0x7fef_ffff_ffff_ffff,
            0xffef_ffff_ffff_ffff,
            // Just below 2^31 and just below -2^63.
            0x41df_ffff_ffff_ffff,
            0xc3e0_0000_0000_0001,
        ]);
        edges
    };
    edges.sort_unstable();
    edges.dedup();
    edges
}

/// One parameter or result of a program: its width, and whether it is a float.
#[derive(Clone, Copy)]
struct Kind {
    bits: u32,
    float: bool,
}

/// Encodings that exercise binary128, as [`float_edges`] does for the
/// narrower formats.
fn quad_edges() -> Vec<u128> {
    // Sign, unbiased exponent and fraction.
    let quad = |negative: bool, exponent: i32, fraction: u128| {
        u128::from(negative) << 127 | ((exponent + 16383) as u128) << 112 | fraction
    };
    let infinity = 0x7fff_u128 << 112;
    let mut edges = vec![
        0,
        1 << 127,
        quad(false, 0, 0),
        quad(true, 0, 0),
        quad(false, 1, 0),
        quad(false, -1, 0),
        quad(false, 1, 1 << 111),
        quad(true, 1, 1 << 110),
        // One third, and the neighbours of one.
        quad(false, -2, 0x5555_5555_5555_5555_5555_5555_5555),
        quad(false, 0, 1),
        quad(false, -1, (1 << 112) - 1),
        quad(false, 63, 0),
        quad(true, 63, 1),
        quad(false, 64, 0),
        quad(false, 127, 0),
        quad(false, 128, 0),
        quad(false, 300, 0x1234 << 90),
        infinity,
        infinity | 1 << 127,
        infinity | 1 << 111,
        infinity | 1 << 111 | 0x1234_5678,
        infinity | 1 << 127 | 1 << 111 | 1,
        infinity | 1,
        // The smallest and largest subnormal, the smallest normal and the
        // largest finite value.
        1,
        (1 << 112) - 1 | 1 << 127,
        1 << 112,
        infinity - 1,
        (infinity - 1) | 1 << 127,
    ];
    edges.sort_unstable();
    edges.dedup();
    edges
}

impl Kind {
    fn edges(self) -> Vec<u128> {
        match (self.float, self.bits) {
            (true, 128) => quad_edges(),
            (true, bits) => float_edges(bits).into_iter().map(u128::from).collect(),
            (false, bits) => edges(bits).into_iter().map(u128::from).collect(),
        }
    }
}

/// Argument tuples for a parameter list: every pairing of boundary values for
/// one or two parameters, a sample of triples for three, then pseudo-random
/// tuples of full-range and small values.
fn vectors(params: &[Kind], random: &mut Sequence) -> Vec<Vec<u128>> {
    let mut tuples: Vec<Vec<u128>> = match params {
        [only] => only.edges().into_iter().map(|value| vec![value]).collect(),
        [first, second] => first
            .edges()
            .into_iter()
            .flat_map(|a| second.edges().into_iter().map(move |b| vec![a, b]))
            .collect(),
        [_, _, _] => (0..400)
            .map(|_| {
                params
                    .iter()
                    .map(|kind| {
                        let edges = kind.edges();
                        edges[(random.next() % edges.len() as u64) as usize]
                    })
                    .collect()
            })
            .collect(),
        other => panic!("no vectors for {} parameters", other.len()),
    };
    for round in 0..48 {
        tuples.push(
            params
                .iter()
                .map(|kind| {
                    let value = random.next();
                    // Alternate full-range values with ones below 256. A small
                    // integer is a subnormal as a float, so floats instead
                    // alternate with numbers of moderate size.
                    match (round % 2 == 0, kind.float, kind.bits) {
                        (true, _, 128) => u128::from(value) << 64 | u128::from(random.next()),
                        (true, _, bits) => u128::from(value & mask(bits)),
                        (false, false, _) => u128::from(value & 0xff),
                        (false, true, 32) => {
                            u128::from(((value % 2001) as f32 / 8.0 - 125.0).to_bits())
                        }
                        (false, true, 64) => {
                            u128::from(((value % 2_000_001) as f64 / 64.0 - 15625.0).to_bits())
                        }
                        // An exponent near zero, a random fraction and sign.
                        (false, true, _) => {
                            (u128::from(value % 40) + 16383 - 20) << 112
                                | u128::from(random.next()) << 48
                                | u128::from(value >> 63) << 127
                        }
                    }
                })
                .collect(),
        );
    }
    tuples
}

struct Program {
    id: u32,
    name: String,
    params: Vec<Kind>,
    results: Vec<u32>,
}

fn programs() -> Vec<Program> {
    let text = std::fs::read_to_string(crate_dir().join("tests/interp/programs/index.json"))
        .expect("program index is part of the repository");
    let index: Json = serde_json::from_str(&text).expect("program index is JSON");
    // A width, or "f32", "f64" or "f128" for a float of that width.
    let kinds = |list: &Json| -> Vec<Kind> {
        list.as_array()
            .expect("kind list")
            .iter()
            .map(|kind| match kind.as_str() {
                Some("f32") => Kind {
                    bits: 32,
                    float: true,
                },
                Some("f64") => Kind {
                    bits: 64,
                    float: true,
                },
                Some("f128") => Kind {
                    bits: 128,
                    float: true,
                },
                Some(other) => panic!("unknown kind {other}"),
                None => Kind {
                    bits: kind.as_u64().expect("width") as u32,
                    float: false,
                },
            })
            .collect()
    };
    index
        .as_array()
        .expect("program list")
        .iter()
        .map(|entry| Program {
            id: entry["id"].as_u64().expect("program id") as u32,
            name: entry["name"].as_str().expect("program name").to_owned(),
            params: kinds(&entry["params"]),
            results: kinds(&entry["results"])
                .iter()
                .map(|kind| kind.bits)
                .collect(),
        })
        .collect()
}

/// Apply `work` to consecutive chunks of `items` on [`workers`] threads and
/// return the results in input order.
fn in_parallel<T: Sync, R: Send>(items: &[T], work: impl Fn(&[T]) -> Vec<R> + Sync) -> Vec<R> {
    let size = items.len().div_ceil(workers()).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(size)
            .map(|chunk| scope.spawn(|| work(chunk)))
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("oracle worker"))
            .collect()
    })
}

/// Run a command with `input` on stdin; return its exit code and stdout.
fn checked_status(mut command: Command, input: &[u8]) -> (Option<i32>, Vec<u8>) {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start smir-run");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input)
        .expect("write batch input");
    let output = child.wait_with_output().expect("smir-run output");
    (output.status.code(), output.stdout)
}

fn checked(mut command: Command, input: Option<&[u8]>, what: &str) -> Vec<u8> {
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{what}: cannot start: {error}"));
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .expect("write oracle input");
    }
    let output = child.wait_with_output().expect("oracle output");
    assert!(
        output.status.success(),
        "{what} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn committed_programs_are_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    let mut build = python();
    build.arg(directory.join("build.py")).arg("--check");
    checked(build, None, "programs/build.py --check");
    let mut assemble = python();
    assemble
        .arg(crate_dir().join("tests/interp/oracle.py"))
        .arg("assemble")
        .arg(directory.join("programs.json"))
        .arg(directory.join("programs.smo"));
    checked(assemble, None, "oracle.py assemble");
}

#[test]
fn authored_programs_agree_with_the_reference_machine_on_every_report() {
    let object = crate_dir().join("tests/interp/programs/programs.smo");
    let module = Module::load(
        &std::fs::read(&object).expect("programs.smo"),
        Limits::default(),
    )
    .expect("programs.smo verifies and lowers");
    let programs = programs();
    assert_eq!(
        programs.len(),
        91,
        "program index changed; update this count deliberately"
    );

    let mut random = Sequence(0x534d_4952_4d31_0001);
    let mut cases = Vec::new();
    for program in &programs {
        for arguments in vectors(&program.params, &mut random) {
            cases.push((program, arguments));
        }
    }
    let request: Vec<Json> = cases
        .iter()
        .map(|(program, arguments)| {
            json!({
                "function": program.id,
                "arguments": arguments.iter().zip(&program.params)
                    .map(|(value, kind)| little_endian(*value, kind.bits)).collect::<Vec<_>>(),
                "fuel": POLICY.fuel,
                "max_frames": POLICY.max_frames,
                "max_memory_bytes": POLICY.max_memory_bytes,
            })
        })
        .collect();
    let expected: Vec<Json> = in_parallel(&request, |chunk| {
        let mut oracle = python();
        oracle
            .arg(crate_dir().join("tests/interp/oracle.py"))
            .arg("machine")
            .arg(&object);
        let stdout = checked(
            oracle,
            Some(&serde_json::to_vec(chunk).unwrap()),
            "oracle.py machine",
        );
        let reports: Vec<Json> = serde_json::from_slice(&stdout).expect("oracle reports are JSON");
        assert_eq!(
            reports.len(),
            chunk.len(),
            "oracle answered a different number of cases"
        );
        reports
    });

    let mut statuses = std::collections::BTreeMap::<String, usize>::new();
    let mut exercised = std::collections::BTreeSet::<String>::new();
    let mut explicit_traps = 0;
    let mut exposures = 0;
    let mut disagreements = Vec::new();
    for ((program, arguments), expected) in cases.iter().zip(&expected) {
        let entry = module
            .function(program.id)
            .expect("program is in the module");
        let values: Vec<Value> = arguments.iter().map(|value| Value::Int(*value)).collect();
        let actual = from_outcome(
            run(&module, entry, &values, POLICY).expect("entry request"),
            &program.results,
        );
        let expected = from_json(expected);
        *statuses.entry(actual.status.clone()).or_default() += 1;
        if let Some(code) = &actual.code {
            // Every fault is a registered code of the class it was reported
            // as, or the reason token of the one explicit trap terminator in
            // these programs.
            if (actual.status.as_str(), code.as_str()) == ("trap", "bad_case") {
                explicit_traps += 1;
            } else {
                let registered = fault_info(code).map(|info| info.class.as_str());
                assert_eq!(
                    registered,
                    Some(actual.status.as_str()),
                    "{} raised {code}",
                    program.name
                );
                exercised.insert(code.clone());
            }
        }
        if actual != expected {
            // The one place where this engine differs on purpose.
            // pointer_roundtrip reads a stored pointer as an integer, writes
            // that integer back and loads it as a pointer. The reference
            // machine gives the result no origin, so using it is undefined.
            // Here the integer read exposed the object, so the address names
            // it again, as an integer converted to a pointer would: compiled
            // code that copies pointers byte by byte depends on that.
            let exposed = program.name == "pointer_roundtrip"
                && expected.code.as_deref() == Some("pointer_provenance")
                && actual.values == Some(vec![json!({"bits_le": little_endian(arguments[0], 64)})]);
            if exposed {
                exposures += 1;
                continue;
            }
            disagreements.push(format!(
                "{}{arguments:x?}:\n  rust   {actual:?}\n  python {expected:?}",
                program.name
            ));
        }
    }
    assert_eq!(exposures, 34, "the cases that differ by exposure changed");
    assert!(
        disagreements.is_empty(),
        "{} of {} cases disagree; first:\n{}",
        disagreements.len(),
        cases.len(),
        disagreements
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "{} cases agree and {exposures} differ by exposure, as intended; by status: {statuses:?}",
        cases.len() - exposures
    );
    // The corpus must keep exercising every kind of outcome.
    for status in ["return", "language_ub", "trap", "resource"] {
        assert!(
            statuses.get(status).copied().unwrap_or(0) >= 10,
            "too few {status} cases: {statuses:?}"
        );
    }
    assert!(
        explicit_traps > 0,
        "no case reached the explicit trap terminator"
    );
    // The corpus raises every registered fault except those listed here.
    let unexercised: Vec<&str> = FAULTS
        .iter()
        .map(|info| info.code)
        .filter(|code| !exercised.contains(*code))
        .collect();
    assert_eq!(
        unexercised,
        [
            // An alignment that is not a power of two cannot be encoded.
            "allocation_shape",
            // code_bind needs a non-callable code address, which the
            // reference machine only issues through its source registry; see
            // the interpreter's unit tests.
            "code_address_unbound",
            // Non-callable code addresses cannot be stored yet.
            "memory_code_pointer",
            // Raised by runtime services, which the reference machine does
            // not perform; see services.rs.
            "service_argument",
            // Needs an allocation near the top of the address space.
            "source_object_extent",
            // Also raised only by runtime services.
            "ub_service_argument",
        ],
        "the set of faults the corpus does not raise changed"
    );
    assert!(
        cases.len() >= 19_000,
        "corpus shrank to {} cases",
        cases.len()
    );
}

#[test]
fn data_that_exceeds_the_memory_limit_stops_the_run_before_its_first_step() {
    let object = crate_dir().join("tests/interp/programs/programs.smo");
    let module = Module::load(
        &std::fs::read(&object).expect("programs.smo"),
        Limits::default(),
    )
    .expect("programs.smo verifies and lowers");
    // The module's segments need more than 16 bytes.
    let policy = Policy {
        max_memory_bytes: 16,
        ..POLICY
    };
    let entry = module.function(160).expect("table_lookup");
    let actual = from_outcome(
        run(&module, entry, &[Value::Int(1)], policy).expect("entry request"),
        &[32],
    );
    assert_eq!(
        actual,
        Report {
            status: "resource".into(),
            steps: 0,
            values: None,
            code: Some("resource_memory".into()),
            location: None
        }
    );
    let request = json!([{
        "function": 160, "arguments": [little_endian(1, 32)], "fuel": policy.fuel,
        "max_frames": policy.max_frames, "max_memory_bytes": policy.max_memory_bytes,
    }]);
    let mut oracle = python();
    oracle
        .arg(crate_dir().join("tests/interp/oracle.py"))
        .arg("machine")
        .arg(&object);
    let stdout = checked(
        oracle,
        Some(&serde_json::to_vec(&request).unwrap()),
        "oracle.py machine",
    );
    let reports: Vec<Json> = serde_json::from_slice(&stdout).expect("oracle reports are JSON");
    assert_eq!(from_json(&reports[0]), actual);
}

fn objects(directory: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            objects(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "smo") {
            found.push(path);
        }
    }
}

/// Run one function through the reference command-line runner.
fn reference_cli(object: &Path, function: u32, arguments: &[String]) -> Json {
    let specification = specification();
    let mut command = python();
    command
        .arg(crate_dir().join("../../tools/smir-format/codec.py"))
        .arg("run-candidate-reference")
        .arg(object)
        .arg("--entry-function")
        .arg(function.to_string())
        .arg("--reference-policy")
        .arg(specification.join("conformance/envelope/candidate/reference-execution/policy.json"));
    for argument in arguments {
        command.arg("--argument-bits").arg(argument);
    }
    let output = command.output().expect("start the reference runner");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "{} function {function}: reference runner printed no report: {}",
            object.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn existing_objects_agree_with_the_reference_runner_wherever_both_execute() {
    let specification = specification();
    let mut found = Vec::new();
    objects(
        &specification.join("conformance/envelope/candidate/reference-execution"),
        &mut found,
    );
    objects(&specification.join("conformance/llvm"), &mut found);
    assert!(found.len() >= 100, "only {} objects found", found.len());

    // Everything this crate can run with integer arguments and results.
    struct Request {
        object: PathBuf,
        function: u32,
        arguments: Vec<String>,
        actual: Report,
    }
    let mut refused_here = 0;
    let mut requests = Vec::new();
    for object in &found {
        let bytes = std::fs::read(object).expect("object bytes");
        let Ok(module) = Module::load(&bytes, Limits::default()) else {
            refused_here += 1;
            continue;
        };
        for id in module.function_ids() {
            let entry = module.function(id).expect("listed function");
            let signature = module.signature(entry);
            let width = |ty| match module.ty(ty) {
                Type::Int { bits } if *bits <= 64 => Some(*bits),
                _ => None,
            };
            let (Some(params), Some(results)) = (
                signature
                    .params()
                    .iter()
                    .map(|ty| width(*ty))
                    .collect::<Option<Vec<u32>>>(),
                signature
                    .results()
                    .iter()
                    .map(|ty| width(*ty))
                    .collect::<Option<Vec<u32>>>(),
            ) else {
                continue;
            };
            // One is representable at every width, including a single bit.
            let arguments: Vec<Value> = params.iter().map(|_| Value::Int(1)).collect();
            let outcome = run(&module, entry, &arguments, REFERENCE_POLICY).expect("entry request");
            requests.push(Request {
                object: object.clone(),
                function: id,
                arguments: params.iter().map(|bits| little_endian(1, *bits)).collect(),
                actual: from_outcome(outcome, &results),
            });
        }
    }
    let references = in_parallel(&requests, |chunk| {
        chunk
            .iter()
            .map(|request| reference_cli(&request.object, request.function, &request.arguments))
            .collect()
    });
    let (mut agreed, mut refused_there) = (0, 0);
    let mut disagreements = Vec::new();
    for (request, reference) in requests.iter().zip(&references) {
        let status = reference["status"].as_str().expect("reference status");
        if !matches!(
            status,
            "reference-return" | "reference-trap" | "reference-language_ub" | "reference-resource"
        ) {
            // The reference refused before running. That is acceptable only
            // when the refusal is a limit of the reference runner itself: its
            // source registry is unavailable for the object, or the request is
            // outside the runner's declared scope. A refusal on any other
            // ground would mean this crate runs an object the reference
            // considers invalid.
            let code = reference["code"].as_str().unwrap_or_default();
            let scope_limit = status == "reference-unavailable"
                || (status == "reference-rejected" && code.starts_with("REFERENCE-"));
            if scope_limit {
                refused_there += 1;
            } else {
                disagreements.push(format!(
                    "{} function {}: this crate runs it, the reference refuses with {status} {code}",
                    request.object.display(),
                    request.function
                ));
            }
        } else if request.actual == from_json(reference) {
            agreed += 1;
        } else {
            disagreements.push(format!(
                "{} function {}:\n  rust   {:?}\n  python {reference}",
                request.object.display(),
                request.function,
                request.actual
            ));
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    eprintln!(
        "{agreed} functions agree; {refused_here} objects refused by this crate, \
         {refused_there} requests refused by the reference runner"
    );
    assert!(
        agreed >= 59,
        "only {agreed} functions were executed by both sides"
    );
}

#[test]
fn the_command_line_runner_prints_the_same_report_as_the_library() {
    let object =
        specification().join("conformance/envelope/candidate/reference-execution/call42.smo");
    let output = Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .arg(&object)
        .args(["--entry-function", "1", "--argument-bits", "2a000000"])
        .output()
        .expect("start smir-run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Json = serde_json::from_slice(&output.stdout).expect("smir-run prints JSON");
    assert_eq!(report["status"], "return");
    assert_eq!(report["steps"], 7);
    assert_eq!(report["values"], json!([{"bits_le": "2a000000"}]));
    assert_eq!(report["entry_function"], 1);
    // The reference runner reports the same content identity for this object.
    assert_eq!(
        report["content_digest"],
        reference_cli(&object, 1, &["2a000000".into()])["content_digest"]
    );

    for (arguments, code, status) in [
        (
            vec!["--entry-function", "1", "--argument-bits", "2a0000"],
            "ARGUMENT_BITS",
            1,
        ),
        (vec!["--entry-function", "1"], "ARGUMENT_ARITY", 1),
        (
            vec!["--entry-function", "77", "--argument-bits", "2a000000"],
            "ENTRY_FUNCTION",
            1,
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_smir-run"))
            .arg(&object)
            .args(&arguments)
            .output()
            .unwrap();
        let report: Json = serde_json::from_slice(&output.stdout).expect("rejections are JSON too");
        assert_eq!(output.status.code(), Some(status), "{arguments:?}");
        assert_eq!(
            (report["status"].as_str(), report["code"].as_str()),
            (Some("rejected"), Some(code))
        );
    }
    let usage = Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .arg(&object)
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));
    assert!(usage.stdout.is_empty());
}

#[test]
fn batch_mode_reports_every_case_in_order_and_survives_rejected_requests() {
    let object = crate_dir().join("tests/interp/programs/programs.smo");
    let run_batch = |extra: &[&str], input: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_smir-run"));
        command.arg(&object).arg("--batch").args(extra);
        let (status, stdout) = checked_status(command, input.as_bytes());
        (
            status,
            serde_json::from_slice::<Json>(&stdout).expect("batch output is JSON"),
        )
    };
    // gcd(48, 18); an unknown function; a malformed argument; a malformed
    // entry; fact(5). Rejections are reported in place.
    let input = r#"[
        {"function": 100, "arguments": ["3000000000000000", "1200000000000000"]},
        {"function": 9999, "arguments": []},
        {"function": 104, "arguments": ["05"]},
        {"arguments": []},
        {"function": 104, "arguments": ["0500000000000000"]}
    ]"#;
    let (status, reports) = run_batch(&[], input);
    assert_eq!(status, Some(0));
    let reports = reports.as_array().expect("array of reports");
    assert_eq!(reports.len(), 5);
    assert_eq!(
        reports[0]["values"],
        json!([{"bits_le": "0600000000000000"}])
    );
    assert_eq!(reports[1]["code"], "ENTRY_FUNCTION");
    assert_eq!(reports[2]["code"], "ARGUMENT_BITS");
    assert_eq!(reports[3]["code"], "BATCH_ENTRY");
    assert_eq!(
        reports[4]["values"],
        json!([{"bits_le": "7800000000000000"}])
    );

    // The policy flags apply to every case of the batch.
    let (_, limited) = run_batch(
        &["--fuel", "3"],
        r#"[{"function": 116, "arguments": ["05000000"]}]"#,
    );
    assert_eq!(
        limited[0],
        json!({"status": "resource", "code": "fuel", "steps": 3})
    );

    // Input that is not a JSON array rejects the batch as a whole.
    let (status, rejected) = run_batch(&[], "{}");
    assert_eq!(status, Some(1));
    assert_eq!(rejected["code"], "BATCH_JSON");

    // --batch excludes the single-run arguments.
    let mixed = Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .arg(&object)
        .args(["--batch", "--entry-function", "100"])
        .output()
        .unwrap();
    assert_eq!(mixed.status.code(), Some(2));
}
