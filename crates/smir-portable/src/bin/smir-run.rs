//! Run a portable SMIR object: one function, a batch of function calls, or
//! the whole program.
//!
//! OBJECT is the object itself, or an ELF, Mach-O or PE file that carries
//! one (see `smir-pack`): the object is then what the file's locator names.
//!
//! ```text
//! smir-run OBJECT --entry-function ID [--argument-bits HEX]... [OPTIONS]
//! smir-run OBJECT --batch [OPTIONS] < cases.json
//! smir-run OBJECT --program [OPTIONS] [-- ARGUMENT...]
//! ```
//!
//! `OPTIONS` are the limits `--fuel N` (steps), `--max-frames N` (call depth)
//! and `--max-memory-bytes N` (bytes of live memory objects), `--processors N`
//! (how many of its threads the program is told run at one time, instead of
//! what this machine runs), and `--native`,
//! which compiles the object to code for this host and runs that instead of
//! interpreting. Either way a run ends the same and reports the same.
//!
//! # One function
//!
//! Each `--argument-bits` is one integer argument as little-endian hex of
//! exactly its type's byte size. The result is one line of JSON on stdout.
//! Exit status: 0 when the program ran (whatever its outcome), 1 when the
//! object or the entry request was rejected, 2 for a usage error.
//!
//! `--batch` loads the object once and reads a JSON array of
//! `{"function": ID, "arguments": [HEX, ...]}` from stdin. It prints a JSON
//! array with one report per case, in order. A case whose request is rejected
//! gets a `rejected` report and does not stop the batch; the exit status is 0
//! once the object has loaded and the input has parsed.
//!
//! Functions run with no capability granted, so an object that imports
//! runtime services is rejected in these two modes.
//!
//! # The program
//!
//! `--program` runs the exported function `_start`, which the compiler
//! generates and which is `int(int, char **, char **)`, or else the exported
//! `main`, which is `int(void)` or `int(int, char **)`. The argument vector
//! is OBJECT followed by each ARGUMENT, and the environment is empty. The
//! program's standard input, output and error are this process's, and it may
//! end itself. With `--directory DIR` it also has files: those under DIR,
//! which is the root of every path it uses and the directory its relative
//! paths start from. Nothing else outside the program is reachable.
//! There is no step limit unless `--fuel` is given, and the memory limit
//! defaults to 16 MiB.
//!
//! The exit status is the low eight bits of what the entry returned or of the
//! status the program exited with. If the program did not end that way, one
//! line of JSON on standard error says how it ended and the exit status is
//! 134 for an abort and 125 for anything else: a fault, an exhausted limit,
//! or an object that could not be run.

use rax_smir_portable::carrier;
use rax_smir_portable::interp::{
    Code, Directory, Engine, Exit, Fault, NoHost, Outcome, Policy, StandardStreams, run_on,
    run_program_on,
};
use rax_smir_portable::ir::{Module, Type, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::{Value as Json, json};
use std::io::{Read, Write};
use std::process::ExitCode;

const USAGE: &str = "usage: smir-run OBJECT --entry-function ID [--argument-bits HEX]... [OPTIONS]\n       \
smir-run OBJECT --batch [OPTIONS] < cases.json\n       \
smir-run OBJECT --program [--directory DIR] [OPTIONS] [-- ARGUMENT...]\n\
OPTIONS: [--fuel N] [--max-frames N] [--max-memory-bytes N] [--processors N] [--native]";

/// What verifying an object may cost. The defaults suit an object of a few
/// functions; a program linked with a C library is a few megabytes, and the
/// verifier's accounting of derived storage is generous.
const LIMITS: Limits = Limits {
    max_object_bytes: 256 * 1024 * 1024,
    max_payload_bytes: 128 * 1024 * 1024,
    max_record_nodes: 50_000_000,
    max_record_depth: 64,
    max_list_items: 4_000_000,
    max_string_bytes: 16 * 1024 * 1024,
    max_semantic_work: 20_000_000_000,
    max_graph_edges: 50_000_000,
    max_derived_bytes: 8 * 1024 * 1024 * 1024,
};

/// Memory limit of a program run when none is given.
const PROGRAM_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
/// Exit status when a program did not end by returning or exiting.
const STATUS_NOT_COMPLETED: u8 = 125;
/// Exit status when a program aborted: 128 plus the number of SIGABRT.
const STATUS_ABORTED: u8 = 134;

/// Largest batch description read from stdin.
const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;

enum Mode {
    Single {
        entry: u32,
        arguments: Vec<String>,
    },
    Batch,
    Program {
        arguments: Vec<Vec<u8>>,
        /// The directory whose files the program has, if any.
        directory: Option<String>,
    },
}

struct Request {
    object: String,
    mode: Mode,
    policy: Policy,
    /// Run as native code.
    native: bool,
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let mut object = None;
    let mut entry = None;
    let (mut batch, mut program, mut native) = (false, false, false);
    let mut arguments = Vec::new();
    let mut trailing = Vec::new();
    let (mut fuel, mut max_frames, mut max_memory_bytes) = (None, None, None);
    let mut directory = None;
    let mut processors = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry-function" => entry = Some(args.next()?.parse().ok()?),
            "--argument-bits" => arguments.push(args.next()?),
            "--batch" => batch = true,
            "--program" => program = true,
            "--native" => native = true,
            "--directory" => directory = Some(args.next()?),
            "--fuel" => fuel = Some(args.next()?.parse().ok()?),
            "--max-frames" => max_frames = Some(args.next()?.parse().ok()?),
            "--max-memory-bytes" => max_memory_bytes = Some(args.next()?.parse().ok()?),
            "--processors" => {
                processors = Some(args.next()?.parse().ok().filter(|count| *count != 0)?);
            }
            // Everything after `--` belongs to the program.
            "--" => trailing.extend(args.by_ref().map(String::into_bytes)),
            _ if arg.starts_with("--") || object.is_some() => return None,
            _ => object = Some(arg),
        }
    }
    let object: String = object?;
    let mut policy = Policy::default();
    let mode = match (batch, program, entry) {
        // Only a program has files.
        (true, false, None) | (false, false, Some(_)) if directory.is_some() => return None,
        (true, false, None) if arguments.is_empty() && trailing.is_empty() => Mode::Batch,
        (false, false, Some(entry)) if trailing.is_empty() => Mode::Single { entry, arguments },
        (false, true, None) if arguments.is_empty() => {
            policy.fuel = u64::MAX;
            policy.max_memory_bytes = PROGRAM_MEMORY_BYTES;
            trailing.insert(0, object.clone().into_bytes());
            Mode::Program {
                arguments: trailing,
                directory,
            }
        }
        _ => return None,
    };
    policy.fuel = fuel.unwrap_or(policy.fuel);
    policy.max_frames = max_frames.unwrap_or(policy.max_frames);
    policy.max_memory_bytes = max_memory_bytes.unwrap_or(policy.max_memory_bytes);
    policy.processors = processors.unwrap_or(policy.processors);
    Some(Request {
        object,
        mode,
        policy,
        native,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rejected(class: &str, code: &str, detail: &str) -> Json {
    json!({"status": "rejected", "class": class, "code": code, "detail": detail})
}

fn error(diagnostic: &Error) -> Json {
    rejected(
        diagnostic.class().as_str(),
        diagnostic.code(),
        diagnostic.context(),
    )
}

/// Decode little-endian hex for an integer of `bits` width.
fn argument(text: &str, bits: u32) -> Option<Value> {
    let size = bits.div_ceil(8) as usize;
    if text.len() != 2 * size || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut value = 0_u128;
    for position in 0..size {
        let byte = u8::from_str_radix(text.get(2 * position..2 * position + 2)?, 16).ok()?;
        value |= u128::from(byte) << (8 * position);
    }
    (bits == 128 || value >> bits == 0).then_some(Value::Int(value))
}

fn result(value: Value, bits: u32) -> Json {
    match value {
        Value::Int(payload) => {
            json!({"bits_le": hex(&payload.to_le_bytes()[..bits.div_ceil(8) as usize])})
        }
        Value::Poison => json!({"state": "poison"}),
        Value::Undef => json!({"state": "undef"}),
        // The entry signature was checked to return integers only.
        Value::DataPtr(_) | Value::CodeAddress(_) | Value::CodePtr(_) => {
            json!({"state": "pointer"})
        }
    }
}

fn located(status: &str, fault: &Fault, steps: u64) -> Json {
    json!({
        "status": status, "code": fault.code, "steps": steps,
        "function": fault.function, "block": fault.block, "operation": fault.operation,
    })
}

fn load(object: &str) -> Result<Module, Json> {
    let bytes = std::fs::read(object)
        .map_err(|failure| rejected("io", "OBJECT_READ", &failure.to_string()))?;
    // The object itself, or the one a native file carries.
    let payload = carrier::payload(&bytes).map_err(|diagnostic| error(&diagnostic))?;
    Module::load(payload, LIMITS).map_err(|diagnostic| error(&diagnostic))
}

/// Run one function. `Err` is a rejected request; nothing ran.
fn case(
    engine: Engine,
    module: &Module,
    function: u32,
    arguments: &[String],
    policy: Policy,
) -> Result<Json, Json> {
    let entry = module
        .function(function)
        .ok_or_else(|| rejected("request", "ENTRY_FUNCTION", "no such function"))?;
    let signature = module.signature(entry);
    let width = |ty| match module.ty(ty) {
        Type::Int { bits } => Some(*bits),
        // A float is passed and reported as the bits of its encoding.
        Type::Float { format } => Some(format.bits()),
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
        return Err(rejected(
            "request",
            "ENTRY_SIGNATURE",
            "entry parameters and results must be integers or floats",
        ));
    };
    if params.len() != arguments.len() {
        return Err(rejected(
            "request",
            "ARGUMENT_ARITY",
            "argument count differs from the signature",
        ));
    }
    let values = arguments
        .iter()
        .zip(&params)
        .map(|(text, bits)| argument(text, *bits))
        .collect::<Option<Vec<Value>>>()
        .ok_or_else(|| {
            rejected(
                "request",
                "ARGUMENT_BITS",
                "malformed or out-of-range argument",
            )
        })?;
    let Outcome { exit, steps } = run_on(engine, module, entry, &values, policy, &mut NoHost)
        .map_err(|diagnostic| error(&diagnostic))?;
    Ok(match exit {
        Exit::Return(values) => json!({
            "status": "return",
            "content_digest": hex(&module.identity()),
            "entry_function": function,
            "steps": steps,
            "values": values.iter().zip(&results).map(|(value, bits)| result(*value, *bits)).collect::<Vec<_>>(),
        }),
        other => stopped(&other, steps),
    })
}

/// The report of a run that ended in any way but returning.
fn stopped(exit: &Exit, steps: u64) -> Json {
    match exit {
        Exit::Return(_) => json!({"status": "return", "steps": steps}),
        Exit::Trap(fault) => located("trap", fault, steps),
        Exit::LanguageUb(fault) => located("language_ub", fault, steps),
        Exit::Resource(reason) => json!({"status": "resource", "code": reason, "steps": steps}),
        Exit::Exited(status) => json!({"status": "exit", "exit_status": status, "steps": steps}),
        Exit::Aborted => json!({"status": "abort", "steps": steps}),
        Exit::Deadlock => json!({"status": "deadlock", "steps": steps}),
    }
}

/// Run the program and return its exit status. `Err` is the report of a run
/// that did not end by returning from `main` or by exiting, with the status
/// to exit with.
fn program(
    engine: Engine,
    module: &Module,
    arguments: &[Vec<u8>],
    directory: Option<&str>,
    policy: Policy,
) -> Result<u8, (Json, u8)> {
    let streams = StandardStreams {
        // The program's threads share the streams, so they are not held
        // locked for the run.
        input: std::io::stdin(),
        output: std::io::stdout(),
        error: std::io::stderr(),
    };
    let (outcome, mut streams) = match directory {
        None => {
            let mut host = streams;
            let outcome = run_program_on(engine, module, arguments, policy, &mut host);
            (outcome, host)
        }
        Some(directory) => {
            let mut host = Directory::new(streams, directory).map_err(|failure| {
                (
                    rejected("io", "DIRECTORY", &format!("{directory}: {failure}")),
                    STATUS_NOT_COMPLETED,
                )
            })?;
            let outcome = run_program_on(engine, module, arguments, policy, &mut host);
            (outcome, host.inner)
        }
    };
    let flushed = streams.output.flush();
    // Release the streams before anything is reported on them.
    drop(streams);
    let Outcome { exit, steps } =
        outcome.map_err(|diagnostic| (error(&diagnostic), STATUS_NOT_COMPLETED))?;
    flushed.map_err(|failure| {
        (
            rejected("io", "OUTPUT_FLUSH", &failure.to_string()),
            STATUS_NOT_COMPLETED,
        )
    })?;
    match exit {
        // Only the low eight bits of a status reach the parent process.
        Exit::Return(values) => match values.as_slice() {
            [Value::Int(status)] => Ok(*status as u8),
            // An unspecified status refines to zero.
            [Value::Undef] => Ok(0),
            _ => Err((
                json!({"status": "return", "values": [{"state": "poison"}], "steps": steps}),
                STATUS_NOT_COMPLETED,
            )),
        },
        Exit::Exited(status) => Ok(status as u8),
        Exit::Aborted => Err((stopped(&Exit::Aborted, steps), STATUS_ABORTED)),
        other => Err((stopped(&other, steps), STATUS_NOT_COMPLETED)),
    }
}

/// Parse one batch entry into a function identifier and its arguments.
fn batch_entry(entry: &Json) -> Option<(u32, Vec<String>)> {
    let function = u32::try_from(entry.get("function")?.as_u64()?).ok()?;
    let arguments = entry
        .get("arguments")?
        .as_array()?
        .iter()
        .map(|argument| argument.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    Some((function, arguments))
}

fn batch(engine: Engine, module: &Module, policy: Policy) -> Result<Json, Json> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_BATCH_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|failure| rejected("io", "BATCH_READ", &failure.to_string()))?;
    if input.len() as u64 > MAX_BATCH_BYTES {
        return Err(rejected(
            "request",
            "BATCH_SIZE",
            "batch description is too large",
        ));
    }
    let cases: Vec<Json> = serde_json::from_slice(&input)
        .map_err(|failure| rejected("request", "BATCH_JSON", &failure.to_string()))?;
    Ok(Json::Array(
        cases
            .iter()
            .map(|entry| match batch_entry(entry) {
                Some((function, arguments)) => case(engine, module, function, &arguments, policy)
                    .unwrap_or_else(|rejection| rejection),
                None => rejected("request", "BATCH_ENTRY", "expected {function, arguments}"),
            })
            .collect(),
    ))
}

fn main() -> ExitCode {
    let Some(request) = parse(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // The object, and its native code if that was asked for.
    let loaded = load(&request.object).and_then(|module| {
        let code = if request.native {
            Some(Code::compile(&module).map_err(|diagnostic| error(&diagnostic))?)
        } else {
            None
        };
        Ok((module, code))
    });
    fn engine(code: &Option<Code>) -> Engine<'_> {
        match code {
            Some(code) => Engine::Native(code),
            None => Engine::Interpreter,
        }
    }
    let outcome = match (&request.mode, &loaded) {
        (
            Mode::Program {
                arguments,
                directory,
            },
            loaded,
        ) => {
            let status = loaded
                .as_ref()
                .map_err(|rejection| (rejection.clone(), STATUS_NOT_COMPLETED))
                .and_then(|(module, code)| {
                    program(
                        engine(code),
                        module,
                        arguments,
                        directory.as_deref(),
                        request.policy,
                    )
                });
            return ExitCode::from(status.unwrap_or_else(|(report, status)| {
                eprintln!("{report}");
                status
            }));
        }
        (_, Err(rejection)) => Err(rejection.clone()),
        (Mode::Single { entry, arguments }, Ok((module, code))) => {
            case(engine(code), module, *entry, arguments, request.policy)
        }
        (Mode::Batch, Ok((module, code))) => batch(engine(code), module, request.policy),
    };
    let (report, status) = match outcome {
        Ok(report) => (report, 0),
        Err(rejection) => (rejection, 1),
    };
    println!("{report}");
    ExitCode::from(status)
}
