//! Run a portable SMIR object in the interpreter: one function, a batch of
//! function calls, or the whole program.
//!
//! ```text
//! smir-run OBJECT --entry-function ID [--argument-bits HEX]... [LIMITS]
//! smir-run OBJECT --batch [LIMITS] < cases.json
//! smir-run OBJECT --program [LIMITS] [-- ARGUMENT...]
//! ```
//!
//! `LIMITS` are `--fuel N` (steps), `--max-frames N` (call depth) and
//! `--max-memory-bytes N` (bytes of live memory objects).
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
//! is OBJECT followed by each ARGUMENT, and the environment is empty. The program's standard input, output and error are this
//! process's, and it may end itself; nothing else outside it is reachable.
//! There is no step limit unless `--fuel` is given, and the memory limit
//! defaults to 16 MiB.
//!
//! The exit status is the low eight bits of what the entry returned or of the
//! status the program exited with. If the program did not end that way, one
//! line of JSON on standard error says how it ended and the exit status is
//! 134 for an abort and 125 for anything else: a fault, an exhausted limit,
//! or an object that could not be run.

use rax_smir_portable::interp::{Exit, Fault, Outcome, Policy, StandardStreams, run, run_program};
use rax_smir_portable::ir::{Module, Type, Value};
use rax_smir_portable::{Error, Limits};
use serde_json::{Value as Json, json};
use std::io::{Read, Write};
use std::process::ExitCode;

const USAGE: &str = "usage: smir-run OBJECT --entry-function ID [--argument-bits HEX]... [LIMITS]\n       \
smir-run OBJECT --batch [LIMITS] < cases.json\n       \
smir-run OBJECT --program [LIMITS] [-- ARGUMENT...]\n\
LIMITS: [--fuel N] [--max-frames N] [--max-memory-bytes N]";

/// Memory limit of a program run when none is given.
const PROGRAM_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
/// Exit status when a program did not end by returning or exiting.
const STATUS_NOT_COMPLETED: u8 = 125;
/// Exit status when a program aborted: 128 plus the number of SIGABRT.
const STATUS_ABORTED: u8 = 134;

/// Largest batch description read from stdin.
const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;

enum Mode {
    Single { entry: u32, arguments: Vec<String> },
    Batch,
    Program { arguments: Vec<Vec<u8>> },
}

struct Request {
    object: String,
    mode: Mode,
    policy: Policy,
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let mut object = None;
    let mut entry = None;
    let (mut batch, mut program) = (false, false);
    let mut arguments = Vec::new();
    let mut trailing = Vec::new();
    let (mut fuel, mut max_frames, mut max_memory_bytes) = (None, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--entry-function" => entry = Some(args.next()?.parse().ok()?),
            "--argument-bits" => arguments.push(args.next()?),
            "--batch" => batch = true,
            "--program" => program = true,
            "--fuel" => fuel = Some(args.next()?.parse().ok()?),
            "--max-frames" => max_frames = Some(args.next()?.parse().ok()?),
            "--max-memory-bytes" => max_memory_bytes = Some(args.next()?.parse().ok()?),
            // Everything after `--` belongs to the program.
            "--" => trailing.extend(args.by_ref().map(String::into_bytes)),
            _ if arg.starts_with("--") || object.is_some() => return None,
            _ => object = Some(arg),
        }
    }
    let object: String = object?;
    let mut policy = Policy::default();
    let mode = match (batch, program, entry) {
        (true, false, None) if arguments.is_empty() && trailing.is_empty() => Mode::Batch,
        (false, false, Some(entry)) if trailing.is_empty() => Mode::Single { entry, arguments },
        (false, true, None) if arguments.is_empty() => {
            policy.fuel = u64::MAX;
            policy.max_memory_bytes = PROGRAM_MEMORY_BYTES;
            trailing.insert(0, object.clone().into_bytes());
            Mode::Program {
                arguments: trailing,
            }
        }
        _ => return None,
    };
    policy.fuel = fuel.unwrap_or(policy.fuel);
    policy.max_frames = max_frames.unwrap_or(policy.max_frames);
    policy.max_memory_bytes = max_memory_bytes.unwrap_or(policy.max_memory_bytes);
    Some(Request {
        object,
        mode,
        policy,
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
    Module::load(&bytes, Limits::default()).map_err(|diagnostic| error(&diagnostic))
}

/// Run one function. `Err` is a rejected request; nothing ran.
fn case(
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
    let Outcome { exit, steps } =
        run(module, entry, &values, policy).map_err(|diagnostic| error(&diagnostic))?;
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
    }
}

/// Run the program and return its exit status. `Err` is the report of a run
/// that did not end by returning from `main` or by exiting, with the status
/// to exit with.
fn program(module: &Module, arguments: &[Vec<u8>], policy: Policy) -> Result<u8, (Json, u8)> {
    let mut host = StandardStreams {
        input: std::io::stdin().lock(),
        output: std::io::stdout().lock(),
        error: std::io::stderr().lock(),
    };
    let outcome = run_program(module, arguments, policy, &mut host);
    let flushed = host.output.flush();
    // Release the streams before anything is reported on them.
    drop(host);
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

fn batch(module: &Module, policy: Policy) -> Result<Json, Json> {
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
                Some((function, arguments)) => {
                    case(module, function, &arguments, policy).unwrap_or_else(|rejection| rejection)
                }
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
    let module = load(&request.object);
    let outcome = match (&request.mode, module) {
        (Mode::Program { arguments }, module) => {
            let status = module
                .map_err(|rejection| (rejection, STATUS_NOT_COMPLETED))
                .and_then(|module| program(&module, arguments, request.policy));
            return ExitCode::from(status.unwrap_or_else(|(report, status)| {
                eprintln!("{report}");
                status
            }));
        }
        (_, Err(rejection)) => Err(rejection),
        (Mode::Single { entry, arguments }, Ok(module)) => {
            case(&module, *entry, arguments, request.policy)
        }
        (Mode::Batch, Ok(module)) => batch(&module, request.policy),
    };
    let (report, status) = match outcome {
        Ok(report) => (report, 0),
        Err(rejection) => (rejection, 1),
    };
    println!("{report}");
    ExitCode::from(status)
}
