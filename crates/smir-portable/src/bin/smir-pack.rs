//! Wrap a portable payload in a native file, and find the payload of one.
//!
//! ```text
//! smir-pack PAYLOAD --carrier elf|macho|pe [--machine x86-64|aarch64] -o FILE
//! smir-pack --extract CARRIER -o FILE
//! smir-pack --show CARRIER
//! ```
//!
//! The first form writes a file of the given native format that carries
//! PAYLOAD: headers that say where it is and what its SHA-256 is, and no
//! code. The machine defaults to the one this program runs on. The payload is
//! verified first, as a runtime verifies it before it runs anything: what is
//! wrapped is a portable object this runtime can run, not just bytes.
//!
//! `--extract` writes the payload of a carrier, and `--show` prints where it
//! is as one line of JSON. Both check what a runtime checks when it is given
//! the file: one locator where the format puts it, a payload the system's
//! loader would map for reading only, and the digest.
//!
//! Exit status: 0 on success, 1 when the payload or the carrier is refused,
//! 2 for a usage error.

use rax_smir_portable::carrier::{self, Carrier, Machine};
use rax_smir_portable::ir::Module;
use rax_smir_portable::{Error, Limits};
use serde_json::json;
use std::process::ExitCode;

const USAGE: &str = "usage: smir-pack PAYLOAD --carrier elf|macho|pe [--machine x86-64|aarch64] -o FILE\n       \
smir-pack --extract CARRIER -o FILE\n       \
smir-pack --show CARRIER";

/// What verifying a payload may cost: as for the runner.
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

enum Request {
    Wrap {
        payload: String,
        carrier: Carrier,
        machine: Machine,
        output: String,
    },
    Extract {
        file: String,
        output: String,
    },
    Show {
        file: String,
    },
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let (mut input, mut output, mut carrier, mut machine) = (None, None, None, None);
    let (mut extract, mut show) = (false, false);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--extract" => extract = true,
            "--show" => show = true,
            "-o" => output = Some(args.next()?),
            "--carrier" => {
                carrier = Some(match args.next()?.as_str() {
                    "elf" => Carrier::Elf,
                    "macho" => Carrier::MachO,
                    "pe" => Carrier::Pe,
                    _ => return None,
                });
            }
            "--machine" => {
                machine = Some(match args.next()?.as_str() {
                    "x86-64" => Machine::X86_64,
                    "aarch64" => Machine::Aarch64,
                    _ => return None,
                });
            }
            _ if arg.starts_with('-') || input.is_some() => return None,
            _ => input = Some(arg),
        }
    }
    let input = input?;
    match (extract, show, carrier, output) {
        (true, false, None, Some(output)) if machine.is_none() => Some(Request::Extract {
            file: input,
            output,
        }),
        (false, true, None, None) if machine.is_none() => Some(Request::Show { file: input }),
        (false, false, Some(carrier), Some(output)) => Some(Request::Wrap {
            payload: input,
            carrier,
            machine: machine.unwrap_or(if cfg!(target_arch = "x86_64") {
                Machine::X86_64
            } else {
                Machine::Aarch64
            }),
            output,
        }),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What went wrong, as the line of JSON that is printed.
fn refusal(diagnostic: &Error) -> String {
    json!({"status": "rejected", "class": diagnostic.class().as_str(), "code": diagnostic.code(),
           "detail": diagnostic.context()})
    .to_string()
}

fn io(code: &str, name: &str, failure: &std::io::Error) -> String {
    json!({"status": "rejected", "class": "io", "code": code, "detail": format!("{name}: {failure}")})
        .to_string()
}

fn perform(request: &Request) -> Result<Option<String>, String> {
    let read = |name: &String| std::fs::read(name).map_err(|failure| io("READ", name, &failure));
    let write = |name: &String, bytes: &[u8]| {
        std::fs::write(name, bytes).map_err(|failure| io("WRITE", name, &failure))
    };
    match request {
        Request::Wrap {
            payload,
            carrier,
            machine,
            output,
        } => {
            let bytes = read(payload)?;
            Module::load(&bytes, LIMITS).map_err(|diagnostic| refusal(&diagnostic))?;
            write(output, &carrier::wrap(&bytes, *carrier, *machine))?;
            Ok(None)
        }
        Request::Extract { file, output } => {
            let bytes = read(file)?;
            let found = found(&bytes)?;
            write(output, found.payload)?;
            Ok(None)
        }
        Request::Show { file } => {
            let bytes = read(file)?;
            let found = found(&bytes)?;
            Ok(Some(
                json!({
                    "carrier": match found.carrier {
                        Carrier::Elf => "elf",
                        Carrier::MachO => "macho",
                        Carrier::Pe => "pe",
                    },
                    "machine": match found.machine {
                        Machine::X86_64 => "x86-64",
                        Machine::Aarch64 => "aarch64",
                    },
                    "offset": found.offset,
                    "length": found.payload.len(),
                    "sha256": hex(&found.sha256),
                })
                .to_string(),
            ))
        }
    }
}

/// The payload of a file that must be a carrier.
fn found(file: &[u8]) -> Result<carrier::Found<'_>, String> {
    let Some(kind) = carrier::kind(file) else {
        return Err(
            json!({"status": "rejected", "class": "framing", "code": "CARRIER_KIND",
                   "detail": "the file is no ELF, Mach-O or PE file"})
            .to_string(),
        );
    };
    carrier::find(file, kind).map_err(|diagnostic| refusal(&diagnostic))
}

fn main() -> ExitCode {
    let Some(request) = parse(std::env::args().skip(1)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match perform(&request) {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(line)) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(line) => {
            println!("{line}");
            ExitCode::from(1)
        }
    }
}
