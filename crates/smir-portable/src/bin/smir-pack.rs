//! Wrap a portable payload in a native file, and find the payload of one.
//!
//! ```text
//! smir-pack PAYLOAD --carrier elf|macho|pe [--machine x86-64|aarch64] -o FILE
//! smir-pack --extract CARRIER -o FILE
//! smir-pack --show CARRIER
//! smir-pack PAYLOAD --section [--library FILE]... -o FILE
//! smir-pack --seal CARRIER
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
//! The last two are for a carrier that a native linker makes, such as an
//! executable that has its runtime in it. `--section` writes what the linker
//! is given as the section that carries the payload: the payload behind a
//! locator that does not yet say where the payload is. What goes into an
//! executable must be a program: a payload that calls functions of other
//! modules is refused, unless each `--library` names one of them, an object
//! or a carrier, and they link; the section is the payload's all the same,
//! and the libraries go into the executable by other means. `--seal`
//! completes the locator in the linked file, in place, and checks that the
//! payload is then found.
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
smir-pack --show CARRIER\n       \
smir-pack PAYLOAD --section [--library FILE]... -o FILE\n       \
smir-pack --seal CARRIER";

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
    Section {
        payload: String,
        libraries: Vec<String>,
        output: String,
    },
    Seal {
        file: String,
    },
}

fn parse(mut args: impl Iterator<Item = String>) -> Option<Request> {
    let (mut input, mut output, mut carrier, mut machine) = (None, None, None, None);
    let (mut extract, mut show, mut section, mut seal) = (false, false, false, false);
    let mut libraries = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--library" => libraries.push(args.next()?),
            "--extract" => extract = true,
            "--show" => show = true,
            "--section" => section = true,
            "--seal" => seal = true,
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
    // Libraries are for a section only.
    if !section && !libraries.is_empty() {
        return None;
    }
    if section || seal {
        return match (
            section,
            seal,
            extract || show || carrier.is_some() || machine.is_some(),
            output,
        ) {
            (true, false, false, Some(output)) => Some(Request::Section {
                payload: input,
                libraries,
                output,
            }),
            (false, true, false, None) => Some(Request::Seal { file: input }),
            _ => None,
        };
    }
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
        Request::Section {
            payload,
            libraries,
            output,
        } => {
            let bytes = read(payload)?;
            let module = Module::load(&bytes, LIMITS).map_err(|diagnostic| refusal(&diagnostic))?;
            // What the executable will hold must be a program.
            if libraries.is_empty() && module.needs_linking() {
                return Err(
                    json!({"status": "rejected", "class": "semantic", "code": "EXEC_UNLINKED",
                                  "detail": "the module calls functions of other modules"})
                    .to_string(),
                );
            }
            if !libraries.is_empty() {
                let mut modules = vec![module];
                for library in libraries {
                    let file = read(library)?;
                    let object =
                        carrier::payload(&file).map_err(|diagnostic| refusal(&diagnostic))?;
                    modules.push(
                        Module::load(object, LIMITS).map_err(|diagnostic| refusal(&diagnostic))?,
                    );
                }
                Module::link(modules).map_err(|diagnostic| refusal(&diagnostic))?;
            }
            write(output, &carrier::section(&bytes))?;
            Ok(None)
        }
        Request::Seal { file } => {
            let mut bytes = read(file)?;
            let kind = carrier::kind(&bytes).ok_or_else(not_a_carrier)?;
            carrier::seal(&mut bytes, kind).map_err(|diagnostic| refusal(&diagnostic))?;
            // Only a file whose payload is then found is written back.
            carrier::find(&bytes, kind).map_err(|diagnostic| refusal(&diagnostic))?;
            write(file, &bytes)?;
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
    let kind = carrier::kind(file).ok_or_else(not_a_carrier)?;
    carrier::find(file, kind).map_err(|diagnostic| refusal(&diagnostic))
}

fn not_a_carrier() -> String {
    json!({"status": "rejected", "class": "framing", "code": "CARRIER_KIND",
           "detail": "the file is no ELF, Mach-O or PE file"})
    .to_string()
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
