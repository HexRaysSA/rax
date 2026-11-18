//! Objects carried by native files: `smir-pack` wraps one, and `smir-run`
//! runs what a carrier holds as it runs the object itself.

use super::crate_dir;
use serde_json::Value as Json;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "smir-packing-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn file(&self, name: &str) -> String {
        self.0.join(name).to_str().expect("a path").to_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pack(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_smir-pack"))
        .args(arguments)
        .output()
        .expect("start smir-pack")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .args(arguments)
        .output()
        .expect("start smir-run")
}

fn object() -> String {
    crate_dir()
        .join("tests/interp/programs/services.smo")
        .to_str()
        .expect("a path")
        .to_owned()
}

fn json(output: &Output) -> Json {
    serde_json::from_slice(&output.stdout).expect("one line of JSON")
}

#[test]
fn a_program_runs_from_a_carrier_as_it_runs_from_its_object() {
    let scratch = Scratch::new();
    let program = ["--program", "--", "carried"];
    let direct = run(&[&[object().as_str()], &program[..]].concat());
    assert_eq!(direct.stdout, b"carri");
    for carrier in ["elf", "macho", "pe"] {
        for machine in ["x86-64", "aarch64"] {
            let file = scratch.file(&format!("{carrier}-{machine}"));
            let packed = pack(&[
                &object(),
                "--carrier",
                carrier,
                "--machine",
                machine,
                "-o",
                &file,
            ]);
            assert!(
                packed.status.success(),
                "{}",
                String::from_utf8_lossy(&packed.stdout)
            );
            // The carrier's machine is that of the code it would hold, and
            // it holds none: any runtime runs what it carries.
            for engine in [&[][..], &["--native"][..]] {
                let carried = run(&[&[file.as_str()], engine, &program[..]].concat());
                assert_eq!(
                    (carried.status.code(), &carried.stdout, &carried.stderr),
                    (direct.status.code(), &direct.stdout, &direct.stderr),
                    "{carrier} {machine}"
                );
            }
            let shown = json(&pack(&["--show", &file]));
            assert_eq!(
                (shown["carrier"].as_str(), shown["machine"].as_str()),
                (Some(carrier), Some(machine))
            );
            let payload = std::fs::read(object()).unwrap();
            assert_eq!(shown["length"], payload.len());
            // What is taken out again is the object, byte for byte.
            let extracted = scratch.file("extracted");
            assert!(
                pack(&["--extract", &file, "-o", &extracted])
                    .status
                    .success()
            );
            assert_eq!(std::fs::read(&extracted).unwrap(), payload);
        }
    }
}

#[test]
fn a_carrier_that_was_changed_is_not_run() {
    let scratch = Scratch::new();
    let file = scratch.file("carrier");
    assert!(
        pack(&[&object(), "--carrier", "elf", "-o", &file])
            .status
            .success()
    );
    let mut bytes = std::fs::read(&file).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&file, &bytes).unwrap();
    let refused = run(&[&file, "--program"]);
    assert_eq!(refused.status.code(), Some(125));
    assert!(refused.stdout.is_empty());
    let report: Json = serde_json::from_slice(&refused.stderr).expect("a report");
    assert_eq!(
        (report["status"].as_str(), report["code"].as_str()),
        (Some("rejected"), Some("LOCATOR_HASH"))
    );
    let shown = pack(&["--show", &file]);
    assert_eq!(
        (shown.status.code(), json(&shown)["code"].as_str()),
        (Some(1), Some("LOCATOR_HASH"))
    );
}

#[test]
fn a_section_for_a_linker_is_sealed_in_the_linked_file() {
    let scratch = Scratch::new();
    let payload = std::fs::read(object()).unwrap();
    let section = scratch.file("section");
    assert!(
        pack(&[&object(), "--section", "-o", &section])
            .status
            .success()
    );
    // The locator, which has the length and not yet the place, and then
    // the object.
    let content = std::fs::read(&section).unwrap();
    assert_eq!(&content[..8], b"RAXSMIR\0");
    assert_eq!(content[16..24], [0; 8]);
    assert_eq!(content[24..32], (payload.len() as u64).to_le_bytes());
    assert_eq!(&content[64..], &payload[..]);
    // A linked file is one whose headers name the section; a wrapped
    // carrier has the same shape. With the place taken out of its locator
    // it carries nothing, and sealed it carries the object again.
    for carrier in ["macho", "pe"] {
        let file = scratch.file(carrier);
        assert!(
            pack(&[&object(), "--carrier", carrier, "-o", &file])
                .status
                .success()
        );
        let whole = std::fs::read(&file).unwrap();
        let at = whole.len() - payload.len() - 64;
        let mut unsealed = whole.clone();
        unsealed[at + 16..at + 24].fill(0);
        std::fs::write(&file, &unsealed).unwrap();
        assert_eq!(pack(&["--show", &file]).status.code(), Some(1));
        assert!(pack(&["--seal", &file]).status.success());
        assert_eq!(std::fs::read(&file).unwrap(), whole);
        // A file whose payload is not found once sealed is left as it was.
        let mut broken = unsealed.clone();
        *broken.last_mut().unwrap() ^= 1;
        std::fs::write(&file, &broken).unwrap();
        let refused = pack(&["--seal", &file]);
        assert_eq!(
            (refused.status.code(), json(&refused)["code"].as_str()),
            (Some(1), Some("LOCATOR_HASH"))
        );
        assert_eq!(std::fs::read(&file).unwrap(), broken);
    }
    // An ELF file's locator is in a note; and an object is no carrier.
    let elf = scratch.file("elf");
    assert!(
        pack(&[&object(), "--carrier", "elf", "-o", &elf])
            .status
            .success()
    );
    assert_eq!(json(&pack(&["--seal", &elf]))["code"], "CARRIER_SEAL");
    assert_eq!(json(&pack(&["--seal", &object()]))["code"], "CARRIER_KIND");
    for arguments in [
        &["--seal", elf.as_str(), "-o", section.as_str()][..],
        &[elf.as_str(), "--section"][..],
        &[
            elf.as_str(),
            "--section",
            "--carrier",
            "elf",
            "-o",
            section.as_str(),
        ][..],
    ] {
        assert_eq!(pack(arguments).status.code(), Some(2), "{arguments:?}");
    }
}

#[test]
fn only_an_object_is_wrapped_and_only_a_carrier_unwrapped() {
    let scratch = Scratch::new();
    let (text, file) = (scratch.file("text"), scratch.file("out"));
    std::fs::write(&text, b"not an object").unwrap();
    let wrapped = pack(&[&text, "--carrier", "macho", "-o", &file]);
    assert_eq!(wrapped.status.code(), Some(1));
    assert_eq!(json(&wrapped)["status"], "rejected");
    assert!(!std::path::Path::new(&file).exists());
    // An object is no carrier.
    let shown = pack(&["--show", &object()]);
    assert_eq!(
        (shown.status.code(), json(&shown)["code"].as_str()),
        (Some(1), Some("CARRIER_KIND"))
    );
    // What the tool was not told is a usage error.
    for arguments in [
        &[][..],
        &[text.as_str()][..],
        &[text.as_str(), "--carrier", "coff", "-o", file.as_str()][..],
        &["--extract", text.as_str()][..],
        &["--show", text.as_str(), "-o", file.as_str()][..],
    ] {
        assert_eq!(pack(arguments).status.code(), Some(2), "{arguments:?}");
    }
}
