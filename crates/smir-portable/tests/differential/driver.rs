use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROCESS_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const PREPARED_LIMIT: usize = 32 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct Case {
    pub(crate) id: String,
    pub(crate) path: PathBuf,
    pub(crate) scope: String,
    pub(crate) expectation: String,
    pub(crate) document: Value,
}

pub(crate) struct Harness {
    pub(crate) root: PathBuf,
    pub(crate) cases: Vec<Case>,
    pub(crate) prepared: Value,
    pub(crate) scratch: PathBuf,
    cli: PathBuf,
    cli_hash: String,
    python: String,
    frozen: Value,
    frozen_inputs: Value,
    development: bool,
}

pub(crate) struct Captured {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("oracle report has no text field {key}: {value}"))
}

fn hash(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

fn read_limited(mut source: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    source
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > limit {
        return Err(format!("child output exceeded {limit} B"));
    }
    Ok(data)
}

fn capture(command: &mut Command) -> Result<Captured, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("{command:?}: {error}"))?;
    let stdout = child.stdout.take().ok_or("missing child stdout")?;
    let stderr = child.stderr.take().ok_or("missing child stderr")?;
    // Drain both pipes concurrently; waiting before reading can deadlock on a full pipe.
    let out = thread::spawn(move || read_limited(stdout, PROCESS_OUTPUT_LIMIT));
    let err = thread::spawn(move || read_limited(stderr, PROCESS_OUTPUT_LIMIT));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if start.elapsed() >= PROCESS_TIMEOUT {
            let _ = child.kill(); // Only the exact child created above is terminated.
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            return Err(format!("own oracle child timed out: {command:?}"));
        }
        thread::sleep(Duration::from_millis(5));
    };
    Ok(Captured {
        status,
        stdout: out.join().map_err(|_| "stdout reader panicked")??,
        stderr: err.join().map_err(|_| "stderr reader panicked")??,
    })
}

impl Harness {
    fn new() -> Result<Self, String> {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .parent()
            .and_then(Path::parent)
            .ok_or("standalone crate is not under repository crates/")?
            .to_path_buf();
        let parent = std::env::var_os("SMIR_DIFF_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let scratch = parent.join(format!("smir-differential-{}-{nonce}", std::process::id()));
        // Oracle prepare creates this fresh directory atomically; never reuse an existing run.
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
        let mode = std::env::var("SMIR_DIFFERENTIAL_MODE").unwrap_or_else(|_| "frozen".into());
        if !["frozen", "development"].contains(&mode.as_str()) {
            return Err("SMIR_DIFFERENTIAL_MODE must be frozen or development".into());
        }
        let development = mode == "development";
        let mut prepare = Command::new(&python);
        prepare
            .arg("-B")
            .arg(manifest.join("tests/differential/oracle.py"))
            .arg("prepare")
            .arg("--output")
            .arg(&scratch)
            .env("PYTHONDONTWRITEBYTECODE", "1");
        if development {
            prepare.arg("--development");
        }
        let result = capture(&mut prepare)?;
        if !result.status.success() {
            return Err(format!(
                "independent oracle setup failed: {}",
                String::from_utf8_lossy(&result.stderr)
            ));
        }
        let source =
            fs::File::open(scratch.join("prepared.json")).map_err(|error| error.to_string())?;
        let prepared: Value = serde_json::from_slice(&read_limited(source, PREPARED_LIMIT)?)
            .map_err(|error| error.to_string())?;
        if text(&prepared, "protocol") != "smir-diff-v1" {
            return Err("unknown prepared corpus protocol".into());
        }
        let mut names = BTreeSet::new();
        let mut cases = Vec::new();
        for row in prepared["cases"].as_array().ok_or("missing actual cases")? {
            let id = text(row, "id").to_owned();
            if !names.insert(id.clone()) {
                return Err(format!("duplicate case identity {id}"));
            }
            let path = PathBuf::from(text(row, "path"));
            if !path.starts_with(&scratch) || hash(&path)? != text(row, "sha256") {
                return Err(format!("prepared source bytes changed: {id}"));
            }
            cases.push(Case {
                id,
                path,
                scope: text(row, "oracle_scope").to_owned(),
                expectation: text(row, "static_expectation").to_owned(),
                document: row.clone(),
            });
        }
        if cases.is_empty() {
            return Err("empty differential corpus".into());
        }
        let manifest_name = if development {
            "development-manifest.json"
        } else {
            "manifest.json"
        };
        let frozen: Value = serde_json::from_slice(
            &fs::read(manifest.join("conformance/differential").join(manifest_name))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let frozen_inputs: Value = if development {
            if prepared["mode"] != "development"
                || frozen["mode"] != "development"
                || frozen["full_p2_qualified"] != false
                || frozen["compiler_freeze_passed"] != false
            {
                return Err("development harness cannot assert frozen qualification".into());
            }
            prepared["inputs"].clone()
        } else {
            let pin = &frozen["frozen_inputs_manifest"];
            let pin_path = manifest.join("conformance/differential").join(text(pin, "path"));
            if hash(&pin_path)? != text(pin, "sha256") {
                return Err("frozen input inventory checksum changed".into());
            }
            serde_json::from_slice(&fs::read(&pin_path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?
        };
        let cli = PathBuf::from(
            option_env!("CARGO_BIN_EXE_smir-inspect")
                .ok_or("root must register the actual smir-inspect binary")?,
        );
        let cli_hash = hash(&cli)?;
        let harness = Self {
            root,
            cases,
            prepared,
            scratch,
            cli,
            cli_hash,
            python,
            frozen,
            frozen_inputs,
            development,
        };
        harness.assert_inputs_stable();
        let run = serde_json::json!({
            "scope": "Static/wire differential tests, no guest execution",
            "mode": mode,
            "compiler_freeze_passed": false,
            "full_p2_qualified": false,
            "candidate_sha256": harness.frozen["candidate_sha256"],
            "rust_cli": {"path": harness.cli, "sha256": harness.cli_hash},
            "test_executable": std::env::current_exe().ok(),
            "test_argv": std::env::args().collect::<Vec<_>>(),
            "cases": harness.cases.len(),
            "python_executable": harness.python,
            "independent_cpp": harness.prepared["cpp"],
            "prepared_inputs": harness.prepared["inputs"],
            "admission": false,
        });
        fs::write(
            harness.scratch.join("run.json"),
            serde_json::to_vec_pretty(&run).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        eprintln!(
            "Differential run artifacts retained at {}",
            harness.scratch.display()
        );
        Ok(harness)
    }

    pub(crate) fn cli(&self, operation: &str, case: &Case) -> (Captured, Value) {
        let result = capture(Command::new(&self.cli).arg(operation).arg(&case.path))
            .unwrap_or_else(|error| panic!("{}: {error}", case.id));
        let report = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
            panic!(
                "{}: invalid actual CLI JSON ({error}): stdout={} stderr={}",
                case.id,
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            )
        });
        (result, report)
    }

    pub(crate) fn reference(&self, case: &Case) -> Value {
        let mut command = Command::new(&self.python);
        command
            .arg("-B")
            .arg(
                self.root
                    .join("crates/smir-portable/tests/differential/oracle.py"),
            )
            .arg(if case.document["reference_adapter"] == "source-declarations-v1" {
                assert!(self.development, "source declaration adapter requires an explicit development run");
                assert_eq!(case.scope, "static-local");
                "verify-source-declarations"
            } else if case.scope == "static-local" {
                "verify-static-reference"
            } else {
                "verify-reference"
            })
            .arg(&case.path)
            .env("PYTHONDONTWRITEBYTECODE", "1");
        let result = capture(&mut command).unwrap_or_else(|error| panic!("{}: {error}", case.id));
        assert!(
            result.status.success(),
            "{}: independent reference crashed: {}",
            case.id,
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        for input in report["inputs"]
            .as_array()
            .expect("reference must report actual imported sources")
        {
            if self.development {
                assert!(
                    self.frozen_inputs.as_array().unwrap().iter().any(|before|
                        before["path"] == input["path"] && before["sha256"] == input["sha256"]),
                    "actual reference consumed an unwatched or changed input: {input}"
                );
            }
            assert_eq!(
                hash(&self.root.join(text(input, "path"))).unwrap(),
                text(input, "sha256")
            );
        }
        report
    }

    pub(crate) fn cpp(&self, case: &Case, section: &Value) -> Value {
        let mut command = Command::new(text(&self.prepared["cpp"], "path"));
        command
            .arg("--record")
            .arg(text(section, "record_type"))
            .arg(text(section, "path"));
        let result = capture(&mut command).unwrap_or_else(|error| panic!("{}: {error}", case.id));
        assert!(
            result.status.success(),
            "{}: C++ record oracle failed: {} {}",
            case.id,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).expect("actual C++ record JSON")
    }

    pub(crate) fn reviewed_diagnostic(&self, case: &Case, code: &str, reference: bool) -> bool {
        if ["INCOMPLETE", "UNIMPLEMENTED", "STUB", "TODO"]
            .iter()
            .any(|word| code.contains(word))
        {
            return false;
        }
        let table = if reference {
            "reference_diagnostics"
        } else {
            "diagnostics"
        };
        self.frozen[table][&case.id]
            .as_array()
            .is_some_and(|allowed| allowed.iter().any(|value| value.as_str() == Some(code)))
    }

    pub(crate) fn assert_inputs_stable(&self) {
        assert_eq!(
            hash(&self.cli).unwrap(),
            self.cli_hash,
            "actual Rust CLI binary changed"
        );
        for row in self.prepared["inputs"]
            .as_array()
            .expect("actual oracle inputs")
        {
            assert_eq!(
                hash(&self.root.join(text(row, "path"))).unwrap(),
                text(row, "sha256")
            );
        }
        for row in self
            .frozen_inputs
            .as_array()
            .expect("all frozen candidate inputs")
        {
            assert_eq!(
                hash(&self.root.join(text(row, "path"))).unwrap(),
                text(row, "sha256"),
                "guarded compiler input changed: {}",
                text(row, "path")
            );
        }
        assert_eq!(
            hash(Path::new(text(&self.prepared["cpp"], "path"))).unwrap(),
            text(&self.prepared["cpp"], "sha256")
        );
    }
}

pub(crate) fn harness() -> &'static Harness {
    static INSTANCE: OnceLock<Result<Harness, String>> = OnceLock::new();
    INSTANCE
        .get_or_init(Harness::new)
        .as_ref()
        .unwrap_or_else(|error| panic!("differential setup FAILED (never skipped): {error}"))
}

/// Standalone CLI checks do not need a prepared semantic corpus or a frozen pin.
pub(crate) fn inspect(operation: &str, path: &Path) -> (Captured, Value) {
    let cli = PathBuf::from(
        option_env!("CARGO_BIN_EXE_smir-inspect")
            .expect("Cargo must provide the actual smir-inspect executable"),
    );
    let before = hash(&cli).expect("actual CLI hash");
    let process = capture(Command::new(&cli).arg(operation).arg(path))
        .unwrap_or_else(|error| panic!("actual CLI check: {error}"));
    assert_eq!(hash(&cli).unwrap(), before, "actual CLI changed during inspection");
    let report = serde_json::from_slice(&process.stdout).unwrap_or_else(|error|
        panic!("actual CLI JSON: {error}; stderr={}", String::from_utf8_lossy(&process.stderr)));
    (process, report)
}
