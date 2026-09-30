//! Strict and bounded process-open configuration, before any worker is started.
use super::*;
use rax_engine::user::{darwin::DarwinConfig, linux::LinuxConfig, windows::WindowsConfig};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const MAX_IMAGE: usize = 64 << 20;
pub(super) const MAX_IMAGES: usize = 64;
pub(super) const MAX_TOTAL_IMAGES: usize = 256 << 20;
pub(super) const MAX_OPTIONS: usize = 64 << 10;
pub(super) const MAX_TRANSFER: usize = 16 << 20;
pub(super) const MAX_INFO: usize = 4 << 20;

fn number(v: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match v.get(key) {
        None => default,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| bad(format!("{key} must be an unsigned integer")))?,
    };
    if !(min..=max).contains(&value) {
        return Err(bad(format!("{key} must be in [{min}, {max}]")));
    }
    Ok(value)
}

fn text(v: &Value, key: &str, default: &str) -> Result<String> {
    let value = match v.get(key) {
        None => default,
        Some(v) => v
            .as_str()
            .ok_or_else(|| bad(format!("{key} must be a string")))?,
    };
    if value.len() > 4096 || value.contains('\0') {
        return Err(bad(format!("invalid {key} string")));
    }
    Ok(value.to_owned())
}

pub(super) enum Config {
    Windows(WindowsConfig),
    Linux(LinuxConfig),
    Darwin(DarwinConfig),
}
impl Config {
    pub(super) fn supply(&mut self, files: BTreeMap<String, Arc<[u8]>>) -> Result<()> {
        match self {
            Self::Windows(c) => c.supplied_dlls = files,
            Self::Darwin(c) => {
                c.supplied_files = Some(
                    rax_engine::user::supplied_fs::Files::new(files)
                        .map_err(|e| bad(e.to_string()))?,
                );
            }
            Self::Linux(c) => {
                c.supplied_files = Some(
                    rax_engine::user::supplied_fs::Files::new(files)
                        .map_err(|e| bad(e.to_string()))?,
                )
            }
        }
        Ok(())
    }
}

pub(super) fn config(bytes: &[u8]) -> Result<Config> {
    let value: Value = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(bytes).map_err(|e| bad(format!("invalid process options: {e}")))?
    };
    let object = value
        .as_object()
        .ok_or_else(|| bad("process options must be an object"))?;
    const FIELDS: &[&str] = &[
        "personality",
        "architecture",
        "guest_path",
        "arguments",
        "environment",
        "current_directory",
        "memory_bytes",
        "slice_instructions",
        "console_capacity",
        "seed",
    ];
    for key in object.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(bad(format!("unknown process option {key}")));
        }
    }
    let personality = text(&value, "personality", "windows")?;
    if !matches!(personality.as_str(), "windows" | "linux" | "darwin") {
        return Err(Failure(
            RaxStatus::Unsupported,
            "process personality must be windows, linux, or darwin".into(),
        ));
    }
    let darwin_abi = if object.contains_key("architecture") {
        if personality != "darwin" {
            return Err(bad(
                "architecture selection is only available for Darwin Mach-O images",
            ));
        }
        Some(match text(&value, "architecture", "")?.as_str() {
            "x86_64" => rax_engine::user::darwin::abi::DarwinAbi::X86_64,
            "aarch64" => rax_engine::user::darwin::abi::DarwinAbi::Arm64,
            _ => return Err(bad("Darwin architecture must be x86_64 or aarch64")),
        })
    } else {
        None
    };
    let mut arguments = Vec::new();
    if let Some(array) = value.get("arguments") {
        let array = array
            .as_array()
            .ok_or_else(|| bad("arguments must be an array"))?;
        if array.len() > 256 {
            return Err(bad("at most 256 arguments are accepted"));
        }
        for argument in array {
            let argument = argument
                .as_str()
                .ok_or_else(|| bad("each argument must be a string"))?;
            if argument.len() > 4096 || argument.contains('\0') {
                return Err(bad("invalid argument string"));
            }
            arguments.push(argument.to_owned());
        }
    }
    let capacity = number(&value, "console_capacity", 1 << 20, 0, MAX_TRANSFER as u64)? as usize;
    let guest_path = text(
        &value,
        "guest_path",
        if personality != "windows" {
            "/program"
        } else {
            "C:\\program.exe"
        },
    )?;
    let cwd = text(
        &value,
        "current_directory",
        if personality != "windows" {
            "/"
        } else {
            "C:\\"
        },
    )?;
    let memory = number(&value, "memory_bytes", 128 << 20, 8 << 20, 1 << 30)?;
    if memory % 4096 != 0 {
        return Err(bad("memory_bytes must be a multiple of 4096 bytes"));
    }
    let slice = number(&value, "slice_instructions", 4096, 1, 65_536)?;
    let seed = Some(number(&value, "seed", 0, 0, u64::MAX)?);
    let mut pairs = Vec::new();
    if let Some(environment) = value.get("environment") {
        let environment = environment
            .as_object()
            .ok_or_else(|| bad("environment must be an object of string values"))?;
        if environment.len() > 256 {
            return Err(bad("at most 256 environment variables are accepted"));
        }
        for (key, value) in environment {
            let value = value
                .as_str()
                .ok_or_else(|| bad("environment values must be strings"))?;
            if key.is_empty()
                || key.contains(['\0', '='])
                || value.contains('\0')
                || key.len() > 4096
                || value.len() > 4096
            {
                return Err(bad("invalid environment entry"));
            }
            pairs.push((key.clone(), value.to_owned()));
        }
    }
    if personality != "windows" {
        let mut argv = vec![guest_path.as_bytes().to_vec()];
        argv.extend(arguments.into_iter().map(String::into_bytes));
        let envp = pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}").into_bytes())
            .collect();
        if personality == "darwin" {
            let console = rax_engine::user::console::CapturedConsole::new(Vec::new(), capacity)
                .map_err(|e| bad(e.to_string()))?;
            let files = rax_engine::user::supplied_fs::Files::new(BTreeMap::new())
                .map_err(|e| bad(e.to_string()))?;
            let mut cfg = DarwinConfig::embedded(guest_path, argv, envp, files, console);
            cfg.abi = darwin_abi;
            cfg.cwd = cwd;
            cfg.arena_bytes = memory;
            cfg.slice_insns = slice;
            cfg.seed = seed;
            return Ok(Config::Darwin(cfg));
        }
        let mut cfg = LinuxConfig::embedded(guest_path, argv, envp, Vec::new(), capacity)
            .map_err(|e| bad(e.to_string()))?;
        cfg.cwd = cwd;
        cfg.arena_bytes = memory;
        cfg.slice_insns = slice;
        cfg.seed = seed;
        rax_engine::user::linux::embedding::validate(&cfg).map_err(|e| bad(e.to_string()))?;
        Ok(Config::Linux(cfg))
    } else {
        let mut cfg = WindowsConfig::embedded(guest_path, arguments, Vec::new(), capacity)
            .map_err(|e| bad(e.to_string()))?;
        cfg.cwd = Some(cwd);
        cfg.arena_bytes = memory;
        cfg.slice_insns = slice;
        cfg.seed = seed;
        if value.get("environment").is_some() {
            cfg.env = Some(pairs);
        }
        Ok(Config::Windows(cfg))
    }
}
