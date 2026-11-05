//! Standalone cross-codec probe. This is not a runtime execution tool.
#[path = "../../src/smir/portable/mod.rs"]
mod framing;

fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        std::process::exit(3);
    };
    let Ok(bytes) = std::fs::read(path) else {
        std::process::exit(3);
    };
    match framing::decode(&bytes, framing::DecodeLimits::default()) {
        Ok(module) => {
            let kind = match module.kind {
                framing::ModuleKind::Object => 1,
                framing::ModuleKind::Image => 2,
            };
            println!(
                "OK {kind} {}",
                module.entry_function.unwrap_or(framing::NO_ENTRY)
            );
            for section in module.sections {
                print!("{} {} ", section.kind, u8::from(section.required));
                for byte in section.bytes {
                    print!("{byte:02x}");
                }
                println!();
            }
        }
        Err(error) => {
            println!("{}", error.code());
            std::process::exit(2);
        }
    }
}
