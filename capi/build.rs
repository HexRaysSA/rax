// Keep native shared-library identities independent of Cargo's build directory.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => {
            println!("cargo:rustc-link-arg-cdylib=-Wl,-install_name,@rpath/librax.dylib");
        }
        Ok("linux") => {
            println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,librax.so");
        }
        _ => {}
    }
}
