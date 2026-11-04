pub use rax::{error, vm};
#[path = "identity.rs"]
pub(crate) mod actual_identity;
mod codec;
mod isa {
    pub(crate) mod x86_64 {
        pub(crate) use crate::actual_identity as identity;
    }
}
mod backend;
fn main() {
    backend::kvm::checkpoint::probe();
}
