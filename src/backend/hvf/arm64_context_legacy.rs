//! Explicit V4 native-read migration: its PC was already advanced at trap.
use super::{Context, Controls, LIMIT, PendingRead, PendingWrite, Profile, Register, Sme, invalid};
use crate::error::Result;
use crate::vm::vcpu::Aarch64CpuState;
use serde::Deserialize;

#[derive(Deserialize)]
struct ReadV4 {
    address: u64,
    register: u32,
    size: u8,
    sign_extend: bool,
    sixty_four: bool,
}

#[derive(Deserialize)]
struct ContextV4 {
    id: u32,
    profile: Profile,
    public: Aarch64CpuState,
    system: Vec<Register>,
    gic_cpu: Vec<Register>,
    running_priority: u64,
    controls: Controls,
    sme: Sme,
    shutdown: bool,
    pending_read: Option<ReadV4>,
    pending_write: Option<PendingWrite>,
    pending_reply: Option<Vec<u8>>,
    completion_error: Option<String>,
}

pub(super) fn decode(raw: &[u8]) -> Result<Context> {
    let old: ContextV4 = crate::codec::deserialize_limited::<_, LIMIT>(raw).map_err(invalid)?;
    Ok(Context {
        id: old.id,
        profile: old.profile,
        public: old.public,
        system: old.system,
        gic_cpu: old.gic_cpu,
        running_priority: old.running_priority,
        controls: old.controls,
        sme: old.sme,
        shutdown: old.shutdown,
        pending_read: old.pending_read.map(|read| PendingRead {
            address: read.address,
            register: read.register,
            size: read.size,
            sign_extend: read.sign_extend,
            sixty_four: read.sixty_four,
            retire_pc: None,
        }),
        pending_write: old.pending_write,
        pending_reply: old.pending_reply,
        completion_error: old.completion_error,
    })
}
