//! Explicit V4/V5 wire readers: historical output PCs were already advanced.
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
struct ReadV5 {
    address: u64,
    register: u32,
    size: u8,
    sign_extend: bool,
    sixty_four: bool,
    retire_pc: Option<u64>,
}
#[derive(Deserialize)]
struct WriteLegacy {
    address: u64,
    data: Vec<u8>,
}
#[derive(Deserialize)]
struct LegacyContext<R> {
    id: u32,
    profile: Profile,
    public: Aarch64CpuState,
    system: Vec<Register>,
    gic_cpu: Vec<Register>,
    running_priority: u64,
    controls: Controls,
    sme: Sme,
    shutdown: bool,
    pending_read: Option<R>,
    pending_write: Option<WriteLegacy>,
    pending_reply: Option<Vec<u8>>,
    completion_error: Option<String>,
}
impl<R> LegacyContext<R> {
    fn upgrade(self, read: impl FnOnce(R) -> PendingRead) -> Context {
        Context {
            id: self.id,
            profile: self.profile,
            public: self.public,
            system: self.system,
            gic_cpu: self.gic_cpu,
            running_priority: self.running_priority,
            controls: self.controls,
            sme: self.sme,
            shutdown: self.shutdown,
            pending_read: self.pending_read.map(read),
            pending_write: self.pending_write.map(|old| PendingWrite {
                address: old.address,
                data: old.data,
                retirement: None,
            }),
            pending_reply: self.pending_reply,
            completion_error: self.completion_error,
        }
    }
}
pub(super) fn decode_v4(raw: &[u8]) -> Result<Context> {
    let old: LegacyContext<ReadV4> =
        crate::codec::deserialize_limited::<_, LIMIT>(raw).map_err(invalid)?;
    Ok(old.upgrade(|r| PendingRead {
        address: r.address,
        register: r.register,
        size: r.size,
        sign_extend: r.sign_extend,
        sixty_four: r.sixty_four,
        retire_pc: None,
    }))
}
pub(super) fn decode_v5(raw: &[u8]) -> Result<Context> {
    let old: LegacyContext<ReadV5> =
        crate::codec::deserialize_limited::<_, LIMIT>(raw).map_err(invalid)?;
    Ok(old.upgrade(|r| PendingRead {
        address: r.address,
        register: r.register,
        size: r.size,
        sign_extend: r.sign_extend,
        sixty_four: r.sixty_four,
        retire_pc: r.retire_pc,
    }))
}
