//! CPU power requests published by firmware emulation and consumed by the VMM.

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuPowerRequest {
    Start {
        cpu_id: u32,
        entry: u64,
        context: u64,
        pstate: u64,
    },
    Off {
        cpu_id: u32,
    },
}
