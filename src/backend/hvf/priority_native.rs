//! SDK access and model binding for the portable priority publication policy.
use super::{bindings::*, convert::*, priority};
use crate::devices::lapic::priority::{PriorityHandle, TaskPriority};

pub(super) type State = priority::State<PriorityHandle>;
impl priority::Register for PriorityHandle {
    fn load(&self) -> u32 {
        PriorityHandle::load(self)
    }
    fn store(&self, value: u32) {
        PriorityHandle::store(self, value);
    }
}
pub(super) fn new() -> State {
    State::new(TaskPriority::new(0).handle())
}
pub(super) struct Host(pub hv_vcpuid_t);
impl priority::Host for Host {
    fn read_tpr(&mut self) -> Result<u64, String> {
        read_register(self.0, hv_x86_reg_t::HV_X86_TPR).map_err(|e| e.to_string())
    }
    fn write_tpr(&mut self, value: u64) -> Result<(), String> {
        write_register(self.0, hv_x86_reg_t::HV_X86_TPR, value).map_err(|e| e.to_string())
    }
}
