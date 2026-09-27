//! The Mach side of a task and its threads (`osfmk/kern/task.h`,
//! `thread.h`): special ports, exception ports, and the bookkeeping the
//! task and thread MIG routines report.

use std::sync::Arc;

use super::ipc::{Port, Right};

/// `EXC_TYPES_COUNT`: exception types 1 ..= 14 index the actions.
pub const EXC_TYPES_COUNT: usize = 15;

/// `TASK_*_PORT` special-port numbers kept per task
/// (`osfmk/mach/task_special_ports.h`).
pub mod special {
    /// `TASK_KERNEL_PORT`.
    pub const KERNEL: i32 = 1;
    /// `TASK_HOST_PORT`.
    pub const HOST: i32 = 2;
    /// `TASK_NAME_PORT`.
    pub const NAME: i32 = 3;
    /// `TASK_BOOTSTRAP_PORT`.
    pub const BOOTSTRAP: i32 = 4;
    /// `TASK_INSPECT_PORT`.
    pub const INSPECT: i32 = 5;
    /// `TASK_READ_PORT`.
    pub const READ: i32 = 6;
    /// `TASK_ACCESS_PORT`.
    pub const ACCESS: i32 = 9;
    /// `TASK_DEBUG_CONTROL_PORT`.
    pub const DEBUG_CONTROL: i32 = 10;
    /// `TASK_RESOURCE_NOTIFY_PORT`.
    pub const RESOURCE_NOTIFY: i32 = 11;
    /// `TASK_MAX_SPECIAL_PORT`.
    pub const MAX: i32 = 13;
}

/// An exception action (`struct exception_action`): the handler's send
/// right, behavior, and thread-state flavor.
#[derive(Clone, Debug, Default)]
pub struct ExcAction {
    /// The handler port (a send right the kernel holds).
    pub port: Option<Arc<Port>>,
    /// `exception_behavior_t`.
    pub behavior: i32,
    /// `thread_state_flavor_t`.
    pub flavor: i32,
}

/// A registered restartable range (`task_restartable_range_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartableRange {
    /// Start address.
    pub location: u64,
    /// Length in bytes.
    pub length: u16,
    /// Offset of the recovery code from `location`.
    pub recovery_offs: u16,
    /// Flags (must be 0).
    pub flags: u32,
}

/// Mach task state (all empty or zero for a new task; the role is
/// `TASK_UNSPECIFIED`).
#[derive(Debug, Default)]
pub struct TaskState {
    /// Settable special ports (send rights held by the kernel), by number.
    pub special: [Option<Arc<Port>>; special::MAX as usize + 1],
    /// The task name port (`TASK_NAME_PORT`), made on first use.
    pub name_port: Option<Arc<Port>>,
    /// Task exception actions, by exception type.
    pub exc: [ExcAction; EXC_TYPES_COUNT],
    /// `task_exc_guard_behavior_t`.
    pub exc_guard: u32,
    /// Restartable ranges (`task_restartable_ranges_register`).
    pub restartable: Vec<RestartableRange>,
    /// Send-once rights waiting for host notifications.
    pub host_notify: Vec<Right>,
    /// The system and calendar clock ports.
    pub clock_ports: [Option<Arc<Port>>; 2],
    /// `dyld_state` from `task_register_dyld_set_dyld_state`.
    pub dyld_state: u8,
    /// dyld's all-image-info address and size (`TASK_DYLD_INFO`).
    pub dyld_info: (u64, u64),
    /// `TF_DYLD_ALL_IMAGE_FINAL`: `dyld_info` no longer changes.
    pub dyld_final: bool,
    /// CPU time of terminated threads: (user, system) nanoseconds.
    pub dead_times: (u64, u64),
    /// Messages sent and received (`task_events_info`).
    pub messages: (u64, u64),
    /// Mach and BSD system calls made (`task_events_info`).
    pub syscalls: (u64, u64),
    /// `task_policy_set` state: `TASK_CATEGORY_POLICY` role.
    pub role: i32,
}

impl TaskState {
    /// `task_set_dyld_info`: records dyld's all-image-info range unless
    /// it is final, making it final when a non-zero range replaces a
    /// non-zero one or when `finalize`; whether it was recorded.
    pub fn set_dyld_info(&mut self, addr: u64, size: u64, finalize: bool) -> bool {
        if addr.checked_add(size).is_none() || self.dyld_final {
            return false;
        }
        let current = self.dyld_info != (0, 0);
        self.dyld_info = (addr, size);
        if (addr, size) != (0, 0) && current || finalize {
            self.dyld_final = true;
        }
        true
    }
}

/// Mach thread state kept outside the CPU.
#[derive(Clone, Debug, Default)]
pub struct ThreadMach {
    /// CPU time spent running guest code, nanoseconds.
    pub user_ns: u64,
    /// CPU time spent in the kernel on the thread's behalf, nanoseconds.
    pub system_ns: u64,
    /// Thread exception actions, by exception type.
    pub exc: Vec<ExcAction>,
    /// Suspend count (`thread_suspend`).
    pub suspend_count: u32,
    /// Context switches (slices run).
    pub csw: u64,
    /// `THREAD_TAG_*`.
    pub tag: u16,
    /// A join ulock to wake when the thread is gone, with the port name
    /// to drop then (`uus_bsdthread_terminate`).
    pub join: Option<(u64, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dyld_info_becomes_final_once_replaced() {
        // exec: cleared, then the loader's registration (not final).
        let mut t = TaskState::default();
        assert!(t.set_dyld_info(0, 0, false));
        assert!(t.set_dyld_info(0x1000, 0x170, false));
        assert!(!t.dyld_final);
        // dyld's own registration replaces it and is final.
        assert!(t.set_dyld_info(0x2000, 0x170, false));
        assert!(t.dyld_final);
        assert!(!t.set_dyld_info(0x2000, 0x170, false));
        assert_eq!(t.dyld_info, (0x2000, 0x170));
    }

    #[test]
    fn dyld_info_without_a_dynamic_linker_is_final() {
        let mut t = TaskState::default();
        assert!(t.set_dyld_info(0, 0, true));
        assert!(t.dyld_final);
        assert!(!t.set_dyld_info(0x1000, 0x10, false));
    }

    #[test]
    fn dyld_info_ranges_must_not_wrap() {
        let mut t = TaskState::default();
        assert!(!t.set_dyld_info(u64::MAX, 2, false));
        assert_eq!(t.dyld_info, (0, 0));
        // A zero range over a zero range is not final.
        assert!(t.set_dyld_info(0, 0, false));
        assert!(!t.dyld_final);
    }
}
