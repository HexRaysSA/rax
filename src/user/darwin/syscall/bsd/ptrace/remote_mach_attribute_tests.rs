//! Cache synchronization is required after debugger writes on ARM64.
//! Expected statuses come from XNU vm_user.c/vm_map.c and the native probe.

use super::*;
use crate::user::mm::{CodeChanges, Mapping, Perms};

#[test]
fn remote_cache_attribute_preserves_values_and_publishes_code_invalidation() {
    let (mut caller, mut target, _) = pair();
    let address = (target.proc.vm.min + 0x10_0000) & !(target.proc.vm.page - 1);
    let page = target.proc.vm.page;
    target
        .proc
        .space
        .map(address, page, Mapping::anonymous(Perms::READ))
        .unwrap();
    let task = task_port(&mut caller.proc, 1002).unwrap();
    let _name = caller.proc.insert_send(&task);
    for id in [
        ids::mach_vm::MACH_VM_MACHINE_ATTRIBUTE,
        ids::vm_map::VM_MACHINE_ATTRIBUTE,
    ] {
        for value in [u32::MAX, 0, 1, 2, 6, 7, 8, 9, 10, 11] {
            let epoch = target.proc.space.code_epoch();
            let mut body = msg::NDR_RECORD.to_vec();
            body.extend_from_slice(&(address + 1).to_le_bytes());
            body.extend_from_slice(&4u64.to_le_bytes());
            body.extend_from_slice(&1u32.to_le_bytes());
            body.extend_from_slice(&value.to_le_bytes());
            let reply = send(&mut caller, &task, id, body);
            ptrace::pump(&mut target.proc, None);
            ptrace::pump(&mut caller.proc, None);
            let message = take_reply(&mut caller.proc, &reply);
            assert_eq!(message.body.len(), 16);
            assert_eq!(
                i32::from_le_bytes(message.body[8..12].try_into().unwrap()),
                0
            );
            assert_eq!(
                u32::from_le_bytes(message.body[12..16].try_into().unwrap()),
                value
            );
            assert_eq!(
                target.proc.space.code_changes_since(epoch).0,
                CodeChanges::Ranges(vec![(address, page)])
            );
            kmsg::destroy(&mut caller.proc, message);
        }
    }
}
