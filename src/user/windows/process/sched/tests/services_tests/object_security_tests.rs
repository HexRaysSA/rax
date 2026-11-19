use super::file_open_tests::arguments;
use super::{Outcome, Proc, Thread, handle_stop, stop, terminal_fixture};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::traverse_only_tests::rpc_directory_with_security;
use crate::user::windows::object_namespace::{RPC_CONTROL_PATH, RpcSecurity};

const SERVICE: u32 = 0x33;

fn invoke(process: &mut Proc, thread: &mut Thread, args: [u64; 5]) -> u32 {
    let stack = thread.cpu.sp();
    arguments(process, thread, &args);
    let result = if process.arch == WinArch::X86 {
        crate::user::windows::process::services::wow64(process, thread, 0x1234_0000)
    } else {
        handle_stop(process, thread, stop(process.arch, SERVICE))
    };
    assert_eq!(result, Outcome::Continue, "{}", process.arch);
    assert_eq!(thread.cpu.pc(), 0x1234_0004);
    assert_eq!(
        thread.cpu.sp(),
        stack + if process.arch == WinArch::X86 { 4 } else { 0 }
    );
    assert!(thread.frames.is_empty());
    thread.cpu.set_sp(stack);
    thread.cpu.gpr(0) as u32
}

#[test]
fn native_rpc_directory_security_preserves_access_and_output_order() {
    const MASK: u64 = 0x17;
    const SENTINEL: u32 = 0xa5a5_a5a5;
    let empty = [
        1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut descriptor = vec![0x19; 232];
    descriptor[..20].copy_from_slice(&empty);
    let mut descriptors: [Option<Box<[u8]>>; 16] = std::array::from_fn(|_| None);
    descriptors[0] = Some(Box::new(empty));
    descriptors[15] = Some(descriptor.clone().into_boxed_slice());
    let namespace = rpc_directory_with_security(RpcSecurity { descriptors });
    let name: Vec<_> = RPC_CONTROL_PATH.encode_utf16().collect();
    let directory = namespace.lookup(None, &name, 0).unwrap();

    for arch in WinArch::ALL {
        let (mut emulation, mut thread, ntdll) = terminal_fixture(arch);
        let process = emulation.state_mut();
        process.modules.nt_services =
            Some((ntdll, named_table(arch, "NtQuerySecurityObject", SERVICE)));
        let read_control = process
            .objects
            .open_directory(directory.clone(), false, 0x20001)
            .unwrap() as u64;
        let query_only = process
            .objects
            .open_directory(directory.clone(), false, 1)
            .unwrap() as u64;
        let (output, _) = process
            .vm
            .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
        process.space.wr(output, &[0xa5; 516]).unwrap();
        let length = output + 512;
        for (handle, mask, address, capacity, returned, status) in [
            (query_only, MASK, 0, 0, length, STATUS_ACCESS_DENIED),
            (query_only, 8, 0, 0, length, STATUS_ACCESS_DENIED),
            (0x4141, MASK, 0, 0, length, STATUS_INVALID_HANDLE),
            (read_control, MASK, 0, 1, length, STATUS_ACCESS_VIOLATION),
            (
                read_control,
                MASK,
                output + 1,
                232,
                length,
                STATUS_DATATYPE_MISALIGNMENT,
            ),
            (read_control, MASK, output, 232, 0, STATUS_ACCESS_VIOLATION),
        ] {
            assert_eq!(
                invoke(
                    process,
                    &mut thread,
                    [handle, mask, address, capacity, returned]
                ),
                status,
                "arch={arch} handle={handle:#x} mask={mask:#x} capacity={capacity}"
            );
        }
        assert_eq!(process.space.u32(length).unwrap(), SENTINEL);
        assert_eq!(process.space.u32(output).unwrap(), SENTINEL);
        assert_eq!(
            invoke(
                process,
                &mut thread,
                [read_control, MASK, output, 231, length]
            ),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(process.space.u32(length).unwrap(), 232);
        assert_eq!(process.space.u32(output).unwrap(), SENTINEL);
        assert_eq!(
            invoke(
                process,
                &mut thread,
                [read_control, MASK, output, 233, output + 4]
            ),
            STATUS_SUCCESS
        );
        let mut expected = descriptor.clone();
        expected[4..8].copy_from_slice(&232u32.to_le_bytes());
        assert_eq!(process.space.bytes(output, 232).unwrap(), expected);
        assert_eq!(process.space.u8(output + 232).unwrap(), 0xa5);
        assert_eq!(
            invoke(
                process,
                &mut thread,
                [read_control, MASK, output, 232, output]
            ),
            STATUS_SUCCESS
        );
        let mut aliased = descriptor.clone();
        aliased[..4].copy_from_slice(&232u32.to_le_bytes());
        if arch == WinArch::X86 {
            for (destination, source) in [(4, 8), (8, 16), (12, 24), (16, 32)] {
                aliased[destination..destination + 4]
                    .copy_from_slice(&descriptor[source..source + 4]);
            }
        }
        assert_eq!(process.space.bytes(output, 232).unwrap(), aliased);
        assert_eq!(
            invoke(
                process,
                &mut thread,
                [query_only, 0x20000000, output, 20, length]
            ),
            STATUS_SUCCESS
        );
        assert_eq!(process.space.u32(length).unwrap(), 20);
        assert_eq!(process.space.bytes(output, 20).unwrap(), empty);
    }
}
