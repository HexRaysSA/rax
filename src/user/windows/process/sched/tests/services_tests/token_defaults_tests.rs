//! Single-pointer token records through the installed NTDLL service boundary on all guest ABIs.

use super::{Proc, Thread, WinArch, handle, invoke, setup};
use crate::user::windows::hle::dispatch::Outcome;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::token::pointer_records::Class;
use crate::user::windows::wnf::Catalog;
use std::sync::Arc;

const OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
const GROUP: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0];
const ACL: [u8; 8] = [2, 0, 8, 0, 0, 0, 0, 0];
const SENTINEL: u32 = 0xa5a5_a5a5;

fn query(
    p: &mut Proc,
    thread: &mut Thread,
    token: u64,
    class: Class,
    output: u64,
    length: u32,
    returned: u64,
) -> u32 {
    let stack = thread.cpu.sp();
    let args = [token, class as u64, output, u64::from(length), returned];
    assert_eq!(invoke(p, thread, &args), Outcome::Continue);
    thread.cpu.set_sp(stack);
    thread.cpu.gpr(0) as u32
}

#[test]
fn native_token_pointer_records_replay_sizes_access_and_overlapping_writes() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, output, handles) = setup(arch, false);
        let p = process.state_mut();
        let wow = arch == WinArch::X86;
        let width = if wow { 4 } else { 8 };
        let returned = output + 128;
        let query_handle = handles[1];
        let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
        let inputs = [
            (Class::Owner, OWNER.as_slice()),
            (Class::PrimaryGroup, GROUP.as_slice()),
            (Class::DefaultDacl, ACL.as_slice()),
            (Class::ProcessTrustLevel, &[]),
        ];
        for (class, bytes) in inputs {
            subject.token_pointer_records.insert(class, bytes.into());
        }
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject.clone()).unwrap());

        for (class, bytes) in inputs {
            let required = width as u32 + bytes.len() as u32;
            let no_result = if wow { 0xffff_fffc } else { SENTINEL };
            let cases = [
                (
                    query_handle,
                    0,
                    0,
                    returned,
                    STATUS_BUFFER_TOO_SMALL,
                    required,
                ),
                (
                    query_handle,
                    output,
                    required - 1,
                    returned,
                    STATUS_BUFFER_TOO_SMALL,
                    required,
                ),
                (
                    query_handle,
                    0,
                    required,
                    returned,
                    STATUS_ACCESS_VIOLATION,
                    no_result,
                ),
                (
                    handles[2],
                    output,
                    required,
                    returned,
                    STATUS_ACCESS_DENIED,
                    no_result,
                ),
                (
                    0,
                    output,
                    required,
                    returned,
                    STATUS_INVALID_HANDLE,
                    no_result,
                ),
                (
                    handle(p, "thread-token", handles),
                    output,
                    required,
                    returned,
                    STATUS_NO_TOKEN,
                    no_result,
                ),
            ];
            for (token, out, length, ret, status, result) in cases {
                p.space.wr(output, &[0xa5; 132]).unwrap();
                assert_eq!(
                    query(p, &mut thread, token, class, out, length, ret),
                    status,
                    "{arch} {class:?} token {token:#x} length {length}"
                );
                assert_eq!(p.space.u32(returned).unwrap(), result);
                assert_eq!(p.space.u32(output).unwrap(), SENTINEL);
            }

            for (out, ret) in [
                (output, returned),
                (output + 4, returned + 1),
                (output + 1, returned),
                (output, 0),
                (output, output),
                (output, output + width + 1),
            ] {
                p.space.wr(output, &[0xa5; 136]).unwrap();
                let status = if !wow && out % 4 != 0 {
                    STATUS_DATATYPE_MISALIGNMENT
                } else if !wow && ret == 0 {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_SUCCESS
                };
                assert_eq!(
                    query(p, &mut thread, query_handle, class, out, required + 1, ret),
                    status,
                    "{arch} {class:?} output +{} return {ret:#x}",
                    out - output,
                );
                if status != STATUS_SUCCESS {
                    assert_eq!(p.space.u8(out).unwrap(), 0xa5);
                    continue;
                }
                let pointer = if bytes.is_empty() { 0 } else { out + width };
                let pointer = pointer.to_le_bytes();
                let mut expected = [0xa5; 136];
                let offset = (out - output) as usize;
                if !wow && ret != 0 {
                    let index = (ret - output) as usize;
                    expected[index..index + 4].copy_from_slice(&required.to_le_bytes());
                }
                expected[offset..offset + width as usize]
                    .copy_from_slice(&pointer[..width as usize]);
                expected[offset + width as usize..offset + required as usize]
                    .copy_from_slice(bytes);
                if wow && ret != 0 {
                    let index = (ret - output) as usize;
                    expected[index..index + 4].copy_from_slice(&required.to_le_bytes());
                }
                assert_eq!(p.space.bytes(output, expected.len()).unwrap(), expected);
            }
        }

        subject
            .token_pointer_records
            .insert(Class::DefaultDacl, Box::from([]));
        let object = p.objects.create(Object::GuestImpersonationToken {
            subject: Arc::new(subject),
            level: 2,
        });
        let token = u64::from(p.objects.open_access(object, false, 8).unwrap());
        p.space.wr(output, &[0xa5; 136]).unwrap();
        assert_eq!(
            query(
                p,
                &mut thread,
                token,
                Class::DefaultDacl,
                output,
                width as u32,
                returned
            ),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u32(returned).unwrap(), width as u32);
        assert_eq!(
            p.space.bytes(output, width as usize).unwrap(),
            vec![0; width as usize]
        );
        assert_eq!(p.space.u8(output + width).unwrap(), 0xa5);
    }
}

#[test]
fn native_token_defaults_keep_pointer_when_wow64_payload_faults() {
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::memory::prot;

    let (mut process, mut thread, base, handles) = setup(WinArch::X86, false);
    let p = process.state_mut();
    let mut subject = (*p.objects.primary_token_subject().unwrap()).clone();
    subject
        .token_pointer_records
        .insert(Class::Owner, Box::from(OWNER));
    p.objects
        .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());

    let boundary = base + PAGE_SIZE;
    let output = boundary - 4;
    let returned = boundary + PAGE_SIZE;
    for inaccessible in [base, boundary] {
        p.space.wr(output, &[0xa5; 16]).unwrap();
        p.space.w32(returned, SENTINEL).unwrap();
        p.vm.protect(inaccessible, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        assert_eq!(
            query(
                p,
                &mut thread,
                handles[1],
                Class::Owner,
                output,
                16,
                returned
            ),
            STATUS_ACCESS_VIOLATION
        );
        p.vm.protect(inaccessible, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        let pointer = if inaccessible == boundary {
            boundary as u32
        } else {
            SENTINEL
        };
        assert_eq!(p.space.u32(output).unwrap(), pointer);
        assert_eq!(p.space.bytes(boundary, 12).unwrap(), [0xa5; 12]);
        assert_eq!(p.space.u32(returned).unwrap(), SENTINEL);
    }
}
