//! ARM64EC emulator helpers over guest interpreters and guest memory only.
use super::*;
use crate::user::image::pe::hybrid::CodeKind;
use crate::user::windows::hle::dispatch::Outcome;
use crate::user::windows::memory::Mem;

#[cfg(test)]
#[path = "hybrid_tests.rs"]
mod tests;

pub(super) fn helper(p: &mut Proc, t: &mut Thread, index: u8) -> Outcome {
    let mut run = || -> Result<(), String> {
        if !t.cpu.is_arm64ec() || t.cpu.instruction_arch() != WinArch::Arm64 {
            return Err("ARM64EC helper requires an active emulation-compatible context".into());
        }
        match index {
            0 => {
                let target = t.cpu.call_gpr(9);
                if p.modules.code_kind(target) != Some(CodeKind::Amd64) {
                    return Err(format!(
                        "ARM64EC no-redirect target is not AMD64 code: {target:#x}"
                    ));
                }
                let stack = t
                    .cpu
                    .sp()
                    .checked_sub(8)
                    .ok_or("ARM64EC exit stack underflow")?;
                p.space
                    .w64(stack, t.cpu.call_gpr(30))
                    .map_err(|fault| format!("ARM64EC exit return store: {fault:?}"))?;
                t.cpu.ec_exit(target, stack)
            }
            1 => t.cpu.ec_return(),
            2..=4 => {
                if index == 4 && p.modules.arm64ec_cfg {
                    return Err(
                        "ARM64EC CFG-enabled process requires target-table admission".into(),
                    );
                }
                // Early direct calls pass X9; both indirect checkers use
                // the documented X11 input/output target carrier.
                let target = t.cpu.call_gpr(if index == 2 { 9 } else { 11 });
                let target = redirect(p, target)?;
                match p.modules.code_kind(target) {
                    Some(CodeKind::Arm64Ec | CodeKind::Arm64) => t.cpu.set_call_gpr(11, target),
                    Some(CodeKind::Amd64) => {
                        let exit = t.cpu.call_gpr(10);
                        if p.modules.code_kind(exit) != Some(CodeKind::Arm64Ec) {
                            return Err("ARM64EC indirect call has no admitted exit thunk".into());
                        }
                        t.cpu.set_call_gpr(9, target);
                        t.cpu.set_call_gpr(11, exit);
                    }
                    _ => {
                        return Err(format!(
                            "ARM64EC indirect target is outside admitted code: {target:#x}"
                        ));
                    }
                }
                t.cpu.set_pc(t.cpu.call_gpr(30));
                Ok(())
            }
            5 | 6 => Err(format!(
                "ARM64EC {} x64 information type {} is not implemented",
                if index == 5 { "get" } else { "set" },
                t.cpu.call_gpr(0)
            )),
            7 => {
                // A signature-less entry thunk defers conversion to the real
                // target. Reconstitute its x64 call boundary before routing it.
                let target = t.cpu.call_gpr(9);
                let link = t.cpu.call_gpr(30);
                let stack = t
                    .cpu
                    .call_gpr(4)
                    .checked_sub(8)
                    .ok_or("ARM64EC jump stack underflow")?;
                p.space
                    .w64(stack, link)
                    .map_err(|fault| format!("ARM64EC jump return store: {fault:?}"))?;
                t.cpu.ec_jump(target, stack)
            }
            _ => Err(format!("unknown ARM64EC helper slot {index}")),
        }
    };
    match run() {
        Ok(()) => Outcome::Continue,
        Err(error) => Outcome::Fail(error),
    }
}

fn redirect(p: &Proc, target: u64) -> Result<u64, String> {
    let Some((_, module)) = p.modules.by_address(target) else {
        return Ok(target);
    };
    let Some(metadata) = &module.hybrid else {
        return Ok(target);
    };
    let rva =
        u32::try_from(target - module.base).map_err(|_| "ARM64EC redirection RVA overflow")?;
    let Ok(index) = metadata
        .redirections
        .binary_search_by_key(&rva, |row| row.source)
    else {
        return Ok(target);
    };
    let destination = module.base + u64::from(metadata.redirections[index].destination);
    // Redirection applies only to the unchanged canonical fast-forward
    // sequence. Modified guest code must execute through its x64 exit thunk.
    let bytes = p
        .space
        .bytes(target, 14)
        .map_err(|_| "ARM64EC fast-forward sequence is unreadable")?;
    if bytes[..10] != [0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9] {
        return Ok(target);
    }
    let relative = i32::from_le_bytes(bytes[10..14].try_into().unwrap());
    if target
        .checked_add(14)
        .and_then(|pc| pc.checked_add_signed(i64::from(relative)))
        != Some(destination)
    {
        return Ok(target);
    }
    Ok(destination)
}
