//! AMD64 syscall contexts on the measured ARM64 kernel use ARM64EC_NT_CONTEXT.
use super::*;

pub(super) fn selected(c: &Ctx, arch: WinArch) -> Result<bool, ApiErr> {
    if arch != WinArch::X64 {
        return Ok(false);
    }
    let Some(native) = &c.p.native else {
        return Ok(false);
    };
    if native.object_namespace.native_machine != Some(0xaa64) {
        return Ok(false);
    }
    if (
        native.version.major,
        native.version.minor,
        native.version.build,
    ) != (10, 0, 29704)
    {
        return Err(
            c.unsupported("AMD64 thread-context compatibility for this native kernel identity")
        );
    }
    Ok(true)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub(super) fn get(c: &mut Ctx) -> ApiResult {
    let (handle, address) = (c.ptr(0)?, c.ptr(1)?);
    let mut output = c.mem().bytes(address, 672)?;
    let flags = u32_at(&output, 48);
    let extended = match extended::capture(c, address, WinArch::X64, flags)? {
        Ok(state) => state,
        Err(status) => return Flow::ret(status.into()),
    };
    let id = match target(c, handle, 8) {
        Ok(id) => id,
        Err(status) => return Flow::ret(status.into()),
    };
    probe_write(c, address, 672)?;
    if retired(c, id) {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    let target = cpu(c, id)?;
    if let Some(state) = &extended {
        state.get(c, target, WinArch::X64)?;
    }
    let source = RegContext::capture(target);
    let selected = if flags & 0x0010_0000 != 0 {
        flags & 0x1b
    } else {
        0
    };
    output[..48].fill(0);
    let returned = selected | if extended.is_some() { 0x40 } else { 0 };
    output[48..52].copy_from_slice(
        &((if returned == 0 {
            0u32
        } else {
            returned | 0x0010_0000
        }) | groups::information(WinArch::X64, flags, reported(c, id)))
        .to_le_bytes(),
    );
    output[54..56].fill(0);
    for (n, selector) in [0x33u16, 0x2b, 0x2b, 0x53, 0x2b, 0x2b]
        .into_iter()
        .enumerate()
    {
        output[56 + n * 2..58 + n * 2].copy_from_slice(&selector.to_le_bytes());
    }
    let eflags = if selected & 1 != 0 {
        source.flags_register() & 0x8c1 | 0x202
    } else {
        0x202
    };
    output[68..72].copy_from_slice(&eflags.to_le_bytes());
    output[72..120].fill(0);
    output[256..280].fill(0);
    output[256..258].copy_from_slice(&0x027fu16.to_le_bytes());
    output[282..288].fill(0);
    for n in 0..8 {
        output[298 + n * 16..304 + n * 16].fill(0);
    }
    if selected & 1 != 0 {
        for range in [152..168, 248..256, 288..296] {
            output[range.clone()].copy_from_slice(&source.bytes()[range]);
        }
    }
    if selected & 2 != 0 {
        for range in [120..152, 168..248] {
            output[range.clone()].copy_from_slice(&source.bytes()[range]);
        }
        for n in 0..8 {
            if n != 0 {
                output[288 + n * 16..296 + n * 16]
                    .copy_from_slice(&source.bytes()[288 + n * 16..296 + n * 16]);
            }
            output[296 + n * 16..298 + n * 16]
                .copy_from_slice(&source.bytes()[296 + n * 16..298 + n * 16]);
        }
    }
    if selected & 8 != 0 {
        output[52..56].copy_from_slice(&source.bytes()[52..56]);
        output[280..284].copy_from_slice(&source.bytes()[52..56]);
        output[416..672].copy_from_slice(&source.bytes()[416..672]);
    }
    if selected & 16 != 0 {
        let debug = target
            .kernel_debug_context(WinArch::Arm64)
            .map_err(|status| c.unsupported(format!("debug context status {status:#x}")))?;
        let enabled: Vec<_> = (0..4).filter(|n| u32_at(&debug, n * 4) & 1 != 0).collect();
        if !enabled.is_empty() {
            output[72..104].copy_from_slice(&debug[32..64]);
            let dr6 = u64::from_le_bytes(debug[64..72].try_into().unwrap());
            let dr6 = dr6 | 0xffff_0ff0;
            output[104..112].copy_from_slice(&dr6.to_le_bytes());
            let mut dr7 = 0x400u64;
            for n in enabled {
                let value = u64::from_le_bytes(debug[32 + n * 8..40 + n * 8].try_into().unwrap());
                if value != 0 {
                    dr7 |= 1 << (n * 2);
                }
            }
            output[112..120].copy_from_slice(&dr7.to_le_bytes());
        }
    }
    c.mem().wr(address, &output)?;
    Flow::ret(0)
}

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let (handle, address) = (c.ptr(0)?, c.ptr(1)?);
    let input = c.mem().bytes(address, 672)?;
    let flags = u32_at(&input, 48);
    let extended = match extended::capture(c, address, WinArch::X64, flags)? {
        Ok(state) => state,
        Err(status) => return Flow::ret(status.into()),
    };
    let id = match target(c, handle, 16) {
        Ok(id) => id,
        Err(status) => return Flow::ret(status.into()),
    };
    if retired(c, id) {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    let ymm = match &extended {
        Some(state) => state.input(c, WinArch::X64)?,
        None => None,
    };
    let selected = if flags & 0x0010_0000 != 0 {
        flags & 0x1b
    } else {
        0
    };
    let target = cpu(c, id)?;
    let mut context = match target.arm64_context_from_amd64(&input, selected) {
        Ok(context) => context,
        Err(status) => return Flow::ret(status.into()),
    };
    // A self CONTROL restore publishes this frame after the immediate state
    // updates. Keep its FP-high aliases consistent with the selected XSTATE
    // payload so the resume cannot restore the previous upper YMM values.
    if let Some(values) = ymm {
        for (n, pair) in values.into_iter().enumerate() {
            context.set_v(n + 16, u128::from(pair[0]) | (u128::from(pair[1]) << 64));
        }
    }
    if let Err(status) = target.validate_kernel_context(&context) {
        return Flow::ret(status.into());
    }
    let debug = if selected & 16 != 0 {
        let mut bytes = vec![0; 120];
        let dr7 = u32_at(&input, 112);
        for n in 0..4 {
            let enabled = dr7 & (1 << (n * 2)) != 0 && (dr7 >> (16 + n * 4)) & 3 == 0;
            bytes[n * 4..n * 4 + 4]
                .copy_from_slice(&(if enabled { 0x1e5u32 } else { 0 }).to_le_bytes());
        }
        bytes[32..64].copy_from_slice(&input[72..104]);
        bytes[64..72].copy_from_slice(&input[104..112]);
        Some(bytes)
    } else {
        None
    };
    let user_limit = c.p.vm.high();
    if let Some(debug) = &debug {
        let mut prepared = target.new_thread();
        if let Err(status) = prepared.apply_kernel_debug_context(WinArch::Arm64, debug, user_limit)
        {
            return Flow::ret(status.into());
        }
    }
    if id == c.t.obj && selected & 1 != 0 {
        if let Some(ymm) = ymm {
            if let Err(status) = c.t.cpu.apply_kernel_ymm_high(ymm) {
                return Flow::ret(status.into());
            }
        }
        if let Some(debug) = &debug {
            if let Err(status) =
                c.t.cpu
                    .apply_kernel_debug_context(WinArch::Arm64, debug, user_limit)
            {
                return Flow::ret(status.into());
            }
        }
        return Ok(Flow::Resume(Box::new(context)));
    }
    let target = if id == c.t.obj {
        &mut c.t.cpu
    } else {
        let Some(Object::Thread { tid, .. }) = c.p.objects.obj(id) else {
            unreachable!("validated thread")
        };
        &mut c.p.threads.get_mut(tid).expect("validated target").cpu
    };
    if selected & 0xb != 0 {
        if let Err(status) = target.apply_kernel_context(&context) {
            return Flow::ret(status.into());
        }
    }
    if let Some(debug) = &debug {
        if let Err(status) = target.apply_kernel_debug_context(WinArch::Arm64, debug, user_limit) {
            return Flow::ret(status.into());
        }
    }
    if let Some(ymm) = ymm {
        if let Err(status) = target.apply_kernel_ymm_high(ymm) {
            return Flow::ret(status.into());
        }
    }
    Flow::ret(0)
}
