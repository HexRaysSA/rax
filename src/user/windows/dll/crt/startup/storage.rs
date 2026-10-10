//! Unpublished process-owned CRT cells and startup input snapshots.
//!
//! `prepare` is synchronous and writes only a fresh, unpublished built-in
//! image. Its VM blob is not a heap allocation or an importer's loader receipt.
//! Cleanup trusts the host's allocation bases, never mutable guest pointers.
//! Counted UTF-16 inputs retain raw units; malformed metadata rejection is a
//! checked personality profile, not a native CRT error-status oracle.

use crate::error::MemoryAccessKind;
use crate::user::windows::context::ExceptionRecord;
use crate::user::windows::dll::BuiltinDll;
use crate::user::windows::hle::{ApiErr, DataSize, Item};
use crate::user::windows::layout::offsets;
use crate::user::windows::loader::{LoadError, ModuleKind, builtin::BuiltinSym};
use crate::user::windows::memory::{AllocKind, Mem, MemFault, mem, prot};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
};
use crate::user::windows::process::Proc;

const NAMES: [&str; 11] = [
    "__argc",
    "__argv",
    "__wargv",
    "_environ",
    "_wenviron",
    "__initenv",
    "__winitenv",
    "_acmdln",
    "_wcmdln",
    "_pgmptr",
    "_wpgmptr",
];

pub(in crate::user::windows::dll::crt) struct StartupState {
    pub(super) cells: [u64; 11],
    pub(super) initial_env: [u64; 2],
    pub(super) blocks: Vec<u64>,
    pub(super) environment: Vec<Vec<u16>>,
    pub(super) command_line: Vec<u16>,
}

fn error(status: u32, message: impl Into<String>) -> LoadError {
    LoadError {
        status,
        message: message.into(),
    }
}

fn no_memory() -> LoadError {
    error(STATUS_NO_MEMORY, "CRT startup storage exhausted")
}

fn malformed(what: &str) -> LoadError {
    error(
        STATUS_INVALID_PARAMETER,
        format!("malformed CRT startup {what}"),
    )
}

fn access(fault: MemFault) -> LoadError {
    error(
        STATUS_ACCESS_VIOLATION,
        format!(
            "CRT startup {} fault at {:#x}",
            if fault.write { "write" } else { "read" },
            fault.addr
        ),
    )
}

/// Computes a complete scalar/range address without guest-width wrapping.
fn address(p: &Proc, base: u64, offset: u64, bytes: u64, write: bool) -> Result<u64, MemFault> {
    let max = p.arch.ptr(u64::MAX);
    let overflow = || MemFault { addr: max, write };
    let at = base.checked_add(offset).ok_or_else(overflow)?;
    let last = at
        .checked_add(bytes.saturating_sub(1))
        .ok_or_else(overflow)?;
    if last > max {
        return Err(MemFault {
            addr: max.saturating_add(1),
            write,
        });
    }
    Ok(at)
}

fn source_address(p: &Proc, base: u64, offset: u64, bytes: u64) -> Result<u64, LoadError> {
    address(p, base, offset, bytes, false).map_err(access)
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), LoadError> {
    values.try_reserve(1).map_err(|_| no_memory())?;
    values.push(value);
    Ok(())
}

fn unicode(p: &Proc, field: u64) -> Result<Vec<u16>, LoadError> {
    let width = p.arch.ptr_size();
    let length = p
        .space
        .u16(source_address(p, field, 0, 2)?)
        .map_err(access)?;
    let maximum = p
        .space
        .u16(source_address(p, field, 2, 2)?)
        .map_err(access)?;
    if length & 1 != 0 || maximum < length {
        return Err(malformed("UNICODE_STRING length"));
    }
    let buffer = p
        .space
        .ptr(source_address(p, field, width, width)?, width)
        .map_err(access)?;
    if length == 0 {
        return Ok(Vec::new());
    }
    if buffer & 1 != 0 {
        return Err(malformed("UTF-16 buffer alignment"));
    }
    source_address(p, buffer, 0, u64::from(length))?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(usize::from(length / 2))
        .map_err(|_| no_memory())?;
    for offset in (0..u64::from(length)).step_by(2) {
        units.push(
            p.space
                .u16(source_address(p, buffer, offset, 2)?)
                .map_err(access)?,
        );
    }
    // The counted range excludes its terminator; do not read the next page.
    Ok(units)
}

fn environment(p: &Proc) -> Result<Vec<Vec<u16>>, LoadError> {
    let o = offsets(p.arch);
    let base = p
        .space
        .ptr(source_address(p, p.params, o.pp_environment, o.ptr)?, o.ptr)
        .map_err(access)?;
    let bytes = p
        .space
        .ptr(
            source_address(p, p.params, o.pp_environment_size, o.ptr)?,
            o.ptr,
        )
        .map_err(access)?;
    if base == 0 && bytes == 0 {
        return Ok(Vec::new());
    }
    if base & 1 != 0 || bytes & 1 != 0 || bytes < 4 {
        return Err(malformed("environment bounds/alignment"));
    }
    source_address(p, base, 0, bytes)?;
    let mut values = Vec::new();
    let mut value = Vec::new();
    let mut previous_nul = false;
    for offset in (0..bytes).step_by(2) {
        let unit = p
            .space
            .u16(source_address(p, base, offset, 2)?)
            .map_err(access)?;
        if unit == 0 {
            if previous_nul {
                return Ok(values);
            }
            if !value.is_empty() {
                push(&mut values, std::mem::take(&mut value))?;
            }
            previous_nul = true;
        } else {
            if previous_nul && values.is_empty() {
                return Err(malformed("leading empty environment entry"));
            }
            previous_nul = false;
            push(&mut value, unit)?;
        }
    }
    Err(malformed("unterminated environment"))
}

fn inputs(p: &Proc) -> Result<(Vec<u16>, Vec<u16>, Vec<Vec<u16>>), LoadError> {
    if p.params == 0 {
        // Test/bootstrap Proc values may have no parameter block. This profile
        // does not substitute config arguments or a host environment.
        let mut path = Vec::new();
        if let Some((_, module)) = p.modules.list.iter().enumerate().find(|(index, module)| {
            p.modules.is_live(*index) && matches!(module.kind, ModuleKind::Exe)
        }) {
            for unit in module.path.encode_utf16() {
                push(&mut path, unit)?;
            }
        }
        return Ok((Vec::new(), path, Vec::new()));
    }
    if p.params % p.arch.ptr_size() != 0 {
        return Err(malformed("process-parameter alignment"));
    }
    let o = offsets(p.arch);
    Ok((
        unicode(p, source_address(p, p.params, o.pp_command_line, 0)?)?,
        unicode(p, source_address(p, p.params, o.pp_image_path_name, 0)?)?,
        environment(p)?,
    ))
}

fn append(blob: &mut Vec<u8>, bytes: &[u8]) -> Result<u64, LoadError> {
    let offset = u64::try_from(blob.len()).map_err(|_| no_memory())?;
    blob.try_reserve(bytes.len()).map_err(|_| no_memory())?;
    blob.extend_from_slice(bytes);
    Ok(offset)
}

fn narrow(blob: &mut Vec<u8>, units: &[u16]) -> Result<u64, LoadError> {
    let bytes = super::codepage::encode(units);
    let offset = append(blob, &bytes)?;
    push(blob, 0)?;
    Ok(offset)
}

fn wide(blob: &mut Vec<u8>, units: &[u16]) -> Result<u64, LoadError> {
    if blob.len() & 1 != 0 {
        push(blob, 0)?;
    }
    let offset = u64::try_from(blob.len()).map_err(|_| no_memory())?;
    let extra = units
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(no_memory)?;
    blob.try_reserve(extra).map_err(|_| no_memory())?;
    for &unit in units {
        blob.extend_from_slice(&unit.to_le_bytes());
    }
    blob.extend_from_slice(&[0, 0]);
    Ok(offset)
}

fn pointer_alignment(blob: &mut Vec<u8>, width: u64) -> Result<(), LoadError> {
    let width = width as usize;
    let aligned = blob.len().checked_add(width - 1).ok_or_else(no_memory)? & !(width - 1);
    blob.try_reserve(aligned - blob.len())
        .map_err(|_| no_memory())?;
    blob.resize(aligned, 0);
    Ok(())
}

fn published_cells(
    p: &Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, BuiltinSym)],
) -> Result<[u64; 11], LoadError> {
    let mut cells = [0; 11];
    for (index, name) in NAMES.iter().enumerate() {
        let Some((_, symbol)) = symbols.iter().find(|(candidate, _)| candidate == name) else {
            continue;
        };
        let size = if index == 0 { 4 } else { p.arch.ptr_size() };
        let descriptor = dll
            .exports
            .iter()
            .flat_map(|table| table.iter())
            .find(|export| export.name == *name && export.archs.has(p.arch));
        let declared = match descriptor.map(|export| &export.item) {
            Some(Item::Data(DataSize::Bytes(bytes))) => u64::from(*bytes),
            Some(Item::Data(DataSize::Ptrs(words))) => u64::from(*words) * p.arch.ptr_size(),
            _ => {
                return Err(error(
                    STATUS_INVALID_IMAGE_FORMAT,
                    "CRT startup cell is not data",
                ));
            }
        };
        if declared != size {
            return Err(error(
                STATUS_INVALID_IMAGE_FORMAT,
                "CRT startup cell width mismatch",
            ));
        }
        let BuiltinSym::Rva(rva) = symbol else {
            return Err(error(
                STATUS_INVALID_IMAGE_FORMAT,
                "CRT startup data forwarder",
            ));
        };
        let at = address(p, base, u64::from(*rva), size, true).map_err(access)?;
        let last = address(p, at, size - 1, 1, true).map_err(access)?;
        if at % size != 0
            || [at, last].into_iter().any(|address| {
                p.vm.query(address).is_none_or(|region| {
                    region.allocation_base != base || region.kind != mem::IMAGE
                })
            })
        {
            return Err(error(
                STATUS_INVALID_IMAGE_FORMAT,
                "CRT startup cell outside its image",
            ));
        }
        p.space
            .probe(at, size as usize, MemoryAccessKind::Write)
            .map_err(|fault| {
                access(MemFault {
                    addr: fault.address,
                    write: true,
                })
            })?;
        cells[index] = at;
    }
    Ok(cells)
}

fn admission() -> ApiErr {
    ApiErr::Raise(ExceptionRecord::new(STATUS_NO_MEMORY, 0, Vec::new()))
}

/// Later API blobs use the same owned VM allocation contract. Admission maps
/// to the facade's errno failure; checked copy faults retain their exact access.
pub(super) fn allocate(p: &mut Proc, bytes: &[u8]) -> Result<u64, ApiErr> {
    let length = u64::try_from(bytes.len()).map_err(|_| admission())?;
    let base =
        p.vm.reserve(
            None,
            length.max(1),
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        )
        .map_err(|_| admission())?;
    let result = (|| {
        address(p, base, 0, length.max(1), true)?;
        p.vm.commit(base, length.max(1), prot::READWRITE)
            .map_err(|_| admission())?;
        p.space.wr(base, bytes)?;
        Ok(base)
    })();
    if let Err(original) = &result
        && let Err(cleanup) = p.vm.release(base)
    {
        p.fail(format!(
            "CRT startup allocation cleanup failed: {cleanup:?}; original: {original:?}"
        ));
    }
    result
}

/// Releases every recorded VM base, even if one cleanup fails. Guest edits to
/// pointer cells, vectors, or strings never redirect ownership cleanup.
pub(super) fn release(p: &mut Proc, state: StartupState) -> Result<(), LoadError> {
    let mut failure = None;
    for base in state.blocks.into_iter().rev() {
        if let Err(cleanup) = p.vm.release(base)
            && failure.is_none()
        {
            failure = Some(error(
                cleanup.status(),
                format!("cannot release CRT startup blob: {cleanup:?}"),
            ));
        }
    }
    failure.map_or(Ok(()), Err)
}

/// O(C + I + E) time/storage for command units C, image-path units I and
/// environment units E; no allocation uses an unverified environment count.
pub(super) fn prepare(
    p: &mut Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, BuiltinSym)],
) -> Result<StartupState, LoadError> {
    let (command_line, image_path, environment) = inputs(p)?;
    let cells = published_cells(p, dll, base, symbols)?;
    let width = p.arch.ptr_size();
    let mut blob = Vec::new();
    blob.try_reserve_exact(11 * width as usize)
        .map_err(|_| no_memory())?;
    blob.resize(11 * width as usize, 0);
    let command_a = narrow(&mut blob, &command_line)?;
    let command_w = wide(&mut blob, &command_line)?;
    let image_a = narrow(&mut blob, &image_path)?;
    let image_w = wide(&mut blob, &image_path)?;
    pointer_alignment(&mut blob, width)?;
    let env_vector = u64::try_from(blob.len()).map_err(|_| no_memory())?;
    let vector_bytes = environment
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_mul(width as usize))
        .ok_or_else(no_memory)?;
    blob.try_reserve(vector_bytes).map_err(|_| no_memory())?;
    let vector_end = blob.len().checked_add(vector_bytes).ok_or_else(no_memory)?;
    blob.resize(vector_end, 0);
    let mut env_strings = Vec::new();
    env_strings
        .try_reserve_exact(environment.len())
        .map_err(|_| no_memory())?;
    for units in &environment {
        env_strings.push(narrow(&mut blob, units)?);
    }
    let mut state = StartupState {
        cells,
        initial_env: [0; 2],
        blocks: Vec::new(),
        environment,
        command_line,
    };
    state.blocks.try_reserve_exact(1).map_err(|_| no_memory())?;
    let allocation = allocate(p, &blob).map_err(|failure| match failure {
        ApiErr::Fault(fault) => access(fault),
        _ => no_memory(),
    })?;
    state.blocks.push(allocation);
    let initialized = (|| {
        for (index, cell) in state.cells.iter_mut().enumerate() {
            if *cell == 0 {
                *cell = address(
                    p,
                    allocation,
                    index as u64 * width,
                    if index == 0 { 4 } else { width },
                    true,
                )
                .map_err(access)?;
            }
        }
        let env_pointer = address(p, allocation, env_vector, width, false).map_err(access)?;
        for (index, offset) in env_strings.iter().enumerate() {
            let target = address(p, allocation, *offset, 1, false).map_err(access)?;
            let at = address(p, env_pointer, index as u64 * width, width, true).map_err(access)?;
            p.space.wptr(at, width, target).map_err(access)?;
        }
        let values = [
            0,
            0,
            0,
            env_pointer,
            0,
            env_pointer,
            0,
            address(p, allocation, command_a, 1, false).map_err(access)?,
            address(p, allocation, command_w, 2, false).map_err(access)?,
            address(p, allocation, image_a, 1, false).map_err(access)?,
            address(p, allocation, image_w, 2, false).map_err(access)?,
        ];
        // Every public image cell was preflighted before allocating. Private
        // cells are in the fresh blob; no guest callback can change mappings.
        for (index, value) in values.into_iter().enumerate() {
            if index == 0 {
                p.space
                    .w32(state.cells[index], value as u32)
                    .map_err(access)?;
            } else {
                p.space
                    .wptr(state.cells[index], width, value)
                    .map_err(access)?;
            }
        }
        state.initial_env[0] = env_pointer;
        Ok(())
    })();
    if let Err(original) = initialized {
        if let Err(cleanup) = release(p, state) {
            p.fail(format!(
                "CRT startup preparation cleanup failed: {cleanup}; original: {original}"
            ));
        }
        return Err(original);
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, PAGE_SIZE, SpaceConfig};
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::heap::Heaps;
    use crate::user::windows::hle::Export;
    use crate::user::windows::memory::VirtualMemory;
    use crate::user::windows::process::WindowsConfig;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    static BAD_CELLS: &[Export] = &[Export::data("__argc", DataSize::Bytes(2))];
    static GOOD_CELLS: &[Export] = &[Export::data("__argc", DataSize::Bytes(4))];
    static BAD_DLL: BuiltinDll = BuiltinDll {
        name: "msvcrt.dll",
        display: "storage-test.dll",
        subsystem: 3,
        exports: &[BAD_CELLS],
    };
    static GOOD_DLL: BuiltinDll = BuiltinDll {
        name: "msvcrt.dll",
        display: "storage-test.dll",
        subsystem: 3,
        exports: &[GOOD_CELLS],
    };

    fn process(arch: WinArch, limit: u64) -> Proc {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 8 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        Proc {
            arch,
            vm: VirtualMemory::new_with_commit_limit(space.clone(), 0x10000, 1 << 32, limit),
            space,
            cfg: Arc::new(WindowsConfig::new(
                "ignored-config-name.exe",
                vec!["ignored-config-argument".into()],
            )),
            native: None,
            pid: 4,
            peb: 0,
            params: 0,
            ansi_command_line: None,
            process_heap: 0,
            modules: Default::default(),
            loader: Default::default(),
            fibers: Default::default(),
            traps: Default::default(),
            objects: Default::default(),
            heaps: Heaps::new(if arch.is64() { 16 } else { 8 }),
            tls: Default::default(),
            seh: Default::default(),
            sync: Default::default(),
            crt: Default::default(),
            threads: BTreeMap::new(),
            next_tid: 8,
            exit_code: None,
            failure: None,
            start_time: Instant::now(),
            rng: 1,
            cwd: vec![],
            exe_stack_reserve: 0x10000,
            exe_stack_commit: PAGE_SIZE,
        }
    }

    fn units(p: &mut Proc, value: &[u16]) -> u64 {
        let bytes: Vec<u8> = value.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        allocate(p, &bytes).unwrap()
    }

    fn counted(p: &Proc, field: u64, buffer: u64, length: u16, maximum: u16) {
        p.space.w16(field, length).unwrap();
        p.space.w16(field + 2, maximum).unwrap();
        p.space
            .wptr(field + p.arch.ptr_size(), p.arch.ptr_size(), buffer)
            .unwrap();
    }

    fn parameters(p: &mut Proc, command: &[u16], path: &[u16], env: &[u16]) {
        let o = offsets(p.arch);
        p.params = allocate(p, &vec![0; o.pp_size as usize]).unwrap();
        let command_buffer = units(p, command);
        let path_buffer = units(p, path);
        let env_buffer = units(p, env);
        counted(
            p,
            p.params + o.pp_command_line,
            command_buffer,
            (command.len() * 2) as u16,
            (command.len() * 2) as u16,
        );
        counted(
            p,
            p.params + o.pp_image_path_name,
            path_buffer,
            (path.len() * 2) as u16,
            (path.len() * 2) as u16,
        );
        p.space
            .wptr(p.params + o.pp_environment, o.ptr, env_buffer)
            .unwrap();
        p.space
            .wptr(
                p.params + o.pp_environment_size,
                o.ptr,
                env.len() as u64 * 2,
            )
            .unwrap();
    }

    fn read_bytes(p: &Proc, address: u64, count: usize) -> Vec<u8> {
        (0..count)
            .map(|offset| p.space.u8(address + offset as u64).unwrap())
            .collect()
    }

    fn value(p: &Proc, state: &StartupState, index: usize) -> u64 {
        p.space.ptr(state.cells[index], p.arch.ptr_size()).unwrap()
    }

    #[test]
    fn no_params_is_empty_input_not_config_reconstruction_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            let state = prepare(&mut p, &GOOD_DLL, 0, &[]).unwrap();
            assert!(state.command_line.is_empty());
            assert!(state.environment.is_empty());
            assert_eq!(p.space.u32(state.cells[0]).unwrap(), 0);
            for index in [1, 2, 4, 6] {
                assert_eq!(value(&p, &state, index), 0);
            }
            assert_eq!(state.initial_env[0], value(&p, &state, 3));
            assert_eq!(state.initial_env[1], 0);
            assert_eq!(value(&p, &state, 3), value(&p, &state, 5));
            assert_eq!(
                p.space.ptr(state.initial_env[0], arch.ptr_size()).unwrap(),
                0
            );
            for index in [7, 9] {
                assert_eq!(p.space.u8(value(&p, &state, index)).unwrap(), 0);
            }
            for index in [8, 10] {
                assert_eq!(p.space.u16(value(&p, &state, index)).unwrap(), 0);
            }
            assert!(p.threads.is_empty());
            release(&mut p, state).unwrap();
            assert_eq!(p.vm.committed_bytes(), 0);
        }
    }

    #[test]
    fn actual_parameters_snapshot_aliases_and_host_owned_cleanup_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            let command: Vec<u16> = "real.exe \"actual argument\"".encode_utf16().collect();
            let path: Vec<u16> = "C:\\actual\\real.exe".encode_utf16().collect();
            let env: Vec<u16> = "A=one\0=C:=C:\\actual\0\0".encode_utf16().collect();
            parameters(&mut p, &command, &path, &env);
            let before = p.vm.committed_bytes();
            let state = prepare(&mut p, &GOOD_DLL, 0, &[]).unwrap();
            assert_eq!(state.command_line, command);
            assert_eq!(state.environment.len(), 2);
            let vector = value(&p, &state, 3);
            assert_eq!(value(&p, &state, 5), vector);
            assert_eq!(state.initial_env, [vector, 0]);
            let first = p.space.ptr(vector, arch.ptr_size()).unwrap();
            let second = p
                .space
                .ptr(vector + arch.ptr_size(), arch.ptr_size())
                .unwrap();
            assert_eq!(read_bytes(&p, first, 6), b"A=one\0");
            let second_value = b"=C:=C:\\actual\0";
            assert_eq!(read_bytes(&p, second, second_value.len()), second_value);
            assert_eq!(
                p.space
                    .ptr(vector + 2 * arch.ptr_size(), arch.ptr_size())
                    .unwrap(),
                0
            );
            assert_eq!(
                read_bytes(&p, value(&p, &state, 7), command.len() + 1),
                [
                    command.iter().map(|&x| x as u8).collect::<Vec<_>>(),
                    vec![0]
                ]
                .concat()
            );
            assert_eq!(
                read_bytes(&p, value(&p, &state, 9), path.len() + 1),
                b"C:\\actual\\real.exe\0"
            );
            for (index, expected) in [(8, &command), (10, &path)] {
                let address = value(&p, &state, index);
                for (offset, &unit) in expected.iter().enumerate() {
                    assert_eq!(p.space.u16(address + offset as u64 * 2).unwrap(), unit);
                }
                assert_eq!(p.space.u16(address + expected.len() as u64 * 2).unwrap(), 0);
            }
            // The initial/current narrow environment genuinely aliases; the
            // input process block and its strings are separate snapshots.
            p.space.w8(first, b'Z').unwrap();
            assert_eq!(
                p.space
                    .u8(p.space.ptr(state.initial_env[0], arch.ptr_size()).unwrap())
                    .unwrap(),
                b'Z'
            );
            let o = offsets(arch);
            let source = p
                .space
                .ptr(p.params + o.pp_command_line + o.ptr, o.ptr)
                .unwrap();
            p.space.w16(source, b'X' as u16).unwrap();
            assert_eq!(p.space.u16(value(&p, &state, 8)).unwrap(), b'r' as u16);
            // Mutating guest cells cannot redirect the VM ownership ledger.
            let owned = state.blocks[0];
            p.space
                .wptr(state.cells[7], arch.ptr_size(), p.params)
                .unwrap();
            release(&mut p, state).unwrap();
            assert_eq!(p.vm.query(owned).unwrap().state, mem::FREE);
            assert_eq!(p.vm.committed_bytes(), before);
            assert_eq!(p.vm.query(p.params).unwrap().state, mem::COMMIT);
            assert!(p.failure.is_none());
        }
    }

    #[test]
    fn counted_utf16_at_page_end_retains_unpaired_units_without_terminator_read_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            parameters(&mut p, &[], &[], &[0, 0]);
            let page = allocate(&mut p, &vec![0; PAGE_SIZE as usize]).unwrap();
            let tail = page + PAGE_SIZE - 4;
            p.space.w16(tail, 0xD800).unwrap();
            p.space.w16(tail + 2, b'X' as u16).unwrap();
            let o = offsets(arch);
            counted(&p, p.params + o.pp_command_line, tail, 4, 4);
            assert!(p.space.u16(page + PAGE_SIZE).is_err());
            let before = p.vm.committed_bytes();
            let state = prepare(&mut p, &GOOD_DLL, 0, &[]).unwrap();
            assert_eq!(state.command_line, [0xD800, b'X' as u16]);
            let copy = value(&p, &state, 8);
            assert_eq!(p.space.u16(copy).unwrap(), 0xD800);
            assert_eq!(p.space.u16(copy + 2).unwrap(), b'X' as u16);
            assert_eq!(p.space.u16(copy + 4).unwrap(), 0);
            release(&mut p, state).unwrap();
            assert_eq!(p.vm.committed_bytes(), before);
        }
    }

    #[test]
    fn malformed_counted_metadata_never_allocates_a_candidate_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            parameters(&mut p, &[b'A' as u16], &[], &[0, 0]);
            let o = offsets(arch);
            let field = p.params + o.pp_command_line;
            let source = p.space.ptr(field + o.ptr, o.ptr).unwrap();
            let before = p.vm.committed_bytes();
            for (buffer, length, maximum) in [(source, 1, 2), (source, 2, 0), (source + 1, 2, 2)] {
                counted(&p, field, buffer, length, maximum);
                let error = prepare(&mut p, &GOOD_DLL, 0, &[]).err().unwrap();
                assert_eq!(error.status, STATUS_INVALID_PARAMETER);
                assert_eq!(p.vm.committed_bytes(), before);
                assert!(p.failure.is_none());
            }
        }
    }

    #[test]
    fn environment_bounds_faults_and_termination_are_checked_without_count_allocation_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            parameters(&mut p, &[], &[], &[b'A' as u16, 0]);
            let before = p.vm.committed_bytes();
            let error = prepare(&mut p, &GOOD_DLL, 0, &[]).err().unwrap();
            assert_eq!(error.status, STATUS_INVALID_PARAMETER);
            assert_eq!(p.vm.committed_bytes(), before);
            let o = offsets(arch);
            let page = allocate(&mut p, &vec![0; PAGE_SIZE as usize]).unwrap();
            let tail = page + PAGE_SIZE - 2;
            p.space.w16(tail, b'B' as u16).unwrap();
            p.space
                .wptr(p.params + o.pp_environment, o.ptr, tail)
                .unwrap();
            p.space
                .wptr(p.params + o.pp_environment_size, o.ptr, 4)
                .unwrap();
            let before = p.vm.committed_bytes();
            let error = prepare(&mut p, &GOOD_DLL, 0, &[]).err().unwrap();
            assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
            assert!(error.message.contains(&format!("{:#x}", page + PAGE_SIZE)));
            assert_eq!(p.vm.committed_bytes(), before);
            // An all-ones-derived even byte count is rejected by checked
            // guest address arithmetic, not used as a host Vec capacity.
            p.space
                .wptr(
                    p.params + o.pp_environment_size,
                    o.ptr,
                    arch.ptr(u64::MAX) - 1,
                )
                .unwrap();
            let error = prepare(&mut p, &GOOD_DLL, 0, &[]).err().unwrap();
            assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
            assert_eq!(p.vm.committed_bytes(), before);
            assert!(p.failure.is_none());
        }
    }

    #[test]
    fn admission_failure_releases_reservation_and_preserves_original_no_memory_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 0);
            let error = allocate(&mut p, &[1]).err().unwrap();
            assert!(matches!(error, ApiErr::Raise(record) if record.code == STATUS_NO_MEMORY));
            assert_eq!(p.vm.committed_bytes(), 0);
            assert_eq!(p.vm.query(0x10000).unwrap().state, mem::FREE);
            let error = prepare(&mut p, &GOOD_DLL, 0, &[]).err().unwrap();
            assert_eq!(error.status, STATUS_NO_MEMORY);
            assert_eq!(p.vm.query(0x10000).unwrap().state, mem::FREE);
            assert!(p.failure.is_none());
        }
    }

    #[test]
    fn public_cells_validate_kind_width_and_write_permission_before_allocation_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            let base =
                p.vm.reserve(
                    None,
                    PAGE_SIZE,
                    prot::READWRITE,
                    AllocKind::Image,
                    false,
                    None,
                )
                .unwrap();
            p.vm.commit(base, PAGE_SIZE, prot::READWRITE).unwrap();
            let symbols = [("__argc", BuiltinSym::Rva(0))];
            let before = p.vm.committed_bytes();
            let error = prepare(&mut p, &BAD_DLL, base, &symbols).err().unwrap();
            assert_eq!(error.status, STATUS_INVALID_IMAGE_FORMAT);
            assert_eq!(p.vm.committed_bytes(), before);
            p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
            let error = prepare(&mut p, &GOOD_DLL, base, &symbols).err().unwrap();
            assert_eq!(error.status, STATUS_ACCESS_VIOLATION);
            assert_eq!(p.vm.committed_bytes(), before);
            p.vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
            let state = prepare(&mut p, &GOOD_DLL, base, &symbols).unwrap();
            assert_eq!(state.cells[0], base);
            assert_eq!(p.space.u32(base).unwrap(), 0);
            release(&mut p, state).unwrap();
            assert_eq!(p.vm.committed_bytes(), before);
            assert_eq!(p.vm.query(base).unwrap().state, mem::COMMIT);
            p.vm.release(base).unwrap();
            let private = allocate(&mut p, &[0; 4]).unwrap();
            let error = prepare(&mut p, &GOOD_DLL, private, &symbols).err().unwrap();
            assert_eq!(error.status, STATUS_INVALID_IMAGE_FORMAT);
            p.vm.release(private).unwrap();
            assert_eq!(p.vm.committed_bytes(), 0);
        }
    }

    #[test]
    fn cleanup_attempts_all_owned_blocks_even_when_one_release_fails_all_abis() {
        for arch in WinArch::ALL {
            let mut p = process(arch, 8 << 20);
            let mut state = prepare(&mut p, &GOOD_DLL, 0, &[]).unwrap();
            let first = state.blocks[0];
            let second = allocate(&mut p, &[7]).unwrap();
            state.blocks.extend([0x123, second]);
            assert!(release(&mut p, state).is_err());
            assert_eq!(p.vm.query(first).unwrap().state, mem::FREE);
            assert_eq!(p.vm.query(second).unwrap().state, mem::FREE);
            assert_eq!(p.vm.committed_bytes(), 0);
        }
    }

    #[test]
    fn guest_width_addition_reports_fault_instead_of_truncating_all_abis() {
        for arch in WinArch::ALL {
            let p = process(arch, 8 << 20);
            let max = arch.ptr(u64::MAX);
            assert_eq!(address(&p, max, 0, 1, false).unwrap(), max);
            for write in [false, true] {
                let fault = address(&p, max - 1, 0, 4, write).unwrap_err();
                assert_eq!(fault.write, write);
                assert_eq!(fault.addr, if arch.is64() { u64::MAX } else { 1 << 32 });
                assert!(address(&p, max, 1, 1, write).is_err());
            }
        }
    }
}
