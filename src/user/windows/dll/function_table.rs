//! Active function-table registration and lookup for 64-bit structured exception handling.

use super::super::hle::{ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;
use super::super::seh::dynamic;
use super::super::seh::unwind;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "RtlAddFunctionTable",
        Stdcall,
        &[Ptr, I32, Ptr],
        add_function_table,
    )
    .only(Archs::WIN64),
    Export::func(
        "RtlDeleteFunctionTable",
        Stdcall,
        &[Ptr],
        delete_function_table,
    )
    .only(Archs::WIN64),
    Export::func(
        "RtlLookupFunctionEntry",
        Stdcall,
        &[I64, Ptr, Ptr],
        lookup_function_entry,
    )
    .only(Archs::WIN64),
];

fn add_function_table(c: &mut Ctx) -> ApiResult {
    let (pointer, count, base) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    Flow::bool(dynamic::register(c.p, pointer, count, base)?)
}

fn delete_function_table(c: &mut Ctx) -> ApiResult {
    let pointer = c.ptr(0)?;
    Flow::bool(dynamic::delete(c.p, pointer))
}

fn lookup_function_entry(c: &mut Ctx) -> ApiResult {
    let (control_pc, image_base, history_table) = (c.arg(0)?, c.ptr(1)?, c.ptr(2)?);
    if history_table != 0 {
        return Err(c.unsupported("non-null HistoryTable"));
    }
    let Some(entry) = unwind::lookup(c.p, control_pc)? else {
        // RAX miss policy: do not write ImageBase when no entry exists.
        return Flow::ret(0);
    };
    c.mem().w64(image_base, entry.image_base)?;
    Flow::ret(entry.entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::image::pe::DataDirectory;
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::arch::WinArch;
    use crate::user::windows::hle::{Api, ApiErr, Item, Value};
    use crate::user::windows::memory::{Mem, mem, prot};
    use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};

    fn with_process(arch: WinArch, test: impl FnOnce(&mut Proc, &mut Thread)) {
        let image: &[u8] = match arch {
            WinArch::X64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
            WinArch::X86 => unreachable!(),
        };
        let mut config = WindowsConfig::new("function-table-lookup.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        test(p, &mut thread);
    }

    fn api(name: &str, arch: WinArch) -> &'static Api {
        EXPORTS
            .iter()
            .find(|export| export.name == name && export.archs.has(arch))
            .and_then(|export| match &export.item {
                Item::Func(api) => Some(api),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {arch:?} export {name}"))
    }

    fn invoke(p: &mut Proc, t: &mut Thread, name: &str, args: [u64; 3]) -> ApiResult {
        let api = api(name, p.arch);
        for (i, value) in args.into_iter().enumerate() {
            t.cpu.set_gpr(
                if p.arch == WinArch::X64 {
                    [1, 2, 8][i]
                } else {
                    i
                },
                value,
            );
        }
        let sp = t.cpu.sp();
        (api.imp)(&mut Ctx {
            p,
            t,
            api,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        })
    }

    fn pointer(flow: Flow) -> u64 {
        match flow {
            Flow::Ret(Value::Int(value)) => value,
            _ => panic!("function-table export must return a pointer/integer"),
        }
    }

    fn page(p: &mut Proc) -> u64 {
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0
    }

    fn entry(p: &Proc, table: u64, arch: WinArch) {
        p.space.w32(table, 0x20).unwrap();
        if arch == WinArch::X64 {
            p.space.w32(table + 4, 0x60).unwrap();
            p.space.w32(table + 8, 0x100).unwrap();
        } else {
            // ARM64 packed function, 0x40-byte length, flag 1.
            p.space.w32(table + 4, 1 | ((0x40 / 4) << 2)).unwrap();
        }
    }

    #[test]
    fn lookup_static_entry_returns_guest_pointer_and_writes_image_base_both_abis() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_process(arch, |p, t| {
                let base = p.modules.exe().base;
                let size = p.modules.exe().size;
                let table = base + 0x1000;
                p.vm.protect(base, size, prot::READWRITE).unwrap();
                entry(p, table, arch);
                p.modules.list[0].pdata = DataDirectory {
                    rva: 0x1000,
                    size: if arch == WinArch::X64 { 12 } else { 8 },
                };
                let output = page(p);
                p.space.w64(output, u64::MAX).unwrap();
                assert_eq!(
                    pointer(
                        invoke(p, t, "RtlLookupFunctionEntry", [base + 0x30, output, 0]).unwrap()
                    ),
                    table,
                    "{arch:?}"
                );
                assert_eq!(p.space.u64(output).unwrap(), base);
            });
        }
    }

    #[test]
    fn lookup_dynamic_entry_before_add_and_after_delete_is_miss_both_abis() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_process(arch, |p, t| {
                let code = page(p);
                let table = page(p);
                let output = page(p);
                let sentinel = 0xA1B2_C3D4_E5F6_0718;
                entry(p, table, arch);
                p.space.w64(output, sentinel).unwrap();
                let args = [code + 0x30, output, 0];
                assert_eq!(
                    pointer(invoke(p, t, "RtlLookupFunctionEntry", args).unwrap()),
                    0
                );
                assert_eq!(p.space.u64(output).unwrap(), sentinel);
                assert_eq!(
                    pointer(invoke(p, t, "RtlAddFunctionTable", [table, 1, code]).unwrap()),
                    1
                );
                assert_eq!(
                    pointer(invoke(p, t, "RtlLookupFunctionEntry", args).unwrap()),
                    table
                );
                assert_eq!(p.space.u64(output).unwrap(), code);
                assert_eq!(
                    pointer(invoke(p, t, "RtlDeleteFunctionTable", [table, 0, 0]).unwrap()),
                    1
                );
                p.space.w64(output, sentinel).unwrap();
                assert_eq!(
                    pointer(invoke(p, t, "RtlLookupFunctionEntry", args).unwrap()),
                    0
                );
                assert_eq!(p.space.u64(output).unwrap(), sentinel);
            });
        }
    }

    #[test]
    fn lookup_output_write_fault_is_atomic_and_miss_does_not_write_both_abis() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_process(arch, |p, t| {
                let code = page(p);
                let table = page(p);
                entry(p, table, arch);
                assert_eq!(
                    pointer(invoke(p, t, "RtlAddFunctionTable", [table, 1, code]).unwrap()),
                    1
                );
                let (buffer, _) =
                    p.vm.allocate(
                        None,
                        2 * PAGE_SIZE,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap();
                let output = buffer + PAGE_SIZE - 4;
                p.space.w32(output, 0x5A5A_5A5A).unwrap();
                p.vm.protect(buffer + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
                let Err(ApiErr::Fault(fault)) =
                    invoke(p, t, "RtlLookupFunctionEntry", [code + 0x30, output, 0])
                else {
                    panic!("lookup hit must fault on inaccessible ImageBase output")
                };
                assert_eq!((fault.addr, fault.write), (buffer + PAGE_SIZE, true));
                assert_eq!(p.space.u32(output).unwrap(), 0x5A5A_5A5A);
                assert_eq!(
                    pointer(
                        invoke(p, t, "RtlLookupFunctionEntry", [code + 0x80, output, 0]).unwrap()
                    ),
                    0
                );
                assert_eq!(p.space.u32(output).unwrap(), 0x5A5A_5A5A);
            });
        }
    }

    #[test]
    fn lookup_nonnull_history_is_rejected_without_output_mutation_both_abis() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_process(arch, |p, t| {
                let output = page(p);
                p.space.w64(output, 0x1122_3344_5566_7788).unwrap();
                let result = invoke(p, t, "RtlLookupFunctionEntry", [0, output, u64::MAX]);
                assert!(
                    matches!(result, Err(ApiErr::Unimplemented(message)) if message.contains("HistoryTable"))
                );
                assert_eq!(p.space.u64(output).unwrap(), 0x1122_3344_5566_7788);
            });
        }
    }

    #[test]
    fn lookup_export_exists_only_on_64_bit_kernel_hosts() {
        for name in ["kernel32.dll", "kernelbase.dll"] {
            let dll = super::super::find(name).unwrap();
            for arch in WinArch::ALL {
                let present = dll
                    .exports
                    .iter()
                    .flat_map(|table| table.iter())
                    .any(|export| {
                        export.name == "RtlLookupFunctionEntry" && export.archs.has(arch)
                    });
                assert_eq!(present, arch != WinArch::X86, "{name} {arch:?}");
            }
        }
    }
}
