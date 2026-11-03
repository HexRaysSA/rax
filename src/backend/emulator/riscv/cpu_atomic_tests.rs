//! Actual shared backend harts must serialize the whole AMO, not two accesses.
use super::*;
use std::sync::Barrier;

struct WriteAdmission(Barrier);

impl FlatTranslation for WriteAdmission {
    fn translate(
        &self,
        address: u64,
        access: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        // Under the predecessor both harts have read the old operand before
        // reaching write admission. An indivisible implementation admits the
        // write before taking its RAM lock and reading the operand.
        if address == 0x800 && access == MemoryAccessKind::Write {
            self.0.wait();
        }
        Ok(address)
    }
}

fn two_hart_increment(native: bool) {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    let schedule = Arc::new(WriteAdmission(Barrier::new(2)));
    let mut harts = Vec::new();
    for id in 0..2u32 {
        let pc = u64::from(id) * 0x100;
        // AMOADD.W a1,a2,(a0).
        memory
            .write_slice(&0x00c5_25afu32.to_le_bytes(), GuestAddress(pc))
            .unwrap();
        let mut hart =
            RiscVVcpu::new_user(id, memory.clone(), RiscVConfig::rv64gc(), schedule.clone());
        let CpuState::RiscV(mut state) = hart.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = pc;
        state.regs.x[10] = 0x800;
        state.regs.x[12] = 1;
        hart.set_state(&CpuState::RiscV(state)).unwrap();
        harts.push(hart);
    }
    let workers: Vec<_> = harts
        .into_iter()
        .map(|mut hart| {
            std::thread::spawn(move || {
                #[cfg(all(
                    feature = "smir-jit",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                if native {
                    assert_eq!(
                        hart.cpu.step_jit(crate::smir::optimize::OptLevel::O0),
                        RiscVExit::Continue
                    );
                    assert_eq!(hart.cpu.jit_stats().native_executions, 1);
                    assert_eq!(hart.cpu.jit_stats().interpreter_fallbacks, 0);
                    return hart.cpu.x(11);
                }
                assert!(!native);
                assert!(hart.step_insn().unwrap().is_none());
                hart.cpu.x(11)
            })
        })
        .collect();
    let mut old: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    old.sort_unstable();
    assert_eq!(
        memory.read_obj::<u32>(GuestAddress(0x800)).unwrap(),
        2,
        "two AMOADD.W operations must retain both increments"
    );
    assert_eq!(old, [0, 1], "one indivisible read/modify/write per hart");
}

#[test]
fn direct_shared_amo_retains_both_causally_ordered_increments() {
    two_hart_increment(false);
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn native_shared_amo_retains_both_causally_ordered_increments() {
    two_hart_increment(true);
}

struct Identity;
impl FlatTranslation for Identity {
    fn translate(
        &self,
        address: u64,
        _: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        Ok(address)
    }
}

fn modes() -> Vec<Option<u8>> {
    let mut modes = vec![None];
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    modes.extend([Some(0), Some(1), Some(2)]);
    modes
}

fn step(hart: &mut RiscVVcpu, mode: Option<u8>) -> RiscVExit {
    #[cfg(all(
        feature = "smir-jit",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if let Some(level) = mode {
        use crate::smir::optimize::OptLevel;
        let before = hart.cpu.jit_stats().native_executions;
        let result = hart.cpu.step_jit(match level {
            0 => OptLevel::O0,
            1 => OptLevel::O1,
            2 => OptLevel::O2,
            _ => unreachable!(),
        });
        assert_eq!(hart.cpu.jit_stats().native_executions, before + 1);
        assert_eq!(hart.cpu.jit_stats().interpreter_fallbacks, 0);
        return result;
    }
    assert!(mode.is_none());
    hart.cpu.step()
}

fn hart(memory: Arc<GuestMemoryMmap>, kind: u8, rv32: bool) -> RiscVVcpu {
    let config = if rv32 {
        RiscVConfig::rv32(crate::isa::riscv::Isa::rv64gc())
    } else {
        RiscVConfig::rv64gc()
    };
    match kind {
        0 => RiscVVcpu::new_with_config(0, memory, config),
        1 => RiscVVcpu::new_embedded(0, memory, config),
        2 => RiscVVcpu::new_user(0, memory, config, Arc::new(Identity)),
        _ => unreachable!(),
    }
}

fn word(operation: u32, width: u32, ordering: u32) -> u32 {
    (operation << 27) | (ordering << 25) | (12 << 20) | (10 << 15) | (width << 12) | (6 << 7) | 0x2f
}

#[test]
fn shared_amo_widths_signedness_orderings_and_all_ram_adapters() {
    // ISA 20250508 13.4: old = signed minimum + 1, source = signed maximum.
    // This distinguishes signed/unsigned extrema, carry, and word extension.
    for (rv32, width, size) in [(true, 2, 4), (false, 2, 4), (false, 3, 8)] {
        let sign = 1u64 << (size * 8 - 1);
        let mask = if size == 4 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let old = sign + 1;
        let source = sign - 1;
        for (operation, expected) in [
            (0, 0),
            (1, source),
            (4, mask ^ 1),
            (8, mask),
            (12, 1),
            (16, old),
            (20, source),
            (24, source),
            (28, old),
        ] {
            for kind in 0..3 {
                for ordering in 0..4 {
                    for mode in modes() {
                        let memory = Arc::new(
                            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap(),
                        );
                        memory
                            .write_obj(word(operation, width, ordering), GuestAddress(0x100))
                            .unwrap();
                        memory
                            .write_slice(&old.to_le_bytes()[..size], GuestAddress(0x800))
                            .unwrap();
                        let mut cpu = hart(memory.clone(), kind, rv32);
                        cpu.cpu.set_pc(0x100);
                        cpu.cpu.set_x(10, 0x800);
                        cpu.cpu.set_x(12, source);
                        assert_eq!(
                            step(&mut cpu, mode),
                            RiscVExit::Continue,
                            "rv32={rv32}, width={width}, op={operation}, kind={kind}, order={ordering}, mode={mode:?}"
                        );
                        let returned = if !rv32 && size == 4 {
                            old as u32 as i32 as i64 as u64
                        } else {
                            old
                        };
                        assert_eq!(cpu.cpu.x(6), returned);
                        let mut bytes = [0; 8];
                        memory
                            .read_slice(&mut bytes[..size], GuestAddress(0x800))
                            .unwrap();
                        assert_eq!(u64::from_le_bytes(bytes), expected);
                        assert_eq!((cpu.cpu.pc(), cpu.cpu.instret()), (0x104, 1));
                    }
                }
            }
        }
    }
}

#[test]
fn contended_shared_add_returns_each_old_value_once_across_map_views() {
    for mode in modes() {
        let shared =
            Arc::new(vm_memory::GuestRegionMmap::from_range(GuestAddress(0), 4096, None).unwrap());
        let extra = Arc::new(
            vm_memory::GuestRegionMmap::from_range(GuestAddress(0x2000), 4096, None).unwrap(),
        );
        let memory = Arc::new(GuestMemoryMmap::from_arc_regions(vec![shared.clone()]).unwrap());
        memory
            .write_obj(word(0, 3, 3), GuestAddress(0x100))
            .unwrap();
        let view = Arc::new(GuestMemoryMmap::from_arc_regions(vec![shared, extra]).unwrap());
        let start = Arc::new(Barrier::new(4));
        let workers = (0..4)
            .map(|id| {
                let mem = if id & 1 == 0 {
                    memory.clone()
                } else {
                    view.clone()
                };
                let start = start.clone();
                std::thread::spawn(move || {
                    let mut cpu = hart(mem, id % 3, false);
                    cpu.cpu.set_x(10, 0x800);
                    cpu.cpu.set_x(12, 1);
                    let mut old = Vec::new();
                    start.wait();
                    for _ in 0..64 {
                        cpu.cpu.set_pc(0x100);
                        assert_eq!(step(&mut cpu, mode), RiscVExit::Continue);
                        old.push(cpu.cpu.x(6));
                    }
                    old
                })
            })
            .collect::<Vec<_>>();
        let mut old = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect::<Vec<_>>();
        old.sort_unstable();
        assert_eq!(old, (0..256).collect::<Vec<u64>>(), "mode={mode:?}");
        assert_eq!(memory.read_obj::<u64>(GuestAddress(0x800)).unwrap(), 256);
    }
}

#[test]
fn contended_cas_has_one_winner_at_every_width_including_rv32_pairs() {
    for (rv32, width, size) in [
        (true, 2, 4),
        (true, 3, 8),
        (false, 2, 4),
        (false, 3, 8),
        (false, 4, 16),
    ] {
        for mode in modes() {
            let memory =
                Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
            memory
                .write_obj(word(5, width, 3), GuestAddress(0x100))
                .unwrap();
            let start = Arc::new(Barrier::new(4));
            let workers = (0..4)
                .map(|id| {
                    let memory = memory.clone();
                    let start = start.clone();
                    std::thread::spawn(move || {
                        let mut cpu = hart(memory, id % 3, rv32);
                        cpu.cpu.set_pc(0x100);
                        cpu.cpu.set_x(10, 0x800);
                        cpu.cpu.set_x(12, u64::from(id + 1));
                        start.wait();
                        assert_eq!(step(&mut cpu, mode), RiscVExit::Continue);
                        (id + 1, cpu.cpu.x(6), cpu.cpu.x(7))
                    })
                })
                .collect::<Vec<_>>();
            let results = workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .collect::<Vec<_>>();
            let winners = results
                .iter()
                .filter(|(_, old, high)| *old == 0 && *high == 0)
                .collect::<Vec<_>>();
            assert_eq!(
                winners.len(),
                1,
                "rv32={rv32}, width={width}, mode={mode:?}: {results:?}"
            );
            let winner = u64::from(winners[0].0);
            assert!(
                results
                    .iter()
                    .all(|(_, old, high)| (*old == 0 || *old == winner) && *high == 0)
            );
            let mut bytes = [0; 16];
            memory
                .read_slice(&mut bytes[..size], GuestAddress(0x800))
                .unwrap();
            assert_eq!(u128::from_le_bytes(bytes), u128::from(winner));
        }
    }
}

#[test]
fn shared_same_value_rmw_and_cas_hit_invalidate_lr_but_cas_miss_omits_store() {
    use crate::isa::riscv::memory::AtomicOp;
    for kind in 0..3 {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
        let observer = MemoryDomain::for_memory(&memory).register();
        let mut cpu = hart(memory.clone(), kind, false);
        for (op, invalidates) in [
            (AtomicOp::Add(0), true),
            (
                AtomicOp::CompareExchange {
                    expected: 0,
                    replacement: 0,
                },
                true,
            ),
            (
                AtomicOp::CompareExchange {
                    expected: 1,
                    replacement: 2,
                },
                false,
            ),
        ] {
            observer.read_exclusive(&memory, 0x800, 8).unwrap();
            assert_eq!(cpu.cpu.memory_mut().atomic(0x800, 8, op).unwrap(), 0);
            assert_eq!(
                observer.write_exclusive(&memory, 0x800, &[0; 8]).unwrap(),
                !invalidates
            );
        }
    }
}

#[test]
fn uart_atomic_rejection_and_htif_publication_preserve_effect_boundaries() {
    use crate::isa::riscv::memory::AtomicOp;
    let memory = Arc::new(
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(UART_BASE), 4096)])
            .unwrap(),
    );
    let mut cpu = hart(memory.clone(), 0, false);
    for size in [4, 8, 16] {
        assert!(
            cpu.cpu
                .memory_mut()
                .atomic(
                    UART_BASE,
                    size,
                    AtomicOp::CompareExchange {
                        expected: 0,
                        replacement: 1
                    }
                )
                .is_err()
        );
    }
    assert!(cpu.pending.lock().unwrap().is_empty());
    assert_eq!(memory.read_obj::<u64>(GuestAddress(UART_BASE)).unwrap(), 0);
    *cpu.tohost_addr.lock().unwrap() = Some(0x800);
    assert_eq!(
        cpu.cpu
            .memory_mut()
            .atomic(
                0x800,
                8,
                AtomicOp::CompareExchange {
                    expected: 2,
                    replacement: 1
                }
            )
            .unwrap(),
        0
    );
    assert!(cpu.pending.lock().unwrap().is_empty());
    assert_eq!(
        cpu.cpu
            .memory_mut()
            .atomic(0x800, 8, AtomicOp::Exchange(1))
            .unwrap(),
        0
    );
    assert!(matches!(
        cpu.pending.lock().unwrap().pop_front(),
        Some(PendingEvent::Shutdown)
    ));
    assert!(cpu.pending.lock().unwrap().is_empty());
    let mut embedded = hart(memory.clone(), 1, false);
    assert_eq!(
        embedded
            .cpu
            .memory_mut()
            .atomic(UART_BASE, 8, AtomicOp::Add(1))
            .unwrap(),
        0
    );
    assert_eq!(memory.read_obj::<u64>(GuestAddress(UART_BASE)).unwrap(), 1);
}

struct AccessProfile {
    read: bool,
    write: bool,
    different_backing: bool,
}
impl FlatTranslation for AccessProfile {
    fn translate(
        &self,
        address: u64,
        access: MemoryAccessKind,
    ) -> std::result::Result<u64, GuestMemoryFault> {
        let allowed = match access {
            MemoryAccessKind::Read => self.read,
            MemoryAccessKind::Write => self.write,
            MemoryAccessKind::Fetch => true,
        };
        if !allowed {
            return Err(GuestMemoryFault {
                address,
                size: 1,
                access,
                kind: crate::error::MemoryFaultKind::Permission,
            });
        }
        Ok(address - 0x1000
            + if self.different_backing && access == MemoryAccessKind::Write {
                0x100
            } else {
                0
            })
    }
}

#[test]
fn translated_atomic_faults_retain_virtual_address_width_and_write_access() {
    use crate::isa::riscv::memory::AtomicOp;
    for size in [4u8, 8, 16] {
        for (read, write, different_backing) in [
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let memory =
                Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
            let mut bridge = UserBridge {
                exclusive: MemoryDomain::for_memory(&memory).register(),
                mem: memory.clone(),
                translation: Arc::new(AccessProfile {
                    read,
                    write,
                    different_backing,
                }),
                last_fault: Arc::new(Mutex::new(None)),
            };
            assert!(
                bridge
                    .atomic(
                        0x1800,
                        size,
                        AtomicOp::CompareExchange {
                            expected: 1,
                            replacement: 2
                        }
                    )
                    .is_err()
            );
            let fault = bridge.last_fault.lock().unwrap().unwrap();
            assert_eq!(
                (fault.address, fault.size, fault.access),
                (0x1800, u32::from(size), MemoryAccessKind::Write)
            );
            assert_eq!(
                fault.kind,
                if different_backing {
                    crate::error::MemoryFaultKind::Unmapped
                } else {
                    crate::error::MemoryFaultKind::Permission
                }
            );
            assert_eq!(memory.read_obj::<u128>(GuestAddress(0x800)).unwrap(), 0);
            assert_eq!(memory.read_obj::<u128>(GuestAddress(0x900)).unwrap(), 0);
        }
    }
}

#[test]
fn last_aligned_atomic_operand_and_fragmented_backing_are_admitted_whole() {
    use crate::isa::riscv::memory::AtomicOp;
    for fragmented in [false, true] {
        let ranges = if fragmented {
            vec![(GuestAddress(0), 4088), (GuestAddress(4088), 8)]
        } else {
            vec![(GuestAddress(0), 4096)]
        };
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&ranges).unwrap());
        let mut cpu = hart(memory.clone(), 2, false);
        for size in [4u8, 8, 16] {
            let address = 4096 - u64::from(size);
            memory
                .write_slice(&[0; 16][..usize::from(size)], GuestAddress(address))
                .unwrap();
            assert_eq!(
                cpu.cpu
                    .memory_mut()
                    .atomic(
                        address,
                        size,
                        AtomicOp::CompareExchange {
                            expected: 0,
                            replacement: 0x1234
                        }
                    )
                    .unwrap(),
                0
            );
            let mut bytes = [0; 16];
            memory
                .read_slice(&mut bytes[..usize::from(size)], GuestAddress(address))
                .unwrap();
            assert_eq!(u128::from_le_bytes(bytes), 0x1234);
        }
    }
}
