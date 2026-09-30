//! C API storage/state adapter for the shared AArch32 user-mode executor.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use rax_engine::cpu::{Aarch32Registers, CpuState, MemAccess, MemRecord, VCpu, VcpuExit};
use rax_engine::error::{Error, GuestMemoryFault, MemoryAccessKind, MemoryFaultKind, Result};
use rax_engine::isa::arm::instructions::ExclusiveMonitor;
use rax_engine::isa::arm::vfp::Fpscr;
use rax_engine::isa::arm::{ProcessorMode, Psr};
use rax_engine::memory::{
    FlatTranslation,
    vm::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap},
};
use rax_engine::user::cpu::arm::{A32AddressSpace, A32Exit, A32UserCpu};

use crate::user::{RAX_SYSCALL_INSN_SVC, RegionTranslation};
use crate::vcpu::UserTrap;

/// Mutable user state omitted from the architecture-neutral CPU image.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ArmUserState {
    pub tpidrurw: u32,
    pub tpidruro: u32,
    pub exclusive_address: Option<u32>,
    pub exclusive_size: u8,
}

impl ArmUserState {
    pub fn encode(self) -> [u8; 20] {
        let fields = [
            self.tpidrurw,
            self.tpidruro,
            self.exclusive_address.unwrap_or(0),
            u32::from(self.exclusive_size),
            u32::from(self.exclusive_address.is_some()),
        ];
        let mut out = [0; 20];
        for (word, value) in out.chunks_exact_mut(4).zip(fields) {
            word.copy_from_slice(&value.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 20 {
            return None;
        }
        let mut words = bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
        let tpidrurw = words.next()?;
        let tpidruro = words.next()?;
        let address = words.next()?;
        let size = words.next()?;
        let active = words.next()?;
        if active > 1
            || (active == 1 && (!matches!(size, 1 | 2 | 4 | 8) || address % size != 0))
            || (active == 0 && (address != 0 || size != 0))
        {
            return None;
        }
        Some(Self {
            tpidrurw,
            tpidruro,
            exclusive_address: (active == 1).then_some(address),
            exclusive_size: size as u8,
        })
    }
}

#[derive(Clone, Debug)]
struct RegionMemory {
    mem: Arc<GuestMemoryMmap>,
    translation: Arc<RegionTranslation>,
    recorder: Arc<Recorder>,
}

#[derive(Debug, Default)]
struct Recorder {
    enabled: AtomicBool,
    records: Mutex<Vec<MemRecord>>,
}

impl Recorder {
    fn record(&self, address: u64, bytes: &[u8], access: MemoryAccessKind) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut value = [0; 8];
        let count = bytes.len().min(value.len());
        value[..count].copy_from_slice(&bytes[..count]);
        let access = match access {
            MemoryAccessKind::Read => MemAccess::Read,
            MemoryAccessKind::Write => MemAccess::Write,
            MemoryAccessKind::Fetch => MemAccess::Exec,
        };
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(MemRecord {
                access,
                addr: address,
                size: bytes.len() as u8,
                value: if access == MemAccess::Exec {
                    0
                } else {
                    u64::from_le_bytes(value)
                },
            });
    }
}

impl RegionMemory {
    /// Validate every page before writing any byte. O(pages) time and space.
    fn spans(
        &self,
        address: u64,
        size: usize,
        access: MemoryAccessKind,
    ) -> std::result::Result<Vec<(u64, usize, usize)>, GuestMemoryFault> {
        let end = address
            .checked_add(size as u64)
            .filter(|end| *end <= 1u64 << 32)
            .ok_or_else(|| GuestMemoryFault::unmapped(address, size, access))?;
        let mut spans = Vec::new();
        let mut at = address;
        while at < end {
            let pa = self.translation.translate(at, access)?;
            let n = ((4096 - (at & 4095)).min(end - at)) as usize;
            if !self.mem.check_range(GuestAddress(pa), n) {
                return Err(GuestMemoryFault::unmapped(at, n, access));
            }
            spans.push((pa, (at - address) as usize, n));
            at += n as u64;
        }
        Ok(spans)
    }

    fn load(
        &self,
        address: u64,
        bytes: &mut [u8],
        access: MemoryAccessKind,
    ) -> std::result::Result<(), GuestMemoryFault> {
        for (pa, offset, n) in self.spans(address, bytes.len(), access)? {
            self.mem
                .read_slice(&mut bytes[offset..offset + n], GuestAddress(pa))
                .map_err(|_| GuestMemoryFault::unmapped(address + offset as u64, n, access))?;
        }
        self.recorder.record(address, bytes, access);
        Ok(())
    }
}

impl A32AddressSpace for RegionMemory {
    fn read(&self, address: u64, bytes: &mut [u8]) -> std::result::Result<(), GuestMemoryFault> {
        self.load(address, bytes, MemoryAccessKind::Read)
    }
    fn fetch(&self, address: u64, bytes: &mut [u8]) -> std::result::Result<(), GuestMemoryFault> {
        self.load(address, bytes, MemoryAccessKind::Fetch)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> std::result::Result<(), GuestMemoryFault> {
        for (pa, offset, n) in self.spans(address, bytes.len(), MemoryAccessKind::Write)? {
            self.mem
                .write_slice(&bytes[offset..offset + n], GuestAddress(pa))
                .map_err(|_| {
                    GuestMemoryFault::unmapped(address + offset as u64, n, MemoryAccessKind::Write)
                })?;
        }
        self.recorder
            .record(address, bytes, MemoryAccessKind::Write);
        Ok(())
    }
}

pub(crate) struct ArmUserVcpu {
    cpu: A32UserCpu<RegionMemory>,
    trap: Option<UserTrap>,
    count: u64,
}

impl ArmUserVcpu {
    pub fn new(
        mem: Arc<GuestMemoryMmap>,
        translation: Arc<RegionTranslation>,
        thumb: bool,
    ) -> Self {
        let mut cpu = A32UserCpu::new(&RegionMemory {
            mem,
            translation,
            recorder: Arc::default(),
        });
        cpu.core_mut().cpsr.t = thumb;
        Self {
            cpu,
            trap: None,
            count: 0,
        }
    }

    pub fn take_trap(&mut self) -> Option<UserTrap> {
        self.trap.take()
    }

    pub fn user_state(&self) -> ArmUserState {
        let monitor = self.cpu.exclusive_monitor();
        ArmUserState {
            tpidrurw: self.cpu.core().cp15.tpidrurw,
            tpidruro: self.cpu.core().cp15.tpidruro,
            exclusive_address: monitor.address,
            exclusive_size: if monitor.address.is_some() {
                monitor.size
            } else {
                0
            },
        }
    }

    pub fn set_user_state(&mut self, state: ArmUserState) {
        self.cpu.core_mut().cp15.tpidrurw = state.tpidrurw;
        self.cpu.core_mut().cp15.tpidruro = state.tpidruro;
        self.cpu.set_exclusive_monitor(ExclusiveMonitor {
            address: state.exclusive_address,
            size: state.exclusive_size,
        });
    }
}

impl VCpu for ArmUserVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        loop {
            if let Some(exit) = self.step_insn()? {
                return Ok(exit);
            }
        }
    }
    fn supports_stepping(&self) -> bool {
        true
    }
    fn supports_mem_hooks(&self) -> bool {
        true
    }
    fn set_mem_recording(&mut self, on: bool) {
        let recorder = &self.cpu.space().recorder;
        recorder.enabled.store(on, Ordering::Relaxed);
        if !on {
            recorder
                .records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
    }
    fn drain_mem_records(&mut self, out: &mut Vec<MemRecord>) {
        out.append(
            &mut self
                .cpu
                .space()
                .recorder
                .records
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
    }
    fn current_pc(&self) -> u64 {
        u64::from(self.cpu.core().regs[15])
    }
    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        let pc = u32::try_from(pc)
            .map_err(|_| Error::InvalidConfig("AArch32 PC exceeds 32 bits".into()))?;
        let mask = if self.cpu.thumb() { !1 } else { !3 };
        self.cpu.core_mut().regs[15] = pc & mask;
        Ok(())
    }
    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.trap = None;
        let thumb = self.cpu.thumb();
        match self.cpu.step_instruction() {
            None | Some(A32Exit::Yield) => {
                self.count += 1;
                Ok(None)
            }
            Some(A32Exit::Svc { imm, pc }) => {
                self.count += 1;
                self.trap = Some(UserTrap::Syscall {
                    pc,
                    len: if thumb { 2 } else { 4 },
                    insn: RAX_SYSCALL_INSN_SVC,
                    imm,
                });
                Ok(Some(VcpuExit::SystemCall))
            }
            Some(A32Exit::Bkpt { imm, pc }) => {
                // ESR_EL1.EC=0x38: BKPT in AArch32; ISS[15:0] is the comment.
                self.trap = Some(UserTrap::Exception {
                    vector: 0x38,
                    pc,
                    return_pc: pc,
                    syndrome: Some(u64::from(imm)),
                    software: true,
                    undefined: false,
                });
                Ok(Some(VcpuExit::Exception(0x38)))
            }
            Some(A32Exit::Undefined { pc, reason, .. }) => {
                self.trap = Some(UserTrap::Exception {
                    vector: 0,
                    pc,
                    return_pc: pc,
                    syndrome: Some(0),
                    software: false,
                    undefined: true,
                });
                Err(Error::InvalidInstruction {
                    pc,
                    diagnosis: reason,
                })
            }
            Some(A32Exit::Fault(fault)) => Err(Error::GuestAccess(GuestMemoryFault {
                address: fault.addr,
                size: 0,
                access: fault.access,
                kind: match fault.kind {
                    rax_engine::user::cpu::AccessFaultKind::Unmapped => MemoryFaultKind::Unmapped,
                    rax_engine::user::cpu::AccessFaultKind::Permission => {
                        MemoryFaultKind::Permission
                    }
                    _ => MemoryFaultKind::Other,
                },
            })),
            Some(A32Exit::Internal(message)) => Err(Error::Emulator(message)),
        }
    }
    fn translate_addr(&mut self, address: u64, access: MemAccess) -> Result<u64> {
        let access = match access {
            MemAccess::Read => MemoryAccessKind::Read,
            MemAccess::Write => MemoryAccessKind::Write,
            MemAccess::Exec => MemoryAccessKind::Fetch,
        };
        if address > u32::MAX as u64 {
            return Err(Error::GuestAccess(GuestMemoryFault::unmapped(
                address, 0, access,
            )));
        }
        self.cpu
            .space()
            .translation
            .translate(address, access)
            .map_err(Error::GuestAccess)
    }
    fn get_state(&self) -> Result<CpuState> {
        let core = self.cpu.core();
        let mut regs = Aarch32Registers::default();
        regs.r.copy_from_slice(&core.regs[..13]);
        regs.sp = core.regs[13];
        regs.lr = core.regs[14];
        regs.pc = core.regs[15];
        regs.cpsr = core.cpsr.to_u32();
        regs.fpscr = core.vfp.fpscr.bits();
        for i in 0..32 {
            regs.s[i] = core.vfp.read_s_bits(i as u8);
        }
        for i in 0..16 {
            regs.d_high[i] = core.vfp.read_d_bits((16 + i) as u8);
        }
        Ok(CpuState::aarch32(regs, Default::default()))
    }
    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let CpuState::Aarch32(state) = state else {
            return Err(Error::InvalidConfig("expected AArch32 user state".into()));
        };
        let core = self.cpu.core_mut();
        core.regs[..13].copy_from_slice(&state.regs.r);
        core.regs[13] = state.regs.sp;
        core.regs[14] = state.regs.lr;
        core.regs[15] = state.regs.pc;
        core.cpsr = Psr::from_u32(state.regs.cpsr);
        core.cpsr.mode = ProcessorMode::User as u8;
        core.cpsr.e = false;
        core.cpsr.a = false;
        core.cpsr.i = false;
        core.cpsr.f = false;
        core.vfp.fpscr = Fpscr::from_bits(state.regs.fpscr);
        for i in 0..32 {
            core.vfp.write_s_bits(i as u8, state.regs.s[i]);
        }
        for i in 0..16 {
            core.vfp.write_d_bits((16 + i) as u8, state.regs.d_high[i]);
        }
        self.trap = None;
        Ok(())
    }
    fn complete_io_in(&mut self, _data: &[u8]) {}
    fn id(&self) -> u32 {
        0
    }
    fn instruction_count(&self) -> u64 {
        self.count
    }
}
