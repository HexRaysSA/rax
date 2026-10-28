//! Apple Hypervisor.framework ARM64 backend implementation.
//!
//! This backend uses Apple's Hypervisor.framework to provide hardware-accelerated
//! virtualization for AArch64 guests on Apple Silicon Macs.
//!
//! Note: This is only compiled on aarch64 macOS targets.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::any::Any;
use std::ptr;
use std::sync::{Arc, Mutex};

use tracing::{debug, info, warn};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::error::{Error, Result};
use crate::vm::memory::GuestMemoryWrapper;
use crate::vm::vcpu::{
    Aarch64CpuState, Aarch64Registers, Aarch64SystemRegisters, CpuState, VCpu, VcpuExit,
};

use super::arm64_bindings::*;
use super::{Backend, Vm};

#[path = "arm64_stack.rs"]
mod stack;
#[path = "arm64_state.rs"]
mod state;

/// ARM64 HVF backend.
pub struct HvfArm64Backend;

impl HvfArm64Backend {
    pub fn new() -> Result<Self> {
        // Check if ARM64 HVF is available
        if let Err(msg) = hv_arm64_check_available() {
            return Err(Error::InvalidConfig(msg.to_string()));
        }

        info!("ARM64 HVF backend initialized for Apple Silicon");
        Ok(HvfArm64Backend)
    }
}

impl Backend for HvfArm64Backend {
    fn name(&self) -> &'static str {
        "hvf-arm64"
    }

    fn create_vm(&self) -> Result<Box<dyn Vm>> {
        // Create VM (NULL config for default settings)
        let ret = unsafe { hv_vm_create(ptr::null()) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to create ARM64 VM: {}",
                hv_error_string(ret)
            )));
        }

        // Create the in-kernel GICv3 before any vCPU exists. Linux requires an
        // interrupt controller; HVF's in-kernel GIC handles the distributor and
        // redistributor MMIO plus the ICC system registers, and wires the
        // virtual timer to PPI 27.
        let gic_config = unsafe { hv_gic_config_create() };
        if gic_config.is_null() {
            unsafe { hv_vm_destroy() };
            return Err(Error::Emulator(
                "hv_gic_config_create failed (requires macOS 15+)".to_string(),
            ));
        }
        let ret = unsafe {
            hv_gic_config_set_distributor_base(
                gic_config,
                crate::machine::arm_virt::AARCH64_GICD_BASE,
            )
        };
        if ret != HV_SUCCESS {
            unsafe { hv_vm_destroy() };
            return Err(Error::Emulator(format!(
                "hv_gic_config_set_distributor_base({:#x}) failed: {}",
                crate::machine::arm_virt::AARCH64_GICD_BASE,
                hv_error_string(ret)
            )));
        }
        let ret = unsafe {
            hv_gic_config_set_redistributor_base(
                gic_config,
                crate::machine::arm_virt::AARCH64_GICR_BASE,
            )
        };
        if ret != HV_SUCCESS {
            unsafe { hv_vm_destroy() };
            return Err(Error::Emulator(format!(
                "hv_gic_config_set_redistributor_base({:#x}) failed: {}",
                crate::machine::arm_virt::AARCH64_GICR_BASE,
                hv_error_string(ret)
            )));
        }
        let ret = unsafe { hv_gic_create(gic_config) };
        if ret != HV_SUCCESS {
            unsafe { hv_vm_destroy() };
            return Err(Error::Emulator(format!(
                "Failed to create in-kernel GICv3: {}",
                hv_error_string(ret)
            )));
        }

        let (mut dist_size, mut redist_size) = (0usize, 0usize);
        unsafe {
            hv_gic_get_distributor_size(&mut dist_size);
            hv_gic_get_redistributor_region_size(&mut redist_size);
        }
        info!(
            gicd_base = format!("{:#x}", crate::machine::arm_virt::AARCH64_GICD_BASE),
            gicr_base = format!("{:#x}", crate::machine::arm_virt::AARCH64_GICR_BASE),
            dist_size = format!("{:#x}", dist_size),
            redist_region_size = format!("{:#x}", redist_size),
            "Created ARM64 HVF VM with in-kernel GICv3"
        );

        Ok(Box::new(HvfArm64Vm {
            memory_mapped: Mutex::new(false),
        }))
    }
}

/// ARM64 HVF VM instance.
pub struct HvfArm64Vm {
    /// Whether memory has been mapped
    memory_mapped: Mutex<bool>,
}

fn checked_arm_ram_mapping(
    region_start: u64,
    region_len: u64,
    ram_base: u64,
    ram_size: u64,
) -> Result<(u64, usize, usize)> {
    let ram_end = ram_base.checked_add(ram_size).ok_or_else(|| {
        Error::InvalidConfig(format!(
            "ARM RAM window {:#x} + {:#x} overflows guest address space",
            ram_base, ram_size
        ))
    })?;

    if region_start != 0 || ram_end > region_len {
        return Err(Error::InvalidConfig(format!(
            "guest memory region (start {:#x}, len {:#x}) does not cover ARM RAM window {:#x}..{:#x}",
            region_start, region_len, ram_base, ram_end
        )));
    }

    let host_offset = usize::try_from(ram_base).map_err(|_| {
        Error::InvalidConfig("ARM RAM base does not fit in host address size".to_string())
    })?;
    let map_size = usize::try_from(ram_size).map_err(|_| {
        Error::InvalidConfig("ARM RAM size does not fit in host address size".to_string())
    })?;

    Ok((ram_end, host_offset, map_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_arm_ram_mapping_accepts_covered_window() {
        let mapping = checked_arm_ram_mapping(0, 0x5000, 0x1000, 0x2000).unwrap();
        assert_eq!(mapping, (0x3000, 0x1000, 0x2000));
    }

    #[test]
    fn checked_arm_ram_mapping_rejects_overflowing_window() {
        let err = checked_arm_ram_mapping(0, 0x1000, 0x800, u64::MAX).unwrap_err();
        assert!(
            err.to_string().contains("overflows guest address space"),
            "{err}"
        );
    }
}

impl HvfArm64Vm {
    /// Register guest RAM with the VM.
    ///
    /// Only the window `[ram_base, ram_base + ram_size)` of the flat backing
    /// allocation is mapped into the guest: ARM platform RAM starts at
    /// `ram_base` (0x4000_0000), and everything below must stay unmapped so
    /// device MMIO (UART, ...) traps out as data aborts. The GIC frames are
    /// claimed by the in-kernel GIC.
    pub fn register_memory(
        &self,
        mem: &GuestMemoryWrapper,
        ram_base: u64,
        ram_size: u64,
    ) -> Result<()> {
        let mut mapped = self.memory_mapped.lock().unwrap();
        if *mapped {
            return Ok(());
        }

        let region = mem
            .memory()
            .iter()
            .next()
            .ok_or_else(|| Error::InvalidConfig("no guest memory region".to_string()))?;
        let region_len = region.len();
        let (_ram_end, host_offset, map_size) =
            checked_arm_ram_mapping(region.start_addr().0, region_len, ram_base, ram_size)?;
        let host_addr = unsafe { (region.as_ptr() as *mut std::ffi::c_void).add(host_offset) };

        debug!(
            guest_addr = format!("{:#x}", ram_base),
            size = ram_size,
            "Mapping guest RAM"
        );

        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
        let ret = unsafe { hv_vm_map(host_addr, ram_base, map_size, flags) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to map RAM at {:#x}: {}",
                ram_base,
                hv_error_string(ret)
            )));
        }

        *mapped = true;
        info!(
            ram_base = format!("{:#x}", ram_base),
            ram_size = ram_size,
            "Mapped guest RAM to ARM64 HVF VM"
        );
        Ok(())
    }
}

impl Vm for HvfArm64Vm {
    fn create_vcpu(&self, id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Box<dyn VCpu>> {
        let vcpu = HvfArm64Vcpu::new(id, mem)?;
        Ok(Box::new(vcpu))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<()> {
        // Route SPI lines through the in-kernel GICv3.
        if irq < 32 {
            return Err(Error::InvalidConfig(format!(
                "intid {irq} is not an SPI (must be >= 32)"
            )));
        }
        let ret = unsafe { hv_gic_set_spi(irq, level) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "hv_gic_set_spi({irq}, {level}) failed: {}",
                hv_error_string(ret)
            )));
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for HvfArm64Vm {
    fn drop(&mut self) {
        let ret = unsafe { hv_vm_destroy() };
        if ret != HV_SUCCESS {
            warn!("Failed to destroy ARM64 VM: {}", hv_error_string(ret));
        }
    }
}

use super::arm64_mmio::PendingMmioRead;

/// ARM64 HVF vCPU.
pub struct HvfArm64Vcpu {
    /// vCPU handle
    vcpu: hv_vcpu_t,
    /// Exit information pointer
    exit: hv_vcpu_exit_t,
    /// Our vCPU ID (index)
    id: u32,
    /// Guest memory reference
    mem: Arc<GuestMemoryMmap>,
    /// MMIO read awaiting completion by the VMM.
    pending_mmio_read: Option<PendingMmioRead>,
    /// Report a failed completion write before another hardware entry.
    io_completion_error: Option<Error>,
    /// Stops the periodic kick thread on drop.
    kick_stop: Arc<std::sync::atomic::AtomicBool>,
    /// Kick thread handle.
    kick_thread: Option<std::thread::JoinHandle<()>>,
}

// Safety: HvfArm64Vcpu is Send because the vCPU handle is thread-local,
// and we synchronize access appropriately.
unsafe impl Send for HvfArm64Vcpu {}

impl HvfArm64Vcpu {
    fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Result<Self> {
        let mut vcpu: hv_vcpu_t = ptr::null_mut();
        let mut exit: hv_vcpu_exit_t = ptr::null_mut();

        let ret = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null()) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to create ARM64 vCPU {}: {}",
                id,
                hv_error_string(ret)
            )));
        }

        // GICv3 routes interrupts by affinity: the redistributor for this
        // vCPU is only assigned once MPIDR_EL1 carries its affinity (RES1
        // bit 31 plus the four affinity levels). For VM indices 0..254,
        // Aff0 equals the index advertised by the device tree.
        let mpidr = crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id(id);
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MPIDR_EL1, mpidr) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "failed to set MPIDR_EL1 for vCPU {id}: {}",
                hv_error_string(ret)
            )));
        }

        // Sanity-check where the in-kernel GIC placed this vCPU's
        // redistributor; the device tree advertises AARCH64_GICR_BASE.
        let mut rdist_base: u64 = 0;
        let gret = unsafe { hv_gic_get_redistributor_base(vcpu, &mut rdist_base) };
        debug!(
            id,
            vcpu = ?vcpu,
            rdist_base = format!("{rdist_base:#x}"),
            gret,
            "Created ARM64 HVF vCPU"
        );

        // With the in-kernel GIC, hv_vcpu_run handles WFI and timer wakeups
        // without returning: an idle guest would park the VMM loop forever
        // and console input / device polling would starve. Kick the vCPU out
        // every few milliseconds so the run loop gets a turn.
        let kick_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick_thread = {
            let stop = kick_stop.clone();
            let vcpu_id = vcpu as usize;
            Some(std::thread::spawn(move || {
                let mut handle: hv_vcpu_t = vcpu_id as hv_vcpu_t;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    unsafe {
                        hv_vcpus_exit(&mut handle, 1);
                    }
                }
            }))
        };

        Ok(HvfArm64Vcpu {
            vcpu,
            exit,
            id,
            mem,
            pending_mmio_read: None,
            io_completion_error: None,
            kick_stop,
            kick_thread,
        })
    }

    /// Read a general-purpose register
    fn read_gpr(&self, reg: hv_reg_t) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to read register {}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(value)
    }

    /// Write a general-purpose register
    fn write_gpr(&self, reg: hv_reg_t, value: u64) -> Result<()> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to write register {}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(())
    }

    /// Read a system register
    fn read_sys_reg(&self, reg: hv_sys_reg_t) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to read system register {:#x}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(value)
    }

    /// Write a system register
    fn write_sys_reg(&self, reg: hv_sys_reg_t, value: u64) -> Result<()> {
        let ret = unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to write system register {:#x}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(())
    }

    /// Read a SIMD/FP register
    fn read_simd_reg(&self, reg: hv_simd_fp_reg_t) -> Result<[u64; 2]> {
        let mut value = hv_simd_fp_uchar16_t::default();
        let ret = unsafe { hv_vcpu_get_simd_fp_reg(self.vcpu, reg, &mut value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to read SIMD register {}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(value.as_u64_pair())
    }

    /// Write a SIMD/FP register
    fn write_simd_reg(&self, reg: hv_simd_fp_reg_t, value: [u64; 2]) -> Result<()> {
        let value = hv_simd_fp_uchar16_t::from_u64_pair(value);
        let ret = unsafe { hv_vcpu_set_simd_fp_reg(self.vcpu, reg, value) };
        if ret != HV_SUCCESS {
            return Err(Error::Emulator(format!(
                "Failed to write SIMD register {}: {}",
                reg,
                hv_error_string(ret)
            )));
        }
        Ok(())
    }

    /// Advance PC past the current instruction
    fn advance_pc(&self, insn_len: u64) -> Result<()> {
        let pc = self.read_gpr(HV_REG_PC)?;
        self.write_gpr(HV_REG_PC, pc + insn_len)
    }

    /// Handle a data abort exception: emulate the trapped load/store as an
    /// MMIO transaction. The faulting instruction is retired here (PC is
    /// advanced); a read is completed later via `complete_io_in`.
    fn handle_data_abort(&mut self, exit_info: &hv_vcpu_exit) -> Result<VcpuExit> {
        let exc = exit_info.exception;
        let iss = exc.iss();
        let addr = exc.physical_address;

        // Without a valid instruction syndrome (ISV=0: LDP/STP, writeback
        // forms, ...) the access cannot be reconstructed from the ESR alone.
        if (iss >> 24) & 1 == 0 {
            let pc = self.read_gpr(HV_REG_PC).unwrap_or(0);
            return Ok(VcpuExit::Unknown(format!(
                "data abort without ISV at {addr:#x} (pc={pc:#x}); \
                 unsupported instruction form for MMIO"
            )));
        }

        let size = 1u8 << exc.access_size();
        let rt = exc.srt();

        // The faulting load/store is consumed by this emulation: continue at
        // the next instruction when the guest resumes.
        self.advance_pc(exc.instruction_length() as u64)?;

        if exc.is_write() {
            let data = if rt < 31 { self.read_gpr(rt)? } else { 0 };
            let data_bytes = match size {
                1 => vec![data as u8],
                2 => (data as u16).to_le_bytes().to_vec(),
                4 => (data as u32).to_le_bytes().to_vec(),
                _ => data.to_le_bytes().to_vec(),
            };
            Ok(VcpuExit::MmioWrite {
                addr,
                data: data_bytes,
            })
        } else {
            self.pending_mmio_read = Some(PendingMmioRead {
                addr,
                rt,
                sign_extend: exc.sign_extend(),
                sixty_four: (iss >> 15) & 1 != 0,
                size,
            });
            Ok(VcpuExit::MmioRead { addr, size })
        }
    }

    /// Handle a PSCI call (SMCCC) made via HVC/SMC. Returns Some(exit) when
    /// the call terminates the VM, None to continue with x0 set to the result.
    fn handle_psci(&mut self) -> Result<Option<VcpuExit>> {
        const PSCI_VERSION: u32 = 0x8400_0000;
        const CPU_SUSPEND_32: u32 = 0x8400_0001;
        const CPU_OFF: u32 = 0x8400_0002;
        const CPU_ON_32: u32 = 0x8400_0003;
        const CPU_ON_64: u32 = 0xC400_0003;
        const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
        const SYSTEM_OFF: u32 = 0x8400_0008;
        const SYSTEM_RESET: u32 = 0x8400_0009;
        const PSCI_FEATURES: u32 = 0x8400_000A;

        const SUCCESS: u64 = 0;
        const NOT_SUPPORTED: u64 = -1i64 as u64;
        const DENIED: u64 = -3i64 as u64;

        let func = self.read_gpr(HV_REG_X0)? as u32;
        let result = match func {
            PSCI_VERSION => 0x0001_0001, // PSCI 1.1
            MIGRATE_INFO_TYPE => 2,      // no trusted OS
            SYSTEM_OFF => {
                info!("PSCI SYSTEM_OFF: guest requested power-off");
                return Ok(Some(VcpuExit::Shutdown));
            }
            SYSTEM_RESET => {
                info!("PSCI SYSTEM_RESET: guest requested reset; shutting down");
                return Ok(Some(VcpuExit::Shutdown));
            }
            PSCI_FEATURES => {
                let queried = self.read_gpr(HV_REG_X1)? as u32;
                match queried {
                    PSCI_VERSION | SYSTEM_OFF | SYSTEM_RESET | PSCI_FEATURES
                    | MIGRATE_INFO_TYPE => SUCCESS,
                    _ => NOT_SUPPORTED,
                }
            }
            // Single-vCPU machine: no secondary bring-up or hotplug.
            CPU_ON_32 | CPU_ON_64 => DENIED,
            CPU_SUSPEND_32 | CPU_OFF => NOT_SUPPORTED,
            _ => {
                debug!(func = format!("{func:#x}"), "unhandled SMCCC/PSCI call");
                NOT_SUPPORTED
            }
        };
        self.write_gpr(HV_REG_X0, result)?;
        Ok(None)
    }

    /// RAZ/WI emulation for system registers HVF traps instead of handling
    /// (PMU, OS lock, implementation-defined). Reads return 0, writes are
    /// dropped.
    fn handle_sysreg_trap(&mut self, exc: &hv_vcpu_exit_exception) -> Result<()> {
        let iss = exc.iss();
        let is_read = iss & 1 != 0;
        let rt = (iss >> 5) & 0x1F;
        debug!(
            syndrome = format!("{:#x}", exc.syndrome),
            is_read, rt, "Trapped system register access (RAZ/WI)"
        );
        if is_read && rt < 31 {
            self.write_gpr(rt, 0)?;
        }
        self.advance_pc(4)
    }
}

impl VCpu for HvfArm64Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        if let Some(error) = self.io_completion_error.take() {
            return Err(error);
        }
        if let Some(pending) = self.pending_mmio_read {
            return Ok(VcpuExit::MmioRead {
                addr: pending.addr,
                size: pending.size,
            });
        }
        loop {
            let ret = unsafe { hv_vcpu_run(self.vcpu) };
            if ret != HV_SUCCESS {
                return Err(Error::Emulator(format!(
                    "hv_vcpu_run failed: {}",
                    hv_error_string(ret)
                )));
            }

            let exit_info = unsafe { &*self.exit }.clone();

            match exit_info.reason {
                hv_exit_reason_t::HV_EXIT_REASON_CANCELED => {
                    // Periodic kick from the exit thread: hand control back to
                    // the VMM loop so it can poll the console and devices.
                    return Ok(VcpuExit::Hlt);
                }

                hv_exit_reason_t::HV_EXIT_REASON_EXCEPTION => {
                    let exc = exit_info.exception;
                    let ec = exc.exception_class();

                    match ec {
                        EC_WFI_WFE => {
                            // WFI/WFE is a hint; retire it and yield to the
                            // VMM loop so console/devices get serviced. The
                            // next hv_vcpu_run delivers any due vtimer exit.
                            self.advance_pc(exc.instruction_length() as u64)?;
                            std::thread::sleep(std::time::Duration::from_micros(100));
                            return Ok(VcpuExit::Hlt);
                        }

                        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_CURR => {
                            // Data abort on unmapped memory: MMIO access
                            return self.handle_data_abort(&exit_info);
                        }

                        EC_INST_ABORT_LOWER | EC_INST_ABORT_CURR => {
                            let addr = exc.physical_address;
                            return Ok(VcpuExit::Unknown(format!(
                                "Instruction abort at {:#x}",
                                addr
                            )));
                        }

                        // SMCCC: PSCI calls arrive as HVC (preferred return
                        // address already points past the HVC) or SMC (must
                        // skip the instruction ourselves).
                        EC_HVC64 => {
                            if let Some(exit) = self.handle_psci()? {
                                return Ok(exit);
                            }
                        }
                        EC_SMC64 => {
                            self.advance_pc(4)?;
                            if let Some(exit) = self.handle_psci()? {
                                return Ok(exit);
                            }
                        }

                        EC_MSR_MRS => {
                            self.handle_sysreg_trap(&exc)?;
                        }

                        EC_SVC64 => {
                            // Supervisor call - let the guest handle it
                            return Ok(VcpuExit::Exception(ec as u8));
                        }

                        _ => {
                            let pc = self.read_gpr(HV_REG_PC).unwrap_or(0);
                            return Ok(VcpuExit::Unknown(format!(
                                "Exception class {:#x} at PC {:#x}, syndrome {:#x}",
                                ec, pc, exc.syndrome
                            )));
                        }
                    }
                }

                hv_exit_reason_t::HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    // Virtual timer fired: make PPI 27 pending in the guest's
                    // redistributor. HVF masks the vtimer until the guest
                    // deactivates the interrupt, then unmasks it.
                    let ret = unsafe {
                        hv_gic_set_redistributor_reg(
                            self.vcpu,
                            HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0,
                            1u64 << HV_GIC_INT_EL1_VIRTUAL_TIMER,
                        )
                    };
                    if ret != HV_SUCCESS {
                        return Err(Error::Emulator(format!(
                            "failed to pend vtimer PPI: {}",
                            hv_error_string(ret)
                        )));
                    }
                }

                hv_exit_reason_t::HV_EXIT_REASON_UNKNOWN => {
                    let pc = self.read_gpr(HV_REG_PC).unwrap_or(0);
                    return Ok(VcpuExit::Unknown(format!("Unknown exit at PC {:#x}", pc)));
                }
            }
        }
    }

    fn get_state(&self) -> Result<CpuState> {
        self.native_state()
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        self.restore_native_state(state)?;
        // Successful external state replacement cancels the old transaction.
        // Failed replacement leaves the staged transaction pending.
        self.pending_mmio_read = None;
        self.io_completion_error = None;
        Ok(())
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        let Some(pending) = self.pending_mmio_read else {
            return;
        };
        match pending.complete(data, |rt, value| self.write_gpr(rt, value)) {
            Ok(false) => return,
            Err(error) => {
                self.io_completion_error = Some(error);
                return;
            }
            Ok(true) => {}
        }
        self.pending_mmio_read = None;
        self.io_completion_error = None;
    }

    fn inject_interrupt(&mut self, _vector: u8) -> Result<bool> {
        // All interrupts flow through the in-kernel GICv3 (hv_gic_set_spi via
        // Vm::set_irq_line); the legacy x86 PIC/LAPIC injection paths in the
        // run loop must not poke the vCPU directly.
        Ok(false)
    }

    fn can_inject_interrupt(&self) -> bool {
        false
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        Ok(false)
    }

    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, _enabled: bool) {
        // ARM single-step would need debug register setup
        // Not implemented yet
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        false
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, _addr: u64) {
        // HVF doesn't have a software decode cache
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        // HVF doesn't provide instruction count
        0
    }
}

impl Drop for HvfArm64Vcpu {
    fn drop(&mut self) {
        self.kick_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.kick_thread.take() {
            let _ = handle.join();
        }
        let ret = unsafe { hv_vcpu_destroy(self.vcpu) };
        if ret != HV_SUCCESS {
            warn!(
                "Failed to destroy ARM64 vCPU {}: {}",
                self.id,
                hv_error_string(ret)
            );
        }
    }
}
