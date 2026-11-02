//! Complete represented GSC state, separate from its target RAM owner.
use super::*;
use crate::isa::riscv::cpu::checkpoint::CoreContext;
use serde::{Deserialize, Serialize};
const IMAGE_TAG: &[u8; 8] = b"RAXGSI01";
const ROWS: usize = 65536;
fn data<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, MAX_STATE>(d)
}
fn spi<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, AP_SPI_DATA_LEN>(d)
}
fn fifo<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u8, D, GSC_FIFO_RAM_LEN>(d)
}
fn seen<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u64>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u64, D, ROWS>(d)
}
fn words<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<(u64, u32)>, D::Error> {
    crate::devices::checkpoint_serde::vector::<(u64, u32), D, ROWS>(d)
}
fn bits<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<(u64, bool)>, D::Error> {
    crate::devices::checkpoint_serde::vector::<(u64, bool), D, ROWS>(d)
}
fn commands<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    struct Command(#[serde(deserialize_with = "data")] Vec<u8>);
    crate::devices::checkpoint_serde::vector::<Command, D, ROWS>(d)
        .map(|v| v.into_iter().map(|v| v.0).collect())
}
fn canonical<T>(v: &[(u64, T)]) -> bool {
    v.windows(2).all(|w| w[0].0 < w[1].0)
}
fn map<V>(v: Vec<(u64, V)>) -> Result<HashMap<u64, V>> {
    let mut m = HashMap::new();
    m.try_reserve(v.len()).map_err(invalid)?;
    m.extend(v);
    Ok(m)
}
#[derive(Serialize, Deserialize)]
struct SharedImage {
    #[serde(deserialize_with = "data")]
    console: Vec<u8>,
    #[serde(deserialize_with = "data")]
    uart_rx: Vec<u8>,
    uart_irq_armed: bool,
    #[serde(deserialize_with = "seen")]
    seen: Vec<u64>,
    #[serde(deserialize_with = "words")]
    read_counts: Vec<(u64, u32)>,
    #[serde(deserialize_with = "words")]
    store: Vec<(u64, u32)>,
    #[serde(deserialize_with = "bits")]
    spin_phase: Vec<(u64, bool)>,
    reset_requested: bool,
    rstsrc: u32,
    flash_pe_en: bool,
    flash_trans: u32,
    flash_read_trans: u32,
    flash_wr_data: [u32; 2],
    flash_dout: [[u32; 2]; 2],
    flash_error: u32,
    #[serde(deserialize_with = "words")]
    flash_info: Vec<(u64, u32)>,
    #[serde(deserialize_with = "spi")]
    ap_spi_data: Vec<u8>,
    trng_state: u32,
    timer_compare: u64,
    tpm_active: bool,
    #[serde(deserialize_with = "fifo")]
    fifo_ram: Vec<u8>,
}
impl SharedImage {
    fn capture(source: &GscShared) -> Result<Self> {
        let GscShared {
            console,
            uart_rx,
            uart_irq_armed,
            seen,
            read_counts,
            store,
            spin_phase,
            reset_requested,
            rstsrc,
            flash_pe_en,
            flash_trans,
            flash_read_trans,
            flash_wr_data,
            flash_dout,
            flash_error,
            flash_info,
            ap_spi_data,
            trng_state,
            timer_compare,
            tpm_active,
            fifo_ram,
        } = source;
        if console.len() > MAX_STATE {
            return Err(invalid("shared collection exceeds budget"));
        }
        if uart_rx.len() > MAX_STATE {
            return Err(invalid("shared collection exceeds budget"));
        }
        if seen.len() > ROWS {
            return Err(invalid("shared collection exceeds budget"));
        }
        if read_counts.len() > ROWS {
            return Err(invalid("shared collection exceeds budget"));
        }
        if store.len() > ROWS {
            return Err(invalid("shared collection exceeds budget"));
        }
        if spin_phase.len() > ROWS {
            return Err(invalid("shared collection exceeds budget"));
        }
        if flash_info.len() > ROWS {
            return Err(invalid("shared collection exceeds budget"));
        }
        if ap_spi_data.len() > AP_SPI_DATA_LEN {
            return Err(invalid("shared collection exceeds budget"));
        }
        if fifo_ram.len() > GSC_FIFO_RAM_LEN {
            return Err(invalid("shared collection exceeds budget"));
        }
        Ok(Self {
            console: console.clone(),
            uart_rx: uart_rx.iter().copied().collect(),
            uart_irq_armed: uart_irq_armed.clone(),
            seen: seen.iter().copied().collect(),
            read_counts: {
                let mut v: Vec<_> = read_counts.iter().map(|(&k, &v)| (k, v)).collect();
                v.sort_unstable_by_key(|v| v.0);
                v
            },
            store: {
                let mut v: Vec<_> = store.iter().map(|(&k, &v)| (k, v)).collect();
                v.sort_unstable_by_key(|v| v.0);
                v
            },
            spin_phase: {
                let mut v: Vec<_> = spin_phase.iter().map(|(&k, &v)| (k, v)).collect();
                v.sort_unstable_by_key(|v| v.0);
                v
            },
            reset_requested: reset_requested.clone(),
            rstsrc: rstsrc.clone(),
            flash_pe_en: flash_pe_en.clone(),
            flash_trans: flash_trans.clone(),
            flash_read_trans: flash_read_trans.clone(),
            flash_wr_data: flash_wr_data.clone(),
            flash_dout: flash_dout.clone(),
            flash_error: flash_error.clone(),
            flash_info: {
                let mut v: Vec<_> = flash_info.iter().map(|(&k, &v)| (k, v)).collect();
                v.sort_unstable_by_key(|v| v.0);
                v
            },
            ap_spi_data: ap_spi_data.clone(),
            trng_state: trng_state.clone(),
            timer_compare: timer_compare.clone(),
            tpm_active: tpm_active.clone(),
            fifo_ram: fifo_ram.clone(),
        })
    }
    fn validate(&self) -> Result<()> {
        if !self.seen.windows(2).all(|w| w[0] < w[1])
            || !canonical(&self.read_counts)
            || !canonical(&self.store)
            || !canonical(&self.spin_phase)
            || !canonical(&self.flash_info)
        {
            return Err(invalid("noncanonical shared table"));
        }
        if self.read_counts.iter().any(|(_, v)| *v >= SPIN_THRESHOLD) {
            return Err(invalid("spin counter phase differs"));
        }
        if ![0, AP_SPI_DATA_LEN].contains(&self.ap_spi_data.len())
            || ![0, GSC_FIFO_RAM_LEN].contains(&self.fifo_ram.len())
        {
            return Err(invalid("peripheral buffer geometry differs"));
        }
        Ok(())
    }
    fn install(self) -> Result<GscShared> {
        Ok(GscShared {
            console: self.console,
            uart_rx: self.uart_rx.into(),
            uart_irq_armed: self.uart_irq_armed,
            seen: self.seen.into_iter().collect(),
            read_counts: map(self.read_counts)?,
            store: map(self.store)?,
            spin_phase: map(self.spin_phase)?,
            reset_requested: self.reset_requested,
            rstsrc: self.rstsrc,
            flash_pe_en: self.flash_pe_en,
            flash_trans: self.flash_trans,
            flash_read_trans: self.flash_read_trans,
            flash_wr_data: self.flash_wr_data,
            flash_dout: self.flash_dout,
            flash_error: self.flash_error,
            flash_info: map(self.flash_info)?,
            ap_spi_data: self.ap_spi_data,
            trng_state: self.trng_state,
            timer_compare: self.timer_compare,
            tpm_active: self.tpm_active,
            fifo_ram: self.fifo_ram,
        })
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct Image {
    pub(super) id: u32,
    cpu: CoreContext,
    cfg: GscConfig,
    halted: bool,
    reset_entry: u64,
    reset_count: u32,
    break_pc: Option<u64>,
    break_hit: u64,
    break_ra: Option<u64>,
    break_saved_ra: Option<u64>,
    break_stack_bytes: u64,
    break_stop: bool,
    syscall_trace: bool,
    print_trace: bool,
    ap_ro_stub: bool,
    ap_ro_crypto_stub: bool,
    break_hits_seen: u64,
    broke: bool,
    #[serde(deserialize_with = "commands")]
    tpm_cmds: Vec<Vec<u8>>,
    tpm_trigger: u64,
    tpm_yield_mode: bool,
    tpm_wired: bool,
    tpm: TpmInject,
    plt_rst_event: bool,
    plt_rst_fired: bool,
    entropy_hooks: bool,
    entropy_state: u64,
    shared: SharedImage,
    bridge_cfg: GscConfig,
    #[serde(deserialize_with = "words")]
    ready: Vec<(u64, u32)>,
    pc: u64,
    time: u64,
    crypto_trace: bool,
}
impl Image {
    pub(super) fn empty(id: u32) -> Result<Self> {
        let cfg = GscConfig {
            uart_base: DEFAULT_UART_BASE,
            uart_state: DEFAULT_UART_STATE,
            open_bus: 0,
            rstsrc_cold: DEFAULT_RSTSRC_COLD,
            rstsrc_warm: DEFAULT_RSTSRC_WARM,
            flash_img_base: DEFAULT_FLASH_IMG_BASE,
            trace: Trace::Off,
            console_trace: false,
            ap_ro_info_stub: false,
            ap_ro_crypto_stub: false,
            ap_ro_stub: false,
            timer_div: TIMER_DEFAULT_DIV,
        };
        let shared = GscShared {
            rstsrc: cfg.rstsrc_cold,
            timer_compare: u64::MAX,
            ..GscShared::default()
        };
        let mut ready: Vec<_> = builtin_ready_map().into_iter().collect();
        ready.sort_unstable_by_key(|v| v.0);
        Ok(Self {
            id,
            cpu: RiscVCpu::new(
                RiscVConfig::rv32(Isa::ti50()),
                Box::new(crate::isa::riscv::FlatMemory::new(0, 0)),
            )
            .checkpoint_state(),
            shared: SharedImage::capture(&shared)?,
            bridge_cfg: cfg,
            ready,
            pc: 0,
            time: 0,
            crypto_trace: false,
            cfg: cfg,
            halted: false,
            reset_entry: 0,
            reset_count: 0,
            break_pc: None,
            break_hit: 1,
            break_ra: None,
            break_saved_ra: None,
            break_stack_bytes: 0,
            break_stop: false,
            syscall_trace: false,
            print_trace: false,
            ap_ro_stub: false,
            ap_ro_crypto_stub: false,
            break_hits_seen: 0,
            broke: false,
            tpm_cmds: Vec::new(),
            tpm_trigger: 0xa2d3c,
            tpm_yield_mode: true,
            tpm_wired: false,
            tpm: TpmInject::default(),
            plt_rst_event: false,
            plt_rst_fired: false,
            entropy_hooks: true,
            entropy_state: 0x243f_6a88_85a3_08d3,
        })
    }
    pub(super) fn capture(source: &GscVcpu) -> Result<Self> {
        let GscVcpu {
            id,
            cpu,
            shared,
            cfg,
            halted,
            reset_entry,
            reset_count,
            pc_cell,
            time_cell,
            break_pc,
            break_hit,
            break_ra,
            break_saved_ra,
            break_stack_bytes,
            break_stop,
            syscall_trace,
            print_trace,
            ap_ro_stub,
            ap_ro_crypto_stub,
            break_hits_seen,
            broke,
            tpm_cmds,
            tpm_trigger,
            tpm_yield_mode,
            tpm_wired,
            tpm,
            plt_rst_event,
            plt_rst_fired,
            entropy_hooks,
            entropy_state,
            bridge,
            checkpoint_publication: _,
        } = source;
        let GscBridge {
            mem: _,
            shared: _,
            ap_flash: _,
            cfg: _,
            ready: _,
            pc: _,
            time: _,
            crypto_trace: _,
        } = bridge;
        if !Arc::ptr_eq(shared, &bridge.shared)
            || !Arc::ptr_eq(pc_cell, &bridge.pc)
            || !Arc::ptr_eq(time_cell, &bridge.time)
        {
            return Err(invalid("bridge owner graph differs"));
        }
        let sh = shared.lock().map_err(|_| invalid("shared lock poisoned"))?;
        let bytes = sh
            .console
            .len()
            .checked_add(sh.uart_rx.len())
            .and_then(|n| tpm_cmds.iter().try_fold(n, |n, v| n.checked_add(v.len())))
            .ok_or_else(|| invalid("byte budget overflow"))?;
        if bytes > MAX_STATE || tpm_cmds.len() > ROWS || bridge.ready.len() > ROWS {
            return Err(invalid("state collections exceed budget"));
        }
        let mut ready: Vec<_> = bridge.ready.iter().map(|(&k, &v)| (k, v)).collect();
        ready.sort_unstable_by_key(|v| v.0);
        let image = Self {
            id: *id,
            cpu: cpu.checkpoint_state(),
            shared: SharedImage::capture(&sh)?,
            bridge_cfg: bridge.cfg,
            ready,
            pc: pc_cell.load(Ordering::Relaxed),
            time: time_cell.load(Ordering::Relaxed),
            crypto_trace: bridge.crypto_trace,
            cfg: cfg.clone(),
            halted: halted.clone(),
            reset_entry: reset_entry.clone(),
            reset_count: reset_count.clone(),
            break_pc: break_pc.clone(),
            break_hit: break_hit.clone(),
            break_ra: break_ra.clone(),
            break_saved_ra: break_saved_ra.clone(),
            break_stack_bytes: break_stack_bytes.clone(),
            break_stop: break_stop.clone(),
            syscall_trace: syscall_trace.clone(),
            print_trace: print_trace.clone(),
            ap_ro_stub: ap_ro_stub.clone(),
            ap_ro_crypto_stub: ap_ro_crypto_stub.clone(),
            break_hits_seen: break_hits_seen.clone(),
            broke: broke.clone(),
            tpm_cmds: tpm_cmds.clone(),
            tpm_trigger: tpm_trigger.clone(),
            tpm_yield_mode: tpm_yield_mode.clone(),
            tpm_wired: tpm_wired.clone(),
            tpm: tpm.clone(),
            plt_rst_event: plt_rst_event.clone(),
            plt_rst_fired: plt_rst_fired.clone(),
            entropy_hooks: entropy_hooks.clone(),
            entropy_state: entropy_state.clone(),
        };
        image.validate()?;
        Ok(image)
    }
    fn validate(&self) -> Result<()> {
        self.cpu.validate().map_err(invalid)?;
        if self.cpu.configuration() != RiscVConfig::rv32(Isa::ti50()) {
            return Err(invalid("core ISA profile differs"));
        }
        for cfg in [&self.cfg, &self.bridge_cfg] {
            if cfg.timer_div == 0
                || cfg.uart_base.checked_add(UART_LEN).is_none()
                || cfg
                    .flash_img_base
                    .checked_add(TI50_RW_SLOT_OFFSET)
                    .is_none()
            {
                return Err(invalid("invalid bridge profile"));
            }
        }
        if self.break_hit == 0
            || (!self.broke && self.break_hits_seen >= self.break_hit)
            || self.tpm.next > self.tpm_cmds.len()
            || (self.tpm.in_call && self.tpm.awaiting)
        {
            return Err(invalid("runtime phase differs"));
        }
        if !canonical(&self.ready) {
            return Err(invalid("noncanonical ready table"));
        }
        self.shared.validate()
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let raw = crate::codec::serialize_limited(self, MAX_STATE - 8).map_err(invalid)?;
        let mut out = IMAGE_TAG.to_vec();
        out.extend_from_slice(&raw);
        Ok(out)
    }
    pub(super) fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_STATE || !raw.starts_with(IMAGE_TAG) {
            return Err(invalid("invalid state resource tag/size"));
        }
        let image: Self = crate::codec::deserialize_limited::<_, { MAX_STATE - 8 }>(&raw[8..])
            .map_err(invalid)?;
        image.validate()?;
        Ok(image)
    }
    pub(super) fn into_cpu(
        self,
        mem: Arc<GuestMemoryMmap>,
        ap_flash: Arc<Vec<u8>>,
    ) -> Result<GscVcpu> {
        let shared = Arc::new(Mutex::new(self.shared.install()?));
        let pc_cell = Arc::new(AtomicU64::new(self.pc));
        let time_cell = Arc::new(AtomicU64::new(self.time));
        let bridge = GscBridge {
            mem,
            shared: shared.clone(),
            ap_flash,
            cfg: self.bridge_cfg,
            ready: map(self.ready)?,
            pc: pc_cell.clone(),
            time: time_cell.clone(),
            crypto_trace: self.crypto_trace,
        };
        let mut cpu = RiscVCpu::new(RiscVConfig::rv32(Isa::ti50()), Box::new(bridge.clone()));
        self.cpu.install(&mut cpu);
        Ok(GscVcpu {
            id: self.id,
            cpu,
            shared,
            pc_cell,
            time_cell,
            bridge,
            checkpoint_publication: None,
            cfg: self.cfg,
            halted: self.halted,
            reset_entry: self.reset_entry,
            reset_count: self.reset_count,
            break_pc: self.break_pc,
            break_hit: self.break_hit,
            break_ra: self.break_ra,
            break_saved_ra: self.break_saved_ra,
            break_stack_bytes: self.break_stack_bytes,
            break_stop: self.break_stop,
            syscall_trace: self.syscall_trace,
            print_trace: self.print_trace,
            ap_ro_stub: self.ap_ro_stub,
            ap_ro_crypto_stub: self.ap_ro_crypto_stub,
            break_hits_seen: self.break_hits_seen,
            broke: self.broke,
            tpm_cmds: self.tpm_cmds,
            tpm_trigger: self.tpm_trigger,
            tpm_yield_mode: self.tpm_yield_mode,
            tpm_wired: self.tpm_wired,
            tpm: self.tpm,
            plt_rst_event: self.plt_rst_event,
            plt_rst_fired: self.plt_rst_fired,
            entropy_hooks: self.entropy_hooks,
            entropy_state: self.entropy_state,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
