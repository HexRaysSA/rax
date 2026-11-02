//! Exhaustive represented CPU/platform image; memory and live UART owners are external.
use super::super::{
    profile::GuestProfile,
    time::{ElapsedClock, ElapsedImage},
};
use super::*;
use crate::devices::s5l8900;
use crate::isa::arm::instructions::ExclusiveMonitor;
use serde::{Deserialize, Serialize};
const IMAGE_TAG: &[u8; 8] = b"RAXSLI01";
fn words<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u32>, D::Error> {
    crate::devices::checkpoint_serde::vector::<u32, D, { MAX_STATE / 4 }>(d)
}
fn pairs<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<(u32, u32)>, D::Error> {
    crate::devices::checkpoint_serde::vector::<(u32, u32), D, { MAX_STATE / 8 }>(d)
}
fn payload<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    struct Data(#[serde(deserialize_with = "data")] Vec<u8>);
    fn data<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        crate::devices::checkpoint_serde::vector::<u8, D, MAX_STATE>(d)
    }
    Option::<Data>::deserialize(d).map(|v| v.map(|v| v.0))
}
#[derive(Serialize, Deserialize)]
struct ExclusiveImage {
    address: Option<u32>,
    size: u8,
}
#[derive(Serialize, Deserialize)]
struct MmuImage {
    enabled: bool,
    ttbr0: u32,
    ttbr1: u32,
    ttbcr_n: u32,
    dacr: u32,
    afe: bool,
}
impl MmuImage {
    fn capture(c: &V6MmuConfig) -> Self {
        let V6MmuConfig {
            enabled,
            ttbr0,
            ttbr1,
            ttbcr_n,
            dacr,
            afe,
        } = *c;
        Self {
            enabled,
            ttbr0,
            ttbr1,
            ttbcr_n,
            dacr,
            afe,
        }
    }
    fn into_config(self) -> V6MmuConfig {
        V6MmuConfig {
            enabled: self.enabled,
            ttbr0: self.ttbr0,
            ttbr1: self.ttbr1,
            ttbcr_n: self.ttbcr_n,
            dacr: self.dacr,
            afe: self.afe,
        }
    }
}
#[derive(Serialize, Deserialize)]
struct RuntimeImage {
    id: u32,
    cpu: Armv7Cpu,
    insn_count: u64,
    excl: ExclusiveImage,
    #[serde(
        serialize_with = "crate::devices::checkpoint_serde::serialize_array",
        deserialize_with = "crate::devices::checkpoint_serde::array::<u32,_,512>"
    )]
    pc_ring: [u32; 512],
    pc_ring_idx: usize,
    zero_slide: u32,
    #[serde(deserialize_with = "words")]
    trace_pcs: Vec<u32>,
    trace_log_budget: u32,
    trace_start_insn: u64,
    pc_sample_interval: u64,
    pc_sample_next_insn: u64,
    pc_sample_remaining: u32,
    trace_all: bool,
    #[serde(deserialize_with = "pairs")]
    storage_call_trace_seen: Vec<(u32, u32)>,
    storage_call_trace_remaining: u32,
    storage_call_trace_start_insn: u64,
    #[serde(deserialize_with = "pairs")]
    fdisk_trace_seen: Vec<(u32, u32)>,
    fdisk_trace_remaining: u32,
    #[serde(deserialize_with = "pairs")]
    nandftl_trace_seen: Vec<(u32, u32)>,
    nandftl_trace_remaining: u32,
    #[serde(deserialize_with = "pairs")]
    wmr_trace_seen: Vec<(u32, u32)>,
    wmr_trace_remaining: u32,
    wmr_init_active: bool,
    partition_trace_remaining: u32,
    iokit_match_follow_remaining: u32,
    kernel_trace_remaining: u32,
    root_trace_remaining: u32,
    root_trace_start_insn: u64,
    root_boot_trace_remaining: u32,
    root_boot_trace_start_insn: u64,
    apple_arm_function_trace_remaining: u32,
    iokit_lifetime_trace_remaining: u32,
    iokit_retain_trace: bool,
    ioreg_free_trace_remaining: u32,
    iokit_watch_object: Option<u32>,
    iokit_watch_trace_remaining: u32,
    sdio_power_trace_remaining: u32,
    iokit_message_trace_remaining: u32,
    pmqueue_trace_remaining: u32,
    admfmc_trace_remaining: u32,
    kernel_entry_logged: bool,
    kernel_fault_log_remaining: u32,
    kernel_exception_log_remaining: u32,
    fault_log_budget: u32,
    heartbeat_clock: ElapsedImage,
    boot_clock: ElapsedImage,
    guest_profile: GuestProfile,
    timer_speedup: u64,
    det_timer: u64,
    timer_mul: u64,
    input_seeded: bool,
    security_state_seeded: bool,
    #[serde(deserialize_with = "payload")]
    input_payload: Option<Vec<u8>>,
    printf_trace: bool,
    vfl_scan_trace: bool,
    derail_trace: bool,
    no_usb_wrangler_race_fix: bool,
    force_iobsd: bool,
    force_iobsd_all: bool,
    sparse_vfl_mask_seeded: [bool; 8],
    fsboot_trace: bool,
    lcd_irq: bool,
    lcd_irq_armed: bool,
    lcd_irq_budget: u32,
    lcd_irq_arm_after_rootdev: bool,
    i2c_irq: bool,
    timer_irq: bool,
    timer_irq_ready: u64,
    timer_irq_interval: u64,
    timer_irq_clock: u64,
    irq_trace: bool,
    irq_trace_timer: bool,
    irq_trace_start_insn: u64,
    irq_trace_budget: u32,
    last_irq_trace: u128,
    fiq_trace_budget: u32,
    fiq_trace_start_insn: u64,
    last_fiq_trace: u128,
    idle_trace: bool,
    idle_trace_start_insn: u64,
    last_idle_trace_insn: u64,
    adm_irq_trace_budget: u32,
    adm_irq_trace_start_insn: u64,
    last_adm_irq_trace: u128,
    i2c_irq_trace_budget: u32,
    last_i2c1_irq_trace: u128,
    shutdown: bool,
}
#[derive(Serialize, Deserialize)]
struct BridgeImage {
    mmu: MmuImage,
    privileged: bool,
    cur_pc: u32,
    cur_insn: u64,
    kernel_started: bool,
    last_fault: LastFault,
    clock0: S5lClock,
    clock1: S5lClock,
    vic0: Pl192,
    vic1: Pl192,
    vic1_adm_daisy_latched: bool,
    vic1_adm_daisy_in_service: bool,
    sysic: S5lSysic,
    gpio: S5lGpio,
    timer: S5lTimer,
    i2c0: S5lI2c,
    i2c1: S5lI2c,
    spi0: S5lSpi,
    spi1: S5lSpi,
    spi2: S5lSpi,
    lcd: S5lLcd,
    nand_ecc: S5lNandEcc,
    sdio: S5lSdio,
    aes: S5lAes,
    dmac0: S5lDmac,
    dmac1: S5lDmac,
    usb: S5lUsb,
    nor: S5lNor,
    adm_data2: u32,
    adm_data3: u32,
    adm_req: Option<u32>,
    adm_irq: bool,
    engine_8900_req: Option<u32>,
    openbus_log_budget: u32,
    devlog: bool,
    vic_trace_budget: u32,
    vic_trace_start_insn: u64,
    vic_trace_adm: bool,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Image {
    runtime: RuntimeImage,
    bridge: BridgeImage,
    uart: Option<S3cUart>,
}

impl Image {
    pub(super) fn capture(
        source: &S5L8900Vcpu,
        scope: Option<&CheckpointPublication<'_>>,
    ) -> Result<Self> {
        source.check_publication()?;
        let now = scope.map_or_else(crate::host::time::Instant::now, |scope| {
            scope.capture_time()
        });
        let S5L8900Vcpu {
            id,
            cpu,
            bridge: _,
            decoder: _,
            uart: _,
            insn_count,
            excl,
            pc_ring,
            pc_ring_idx,
            zero_slide,
            trace_pcs,
            trace_log_budget,
            trace_start_insn,
            pc_sample_interval,
            pc_sample_next_insn,
            pc_sample_remaining,
            trace_all,
            storage_call_trace_seen,
            storage_call_trace_remaining,
            storage_call_trace_start_insn,
            fdisk_trace_seen,
            fdisk_trace_remaining,
            nandftl_trace_seen,
            nandftl_trace_remaining,
            wmr_trace_seen,
            wmr_trace_remaining,
            wmr_init_active,
            partition_trace_remaining,
            iokit_match_follow_remaining,
            kernel_trace_remaining,
            root_trace_remaining,
            root_trace_start_insn,
            root_boot_trace_remaining,
            root_boot_trace_start_insn,
            apple_arm_function_trace_remaining,
            iokit_lifetime_trace_remaining,
            iokit_retain_trace,
            ioreg_free_trace_remaining,
            iokit_watch_object,
            iokit_watch_trace_remaining,
            sdio_power_trace_remaining,
            iokit_message_trace_remaining,
            pmqueue_trace_remaining,
            admfmc_trace_remaining,
            kernel_entry_logged,
            kernel_fault_log_remaining,
            kernel_exception_log_remaining,
            fault_log_budget,
            heartbeat_clock,
            boot_clock,
            guest_profile,
            capture_owner: _,
            checkpoint_publication: _,
            timer_speedup,
            det_timer,
            timer_mul,
            input_seeded,
            security_state_seeded,
            input_payload,
            printf_trace,
            vfl_scan_trace,
            derail_trace,
            no_usb_wrangler_race_fix,
            force_iobsd,
            force_iobsd_all,
            sparse_vfl_mask_seeded,
            fsboot_trace,
            lcd_irq,
            lcd_irq_armed,
            lcd_irq_budget,
            lcd_irq_arm_after_rootdev,
            i2c_irq,
            timer_irq,
            timer_irq_ready,
            timer_irq_interval,
            timer_irq_clock,
            irq_trace,
            irq_trace_timer,
            irq_trace_start_insn,
            irq_trace_budget,
            last_irq_trace,
            fiq_trace_budget,
            fiq_trace_start_insn,
            last_fiq_trace,
            idle_trace,
            idle_trace_start_insn,
            last_idle_trace_insn,
            adm_irq_trace_budget,
            adm_irq_trace_start_insn,
            last_adm_irq_trace,
            i2c_irq_trace_budget,
            last_i2c1_irq_trace,
            shutdown,
        } = source;
        let inner = source.bridge.inner.borrow();
        Self::validate_devices(&inner)?;
        let BridgeInner {
            mmu,
            privileged,
            cur_pc,
            cur_insn,
            kernel_started,
            last_fault,
            clock0,
            clock1,
            vic0,
            vic1,
            vic1_adm_daisy_latched,
            vic1_adm_daisy_in_service,
            sysic,
            gpio,
            timer,
            i2c0,
            i2c1,
            spi0,
            spi1,
            spi2,
            lcd,
            nand: _,
            nand_ecc,
            sdio,
            aes,
            dmac0,
            dmac1,
            usb,
            nor,
            adm_data2,
            adm_data3,
            adm_req,
            adm_irq,
            uart: _,
            engine_8900_req,
            openbus_log_budget,
            devlog,
            vic_trace_budget,
            vic_trace_start_insn,
            vic_trace_adm,
        } = &*inner;
        let runtime = RuntimeImage {
            id: id.clone(),
            cpu: cpu.clone(),
            insn_count: insn_count.clone(),
            excl: ExclusiveImage {
                address: excl.address,
                size: excl.size,
            },
            pc_ring: pc_ring.clone(),
            pc_ring_idx: pc_ring_idx.clone(),
            zero_slide: zero_slide.clone(),
            trace_pcs: trace_pcs.clone(),
            trace_log_budget: trace_log_budget.clone(),
            trace_start_insn: trace_start_insn.clone(),
            pc_sample_interval: pc_sample_interval.clone(),
            pc_sample_next_insn: pc_sample_next_insn.clone(),
            pc_sample_remaining: pc_sample_remaining.clone(),
            trace_all: trace_all.clone(),
            storage_call_trace_seen: storage_call_trace_seen.clone(),
            storage_call_trace_remaining: storage_call_trace_remaining.clone(),
            storage_call_trace_start_insn: storage_call_trace_start_insn.clone(),
            fdisk_trace_seen: fdisk_trace_seen.clone(),
            fdisk_trace_remaining: fdisk_trace_remaining.clone(),
            nandftl_trace_seen: nandftl_trace_seen.clone(),
            nandftl_trace_remaining: nandftl_trace_remaining.clone(),
            wmr_trace_seen: wmr_trace_seen.clone(),
            wmr_trace_remaining: wmr_trace_remaining.clone(),
            wmr_init_active: wmr_init_active.clone(),
            partition_trace_remaining: partition_trace_remaining.clone(),
            iokit_match_follow_remaining: iokit_match_follow_remaining.clone(),
            kernel_trace_remaining: kernel_trace_remaining.clone(),
            root_trace_remaining: root_trace_remaining.clone(),
            root_trace_start_insn: root_trace_start_insn.clone(),
            root_boot_trace_remaining: root_boot_trace_remaining.clone(),
            root_boot_trace_start_insn: root_boot_trace_start_insn.clone(),
            apple_arm_function_trace_remaining: apple_arm_function_trace_remaining.clone(),
            iokit_lifetime_trace_remaining: iokit_lifetime_trace_remaining.clone(),
            iokit_retain_trace: iokit_retain_trace.clone(),
            ioreg_free_trace_remaining: ioreg_free_trace_remaining.clone(),
            iokit_watch_object: iokit_watch_object.clone(),
            iokit_watch_trace_remaining: iokit_watch_trace_remaining.clone(),
            sdio_power_trace_remaining: sdio_power_trace_remaining.clone(),
            iokit_message_trace_remaining: iokit_message_trace_remaining.clone(),
            pmqueue_trace_remaining: pmqueue_trace_remaining.clone(),
            admfmc_trace_remaining: admfmc_trace_remaining.clone(),
            kernel_entry_logged: kernel_entry_logged.clone(),
            kernel_fault_log_remaining: kernel_fault_log_remaining.clone(),
            kernel_exception_log_remaining: kernel_exception_log_remaining.clone(),
            fault_log_budget: fault_log_budget.clone(),
            heartbeat_clock: heartbeat_clock.capture_at(now),
            boot_clock: boot_clock.capture_at(now),
            guest_profile: source.effective_guest_profile().into_owned(),
            timer_speedup: timer_speedup.clone(),
            det_timer: det_timer.clone(),
            timer_mul: timer_mul.clone(),
            input_seeded: input_seeded.clone(),
            security_state_seeded: security_state_seeded.clone(),
            input_payload: input_payload.clone(),
            printf_trace: printf_trace.clone(),
            vfl_scan_trace: vfl_scan_trace.clone(),
            derail_trace: derail_trace.clone(),
            no_usb_wrangler_race_fix: no_usb_wrangler_race_fix.clone(),
            force_iobsd: force_iobsd.clone(),
            force_iobsd_all: force_iobsd_all.clone(),
            sparse_vfl_mask_seeded: sparse_vfl_mask_seeded.clone(),
            fsboot_trace: fsboot_trace.clone(),
            lcd_irq: lcd_irq.clone(),
            lcd_irq_armed: lcd_irq_armed.clone(),
            lcd_irq_budget: lcd_irq_budget.clone(),
            lcd_irq_arm_after_rootdev: lcd_irq_arm_after_rootdev.clone(),
            i2c_irq: i2c_irq.clone(),
            timer_irq: timer_irq.clone(),
            timer_irq_ready: timer_irq_ready.clone(),
            timer_irq_interval: timer_irq_interval.clone(),
            timer_irq_clock: timer_irq_clock.clone(),
            irq_trace: irq_trace.clone(),
            irq_trace_timer: irq_trace_timer.clone(),
            irq_trace_start_insn: irq_trace_start_insn.clone(),
            irq_trace_budget: irq_trace_budget.clone(),
            last_irq_trace: last_irq_trace.clone(),
            fiq_trace_budget: fiq_trace_budget.clone(),
            fiq_trace_start_insn: fiq_trace_start_insn.clone(),
            last_fiq_trace: last_fiq_trace.clone(),
            idle_trace: idle_trace.clone(),
            idle_trace_start_insn: idle_trace_start_insn.clone(),
            last_idle_trace_insn: last_idle_trace_insn.clone(),
            adm_irq_trace_budget: adm_irq_trace_budget.clone(),
            adm_irq_trace_start_insn: adm_irq_trace_start_insn.clone(),
            last_adm_irq_trace: last_adm_irq_trace.clone(),
            i2c_irq_trace_budget: i2c_irq_trace_budget.clone(),
            last_i2c1_irq_trace: last_i2c1_irq_trace.clone(),
            shutdown: shutdown.clone(),
        };
        let bridge = BridgeImage {
            mmu: MmuImage::capture(mmu),
            privileged: privileged.clone(),
            cur_pc: cur_pc.clone(),
            cur_insn: cur_insn.clone(),
            kernel_started: kernel_started.clone(),
            last_fault: last_fault.clone(),
            clock0: clock0.clone(),
            clock1: clock1.clone(),
            vic0: vic0.clone(),
            vic1: vic1.clone(),
            vic1_adm_daisy_latched: vic1_adm_daisy_latched.clone(),
            vic1_adm_daisy_in_service: vic1_adm_daisy_in_service.clone(),
            sysic: sysic.clone(),
            gpio: gpio.clone(),
            timer: timer.clone(),
            i2c0: i2c0.clone(),
            i2c1: i2c1.clone(),
            spi0: spi0.clone(),
            spi1: spi1.clone(),
            spi2: spi2.clone(),
            lcd: lcd.clone(),
            nand_ecc: nand_ecc.clone(),
            sdio: sdio.clone(),
            aes: aes.clone(),
            dmac0: dmac0.clone(),
            dmac1: dmac1.clone(),
            usb: usb.clone(),
            nor: nor.clone(),
            adm_data2: adm_data2.clone(),
            adm_data3: adm_data3.clone(),
            adm_req: adm_req.clone(),
            adm_irq: adm_irq.clone(),
            engine_8900_req: engine_8900_req.clone(),
            openbus_log_budget: openbus_log_budget.clone(),
            devlog: devlog.clone(),
            vic_trace_budget: vic_trace_budget.clone(),
            vic_trace_start_insn: vic_trace_start_insn.clone(),
            vic_trace_adm: vic_trace_adm.clone(),
        };
        if !Arc::ptr_eq(&source.uart, &inner.uart) {
            return Err(invalid("source UART owner aliases differ"));
        }
        let uart = source
            .uart
            .get()
            .map(|uart| match scope {
                Some(scope) => scope.capture_s3c_uart(uart),
                None => uart
                    .lock()
                    .map_err(|_| invalid("UART lock poisoned"))?
                    .checkpoint_clone(),
            })
            .transpose()?;
        let image = Self {
            runtime,
            bridge,
            uart,
        };
        image.validate()?;
        Ok(image)
    }
    fn validate_devices(v: &BridgeInner) -> Result<()> {
        v.vic0.validate_checkpoint()?;
        v.vic1.validate_checkpoint()?;
        v.dmac0.validate_checkpoint()?;
        v.dmac1.validate_checkpoint()?;
        v.i2c0.validate_checkpoint(false, true)?;
        v.i2c1.validate_checkpoint(true, false)?;
        v.spi0.validate_checkpoint(0)?;
        v.spi1.validate_checkpoint(1)?;
        v.spi2.validate_checkpoint(2)?;
        v.usb.validate_checkpoint()?;
        v.lcd.validate_checkpoint()?;
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        let r = &self.runtime;
        crate::backend::emulator::aarch32::context::validate_cpu(&r.cpu)?;
        if r.cpu.cp15.midr != 0x410f_b767
            || r.cpu.cp15.ctr != 0x1d15_2152
            || r.pc_ring_idx >= 512
            || (r.excl.address.is_some() && !matches!(r.excl.size, 1 | 2 | 4 | 8))
            || self.bridge.mmu.ttbcr_n > 7
            || self.bridge.nor.unlock_step > 2
        {
            return Err(invalid("core/profile/cursor shape differs"));
        }
        r.guest_profile.validate()?;
        ElapsedClock::suspended(r.boot_clock)?;
        ElapsedClock::suspended(r.heartbeat_clock)?;
        self.bridge.vic0.validate_checkpoint()?;
        self.bridge.vic1.validate_checkpoint()?;
        self.bridge.dmac0.validate_checkpoint()?;
        self.bridge.dmac1.validate_checkpoint()?;
        self.bridge.i2c0.validate_checkpoint(false, true)?;
        self.bridge.i2c1.validate_checkpoint(true, false)?;
        self.bridge.spi0.validate_checkpoint(0)?;
        self.bridge.spi1.validate_checkpoint(1)?;
        self.bridge.spi2.validate_checkpoint(2)?;
        self.bridge.usb.validate_checkpoint()?;
        self.bridge.lcd.validate_checkpoint()?;
        Ok(())
    }
    pub(super) fn id(&self) -> u32 {
        self.runtime.id
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = IMAGE_TAG.to_vec();
        bytes.extend_from_slice(
            &crate::codec::serialize_limited(self, MAX_STATE - 8).map_err(invalid)?,
        );
        Ok(bytes)
    }
    pub(super) fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_STATE || !raw.starts_with(IMAGE_TAG) {
            return Err(invalid("state tag/length differs"));
        }
        let value: Self = crate::codec::deserialize_limited::<_, { MAX_STATE - 8 }>(&raw[8..])
            .map_err(invalid)?;
        value.validate()?;
        Ok(value)
    }
    pub(super) fn into_cpu(
        self,
        mem: Arc<GuestMemoryMmap>,
        nand: S5lNand,
        uart: Arc<OnceLock<Arc<Mutex<S3cUart>>>>,
    ) -> Result<(S5L8900Vcpu, Option<S3cUart>)> {
        self.validate()?;
        let Self {
            runtime,
            bridge,
            uart: saved_uart,
        } = self;
        let RuntimeImage {
            id,
            cpu,
            insn_count,
            excl,
            pc_ring,
            pc_ring_idx,
            zero_slide,
            trace_pcs,
            trace_log_budget,
            trace_start_insn,
            pc_sample_interval,
            pc_sample_next_insn,
            pc_sample_remaining,
            trace_all,
            storage_call_trace_seen,
            storage_call_trace_remaining,
            storage_call_trace_start_insn,
            fdisk_trace_seen,
            fdisk_trace_remaining,
            nandftl_trace_seen,
            nandftl_trace_remaining,
            wmr_trace_seen,
            wmr_trace_remaining,
            wmr_init_active,
            partition_trace_remaining,
            iokit_match_follow_remaining,
            kernel_trace_remaining,
            root_trace_remaining,
            root_trace_start_insn,
            root_boot_trace_remaining,
            root_boot_trace_start_insn,
            apple_arm_function_trace_remaining,
            iokit_lifetime_trace_remaining,
            iokit_retain_trace,
            ioreg_free_trace_remaining,
            iokit_watch_object,
            iokit_watch_trace_remaining,
            sdio_power_trace_remaining,
            iokit_message_trace_remaining,
            pmqueue_trace_remaining,
            admfmc_trace_remaining,
            kernel_entry_logged,
            kernel_fault_log_remaining,
            kernel_exception_log_remaining,
            fault_log_budget,
            heartbeat_clock,
            boot_clock,
            guest_profile,
            timer_speedup,
            det_timer,
            timer_mul,
            input_seeded,
            security_state_seeded,
            input_payload,
            printf_trace,
            vfl_scan_trace,
            derail_trace,
            no_usb_wrangler_race_fix,
            force_iobsd,
            force_iobsd_all,
            sparse_vfl_mask_seeded,
            fsboot_trace,
            lcd_irq,
            lcd_irq_armed,
            lcd_irq_budget,
            lcd_irq_arm_after_rootdev,
            i2c_irq,
            timer_irq,
            timer_irq_ready,
            timer_irq_interval,
            timer_irq_clock,
            irq_trace,
            irq_trace_timer,
            irq_trace_start_insn,
            irq_trace_budget,
            last_irq_trace,
            fiq_trace_budget,
            fiq_trace_start_insn,
            last_fiq_trace,
            idle_trace,
            idle_trace_start_insn,
            last_idle_trace_insn,
            adm_irq_trace_budget,
            adm_irq_trace_start_insn,
            last_adm_irq_trace,
            i2c_irq_trace_budget,
            last_i2c1_irq_trace,
            shutdown,
        } = runtime;
        let BridgeImage {
            mmu,
            privileged,
            cur_pc,
            cur_insn,
            kernel_started,
            last_fault,
            clock0,
            clock1,
            vic0,
            vic1,
            vic1_adm_daisy_latched,
            vic1_adm_daisy_in_service,
            sysic,
            gpio,
            timer,
            i2c0,
            i2c1,
            spi0,
            spi1,
            spi2,
            lcd,
            nand_ecc,
            sdio,
            aes,
            dmac0,
            dmac1,
            usb,
            nor,
            adm_data2,
            adm_data3,
            adm_req,
            adm_irq,
            engine_8900_req,
            openbus_log_budget,
            devlog,
            vic_trace_budget,
            vic_trace_start_insn,
            vic_trace_adm,
        } = bridge;
        let bridge = S5lBridge {
            mem,
            inner: RefCell::new(BridgeInner {
                mmu: mmu.into_config(),
                privileged: privileged,
                cur_pc: cur_pc,
                cur_insn: cur_insn,
                kernel_started: kernel_started,
                last_fault: last_fault,
                clock0: clock0,
                clock1: clock1,
                vic0: vic0,
                vic1: vic1,
                vic1_adm_daisy_latched: vic1_adm_daisy_latched,
                vic1_adm_daisy_in_service: vic1_adm_daisy_in_service,
                sysic: sysic,
                gpio: gpio,
                timer: timer,
                i2c0: i2c0,
                i2c1: i2c1,
                spi0: spi0,
                spi1: spi1,
                spi2: spi2,
                lcd: lcd,
                nand: nand,
                nand_ecc: nand_ecc,
                sdio: sdio,
                aes: aes,
                dmac0: dmac0,
                dmac1: dmac1,
                usb: usb,
                nor: nor,
                adm_data2: adm_data2,
                adm_data3: adm_data3,
                adm_req: adm_req,
                adm_irq: adm_irq,
                uart: uart.clone(),
                engine_8900_req: engine_8900_req,
                openbus_log_budget: openbus_log_budget,
                devlog: devlog,
                vic_trace_budget: vic_trace_budget,
                vic_trace_start_insn: vic_trace_start_insn,
                vic_trace_adm: vic_trace_adm,
            }),
        };
        let cpu = S5L8900Vcpu {
            id: id,
            cpu: cpu,
            bridge: bridge,
            decoder: Decoder::new_aarch32(),
            uart: uart,
            insn_count: insn_count,
            excl: ExclusiveMonitor {
                address: excl.address,
                size: excl.size,
            },
            pc_ring: pc_ring,
            pc_ring_idx: pc_ring_idx,
            zero_slide: zero_slide,
            trace_pcs: trace_pcs,
            trace_log_budget: trace_log_budget,
            trace_start_insn: trace_start_insn,
            pc_sample_interval: pc_sample_interval,
            pc_sample_next_insn: pc_sample_next_insn,
            pc_sample_remaining: pc_sample_remaining,
            trace_all: trace_all,
            storage_call_trace_seen: storage_call_trace_seen,
            storage_call_trace_remaining: storage_call_trace_remaining,
            storage_call_trace_start_insn: storage_call_trace_start_insn,
            fdisk_trace_seen: fdisk_trace_seen,
            fdisk_trace_remaining: fdisk_trace_remaining,
            nandftl_trace_seen: nandftl_trace_seen,
            nandftl_trace_remaining: nandftl_trace_remaining,
            wmr_trace_seen: wmr_trace_seen,
            wmr_trace_remaining: wmr_trace_remaining,
            wmr_init_active: wmr_init_active,
            partition_trace_remaining: partition_trace_remaining,
            iokit_match_follow_remaining: iokit_match_follow_remaining,
            kernel_trace_remaining: kernel_trace_remaining,
            root_trace_remaining: root_trace_remaining,
            root_trace_start_insn: root_trace_start_insn,
            root_boot_trace_remaining: root_boot_trace_remaining,
            root_boot_trace_start_insn: root_boot_trace_start_insn,
            apple_arm_function_trace_remaining: apple_arm_function_trace_remaining,
            iokit_lifetime_trace_remaining: iokit_lifetime_trace_remaining,
            iokit_retain_trace: iokit_retain_trace,
            ioreg_free_trace_remaining: ioreg_free_trace_remaining,
            iokit_watch_object: iokit_watch_object,
            iokit_watch_trace_remaining: iokit_watch_trace_remaining,
            sdio_power_trace_remaining: sdio_power_trace_remaining,
            iokit_message_trace_remaining: iokit_message_trace_remaining,
            pmqueue_trace_remaining: pmqueue_trace_remaining,
            admfmc_trace_remaining: admfmc_trace_remaining,
            kernel_entry_logged: kernel_entry_logged,
            kernel_fault_log_remaining: kernel_fault_log_remaining,
            kernel_exception_log_remaining: kernel_exception_log_remaining,
            fault_log_budget: fault_log_budget,
            heartbeat_clock: ElapsedClock::suspended(heartbeat_clock)?,
            boot_clock: ElapsedClock::suspended(boot_clock)?,
            guest_profile: Some(guest_profile),
            capture_owner: Arc::new(()),
            checkpoint_publication: None,
            timer_speedup: timer_speedup,
            det_timer: det_timer,
            timer_mul: timer_mul,
            input_seeded: input_seeded,
            security_state_seeded: security_state_seeded,
            input_payload: input_payload,
            printf_trace: printf_trace,
            vfl_scan_trace: vfl_scan_trace,
            derail_trace: derail_trace,
            no_usb_wrangler_race_fix: no_usb_wrangler_race_fix,
            force_iobsd: force_iobsd,
            force_iobsd_all: force_iobsd_all,
            sparse_vfl_mask_seeded: sparse_vfl_mask_seeded,
            fsboot_trace: fsboot_trace,
            lcd_irq: lcd_irq,
            lcd_irq_armed: lcd_irq_armed,
            lcd_irq_budget: lcd_irq_budget,
            lcd_irq_arm_after_rootdev: lcd_irq_arm_after_rootdev,
            i2c_irq: i2c_irq,
            timer_irq: timer_irq,
            timer_irq_ready: timer_irq_ready,
            timer_irq_interval: timer_irq_interval,
            timer_irq_clock: timer_irq_clock,
            irq_trace: irq_trace,
            irq_trace_timer: irq_trace_timer,
            irq_trace_start_insn: irq_trace_start_insn,
            irq_trace_budget: irq_trace_budget,
            last_irq_trace: last_irq_trace,
            fiq_trace_budget: fiq_trace_budget,
            fiq_trace_start_insn: fiq_trace_start_insn,
            last_fiq_trace: last_fiq_trace,
            idle_trace: idle_trace,
            idle_trace_start_insn: idle_trace_start_insn,
            last_idle_trace_insn: last_idle_trace_insn,
            adm_irq_trace_budget: adm_irq_trace_budget,
            adm_irq_trace_start_insn: adm_irq_trace_start_insn,
            last_adm_irq_trace: last_adm_irq_trace,
            i2c_irq_trace_budget: i2c_irq_trace_budget,
            last_i2c1_irq_trace: last_i2c1_irq_trace,
            shutdown: shutdown,
        };
        Ok((cpu, saved_uart))
    }
    pub(super) fn empty(id: u32) -> Result<Self> {
        let mut cpu = Armv7Cpu::new();
        cpu.cp15.midr = 0x410f_b767;
        cpu.cp15.ctr = 0x1d15_2152;
        Ok(Self {
            runtime: RuntimeImage {
                id: id,
                cpu: cpu,
                insn_count: 0,
                excl: ExclusiveImage {
                    address: None,
                    size: 0,
                },
                pc_ring: [0; 512],
                pc_ring_idx: 0,
                zero_slide: 0,
                trace_pcs: Vec::new(),
                trace_log_budget: 0,
                trace_start_insn: 0,
                pc_sample_interval: 0,
                pc_sample_next_insn: 0,
                pc_sample_remaining: 0,
                trace_all: false,
                storage_call_trace_seen: Vec::new(),
                storage_call_trace_remaining: 0,
                storage_call_trace_start_insn: 0,
                fdisk_trace_seen: Vec::new(),
                fdisk_trace_remaining: 0,
                nandftl_trace_seen: Vec::new(),
                nandftl_trace_remaining: 0,
                wmr_trace_seen: Vec::new(),
                wmr_trace_remaining: 0,
                wmr_init_active: false,
                partition_trace_remaining: 0,
                iokit_match_follow_remaining: 0,
                kernel_trace_remaining: 0,
                root_trace_remaining: 0,
                root_trace_start_insn: 0,
                root_boot_trace_remaining: 0,
                root_boot_trace_start_insn: 0,
                apple_arm_function_trace_remaining: 0,
                iokit_lifetime_trace_remaining: 0,
                iokit_retain_trace: false,
                ioreg_free_trace_remaining: 0,
                iokit_watch_object: None,
                iokit_watch_trace_remaining: 0,
                sdio_power_trace_remaining: 0,
                iokit_message_trace_remaining: 0,
                pmqueue_trace_remaining: 0,
                admfmc_trace_remaining: 0,
                kernel_entry_logged: false,
                kernel_fault_log_remaining: 0,
                kernel_exception_log_remaining: 0,
                fault_log_budget: 0,
                heartbeat_clock: ElapsedImage::zero(),
                boot_clock: ElapsedImage::zero(),
                guest_profile: GuestProfile::default(),
                timer_speedup: 0,
                det_timer: 0,
                timer_mul: 0,
                input_seeded: false,
                security_state_seeded: false,
                input_payload: None,
                printf_trace: false,
                vfl_scan_trace: false,
                derail_trace: false,
                no_usb_wrangler_race_fix: false,
                force_iobsd: false,
                force_iobsd_all: false,
                sparse_vfl_mask_seeded: [false; 8],
                fsboot_trace: false,
                lcd_irq: false,
                lcd_irq_armed: false,
                lcd_irq_budget: 0,
                lcd_irq_arm_after_rootdev: false,
                i2c_irq: false,
                timer_irq: false,
                timer_irq_ready: 0,
                timer_irq_interval: 0,
                timer_irq_clock: 0,
                irq_trace: false,
                irq_trace_timer: false,
                irq_trace_start_insn: 0,
                irq_trace_budget: 0,
                last_irq_trace: 0,
                fiq_trace_budget: 0,
                fiq_trace_start_insn: 0,
                last_fiq_trace: 0,
                idle_trace: false,
                idle_trace_start_insn: 0,
                last_idle_trace_insn: 0,
                adm_irq_trace_budget: 0,
                adm_irq_trace_start_insn: 0,
                last_adm_irq_trace: 0,
                i2c_irq_trace_budget: 0,
                last_i2c1_irq_trace: 0,
                shutdown: false,
            },
            bridge: BridgeImage {
                mmu: MmuImage::capture(&V6MmuConfig::default()),
                privileged: false,
                cur_pc: 0,
                cur_insn: 0,
                kernel_started: false,
                last_fault: LastFault::default(),
                clock0: S5lClock::new(),
                clock1: S5lClock::new(),
                vic0: Pl192::new(),
                vic1: Pl192::new(),
                vic1_adm_daisy_latched: false,
                vic1_adm_daisy_in_service: false,
                sysic: S5lSysic::new(),
                gpio: S5lGpio::new(),
                timer: S5lTimer::new(),
                i2c0: S5lI2c::new(false, true),
                i2c1: S5lI2c::new(true, false),
                spi0: S5lSpi::new_checkpoint_target(0),
                spi1: S5lSpi::new_checkpoint_target(1),
                spi2: S5lSpi::new_checkpoint_target(2),
                lcd: S5lLcd::new(),
                nand_ecc: S5lNandEcc::new(),
                sdio: S5lSdio::new(),
                aes: S5lAes::new(),
                dmac0: S5lDmac::new(),
                dmac1: S5lDmac::new(),
                usb: S5lUsb::new(),
                nor: S5lNor::default(),
                adm_data2: 0,
                adm_data3: 0,
                adm_req: None,
                adm_irq: false,
                engine_8900_req: None,
                openbus_log_budget: 0,
                devlog: false,
                vic_trace_budget: 0,
                vic_trace_start_insn: 0,
                vic_trace_adm: false,
            },
            uart: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(image: &Image) -> Vec<u8> {
        let mut raw = IMAGE_TAG.to_vec();
        raw.extend_from_slice(&crate::codec::serialize(image).unwrap());
        raw
    }
    #[test]
    fn complete_image_decoder_rejects_semantically_invalid_profiles_and_cursors() {
        for case in 0..8 {
            let mut image = Image::empty(0).unwrap();
            match case {
                0 => image.runtime.pc_ring_idx = 512,
                1 => image.runtime.cpu.instruction_size = 3,
                2 => image.runtime.cpu.cp15.midr = 0,
                3 => image.bridge.mmu.ttbcr_n = 8,
                4 => image.bridge.nor.unlock_step = 3,
                5 => {
                    image.runtime.excl.address = Some(4);
                    image.runtime.excl.size = 3;
                }
                6 => image.runtime.guest_profile.gid_key = Some(vec![0]),
                7 => {
                    let mut bytes = 0u64.to_le_bytes().to_vec();
                    bytes.extend_from_slice(&1_000_000_000u32.to_le_bytes());
                    image.runtime.boot_clock = crate::codec::deserialize_strict(&bytes).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(Image::decode(&raw(&image)).is_err(), "case={case}");
        }
    }
    #[test]
    fn complete_image_fixed_prefix_roundtrip_and_strict_frame_admission() {
        let source = Image::empty(3).unwrap();
        let encoded = source.encode().unwrap();
        assert_eq!(Image::decode(&encoded).unwrap().encode().unwrap(), encoded);
        for end in [0, 1, 7, 8, 9, encoded.len() - 1] {
            assert!(Image::decode(&encoded[..end]).is_err());
        }
        let mut bytes = encoded.clone();
        bytes.push(0);
        assert!(Image::decode(&bytes).is_err());
        let mut bytes = encoded;
        bytes[0] ^= 1;
        assert!(Image::decode(&bytes).is_err());
    }
}
