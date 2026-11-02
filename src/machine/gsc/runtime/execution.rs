//! GSC platform-aware execution and guest control.
use super::*;

impl GscVcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        let cfg = GscConfig::from_env();
        install_synthetic_cryptolib(&mem);
        let uart_rx = std::env::var("RAX_GSC_UART_RX")
            .map(|s| s.into_bytes().into())
            .unwrap_or_default();
        let shared: Shared = Arc::new(Mutex::new(GscShared {
            rstsrc: cfg.rstsrc_cold,
            uart_rx,
            timer_compare: u64::MAX,
            ..GscShared::default()
        }));
        let mut ready = builtin_ready_map();
        // The console UART STATE register reads back "TX ready" so the
        // firmware's transmit-ready poll always passes, at whatever base.
        ready.insert(cfg.uart_base + UART_STATE, cfg.uart_state);
        // `RAX_GSC_AP_ON=1` deasserts PLT_RST_L (GPIO bank0 bit11) so the
        // firmware sees the AP host powered on and processes TPM commands
        // instead of dropping them "while AP off".
        if std::env::var("RAX_GSC_AP_ON").is_ok() {
            let v = ready.entry(GPIO_INPUT_BANK0).or_insert(0);
            *v |= GPIO_PLT_RST_L_MASK;
        }
        ready.extend(parse_ready_env());
        let pc_cell = Arc::new(AtomicU64::new(0));
        let time_cell = Arc::new(AtomicU64::new(0));
        let bridge = GscBridge {
            mem,
            shared: shared.clone(),
            ap_flash: load_ap_flash_from_env(),
            cfg,
            ready,
            pc: pc_cell.clone(),
            time: time_cell.clone(),
            crypto_trace: std::env::var("RAX_GSC_CRYPTO_TRACE").is_ok(),
        };
        let cpu = RiscVCpu::new(RiscVConfig::rv32(Isa::ti50()), Box::new(bridge));
        GscVcpu {
            id,
            cpu,
            shared,
            cfg,
            halted: false,
            reset_entry: 0,
            reset_count: 0,
            pc_cell,
            time_cell,
            break_pc: env_hex("RAX_GSC_BREAK"),
            break_hit: env_hex("RAX_GSC_BREAK_HIT").unwrap_or(1).max(1),
            break_ra: env_hex("RAX_GSC_BREAK_RA"),
            break_saved_ra: env_hex("RAX_GSC_BREAK_SAVED_RA"),
            break_stack_bytes: env_hex("RAX_GSC_BREAK_STACK").unwrap_or(0),
            break_stop: std::env::var("RAX_GSC_BREAK_STOP").is_ok(),
            syscall_trace: std::env::var("RAX_GSC_SYSCALL_TRACE").is_ok(),
            print_trace: std::env::var("RAX_GSC_PRINT_TRACE").is_ok(),
            ap_ro_stub: cfg.ap_ro_stub,
            ap_ro_crypto_stub: cfg.ap_ro_crypto_stub || cfg.ap_ro_stub,
            break_hits_seen: 0,
            broke: false,
            tpm_cmds: parse_tpm_cmds_env(),
            tpm_trigger: env_hex("RAX_GSC_TPM_TRIGGER").unwrap_or(0xa2d3c),
            tpm_yield_mode: std::env::var("RAX_GSC_TPM_MODE").as_deref() != Ok("call"),
            tpm_wired: std::env::var("RAX_GSC_TPM_WIRED").is_ok(),
            tpm: TpmInject::default(),
            plt_rst_event: std::env::var("RAX_GSC_PLT_RST_EVENT").is_ok(),
            plt_rst_fired: false,
            entropy_hooks: !std::env::var("RAX_GSC_NO_ENTROPY").is_ok(),
            entropy_state: 0x243f_6a88_85a3_08d3,
        }
    }

    /// Drain a pending warm-reset request, returning whether the run loop should
    /// reboot the hart. Enforces the [`MAX_RESETS`] loop guard.
    fn take_reset(&mut self) -> Option<VcpuExit> {
        let requested = {
            let mut sh = self.shared.lock().unwrap();
            std::mem::take(&mut sh.reset_requested)
        };
        if !requested {
            return None;
        }
        self.reset_count += 1;
        if self.reset_count > MAX_RESETS {
            self.halted = true;
            return Some(VcpuExit::Unknown(format!(
                "gsc: firmware reboot loop ({} resets) without reaching console",
                self.reset_count
            )));
        }
        if self.cfg.trace != Trace::Off {
            eprintln!(
                "[gsc] warm reset #{} -> entry {:#x}",
                self.reset_count, self.reset_entry
            );
        }
        // After a software reset the firmware must see a non-POR cause, else it
        // re-runs POR init and reboots again.
        self.shared.lock().unwrap().rstsrc = self.cfg.rstsrc_warm;
        self.cpu.reset(self.reset_entry);
        None
    }

    /// Snapshot of console bytes emitted so far (for tests / introspection).
    pub fn console(&self) -> Vec<u8> {
        self.shared.lock().unwrap().console.clone()
    }

    fn sync_machine_external_irq(&mut self) {
        let (meip, compare) = {
            let sh = self.shared.lock().unwrap();
            (
                sh.uart_irq_armed && !sh.uart_rx.is_empty(),
                sh.timer_compare,
            )
        };
        self.cpu.set_interrupt_pending(MIP_MEIP, meip);
        // Machine timer: assert MTIP while the free-running counter (derived
        // from retired instructions, same source as the 0x400C0014/+0x1C reads)
        // has reached the alarm compare. The firmware's cause-7 ISR re-arms or
        // disarms the compare, which clears MTIP on the next sync.
        let counter = self.cpu.instret() / self.cfg.timer_div.max(1);
        self.cpu.set_interrupt_pending(MIP_MTIP, counter >= compare);
    }

    #[inline]
    fn read_guest_u32(&self, addr: u64) -> u32 {
        let mut w = [0u8; 4];
        if self.cpu.read_memory(addr, &mut w).is_ok() {
            u32::from_le_bytes(w)
        } else {
            0
        }
    }

    /// Fill `count` bytes of guest memory at `dest` with PRNG output (SplitMix64
    /// advanced per call). Used by the TPM randomness hooks so generated random
    /// numbers, nonces, and keys are non-zero.
    fn fill_entropy(&mut self, dest: u64, count: u64) {
        let count = count.min(4096) as usize;
        let mut bytes = Vec::with_capacity(count);
        while bytes.len() < count {
            self.entropy_state = self.entropy_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.entropy_state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            bytes.extend_from_slice(&z.to_le_bytes());
        }
        bytes.truncate(count);
        let _ = self.cpu.write_memory(dest, &bytes);
    }

    /// Service a TPM randomness primitive by guest PC: fill its destination
    /// buffer with PRNG bytes, set the return value to the requested length,
    /// and return to the caller (skipping the zero-writing kernel `ecall`).
    /// Returns `true` if `pc` was a randomness function.
    fn maybe_fill_random(&mut self, pc: u64) -> bool {
        let (dest, count) = match pc {
            // CryptRandomGenerate(ctx=a0, dest=a1, count=a2)
            TPM_RAND_GENERATE | TPM_RAND_GENERATE_B => (self.cpu.x(11), self.cpu.x(12)),
            // nonce fill(count=a0, dest=a1)
            TPM_RAND_NONCE | TPM_RAND_NONCE_B => (self.cpu.x(11), self.cpu.x(10)),
            _ => return false,
        };
        if count == 0 || count > 4096 {
            return false;
        }
        self.fill_entropy(dest, count);
        self.cpu.set_x(10, count); // return the byte count (success)
        let ra = self.cpu.x(1);
        self.cpu.set_pc(ra);
        true
    }

    /// Begin a synthetic call into the TPM 2.0 ExecuteCommand wrapper
    /// (`sub_E06BE`) with `cmd`. Stages the command and the two by-reference
    /// argument slots in scratch RAM, snapshots the CPU state, masks
    /// interrupts, and redirects the hart into the wrapper with a sentinel
    /// return address. The normal run loop then executes the call to
    /// completion; [`finish_tpm_call`] captures the response.
    fn begin_tpm_call(&mut self, cmd: &[u8]) {
        let _ = self.cpu.write_memory(TPM_SCRATCH_BUF, cmd);
        let _ = self
            .cpu
            .write_memory(TPM_SCRATCH_CAP, &TPM_SCRATCH_CAPACITY.to_le_bytes());
        let _ = self
            .cpu
            .write_memory(TPM_SCRATCH_BUFPTR, &(TPM_SCRATCH_BUF as u32).to_le_bytes());

        for i in 0..32u8 {
            self.tpm.saved_x[i as usize] = self.cpu.x(i);
        }
        self.tpm.saved_pc = self.cpu.pc();
        self.tpm.saved_mstatus = self.cpu.csr_read(0x300).unwrap_or(0);
        self.tpm.saved_mie = self.cpu.csr_read(0x304).unwrap_or(0);
        self.tpm.cap_slot = TPM_SCRATCH_CAP;
        self.tpm.bufptr_slot = TPM_SCRATCH_BUFPTR;
        self.tpm.call_start_instret = self.cpu.instret();

        // a0=len, a1=buf, a2=&cap, a3=&bufptr; ra=sentinel.
        self.cpu.set_x(10, cmd.len() as u64);
        self.cpu.set_x(11, TPM_SCRATCH_BUF);
        self.cpu.set_x(12, TPM_SCRATCH_CAP);
        self.cpu.set_x(13, TPM_SCRATCH_BUFPTR);
        self.cpu.set_x(1, TPM_CALL_SENTINEL);
        // Mask interrupts so the timer/UART can't divert the synthetic call.
        let _ = self.cpu.csr_write(0x304, 0);
        let _ = self.cpu.csr_write(0x300, self.tpm.saved_mstatus & !0x8);
        self.cpu.set_pc(TPM_EXECUTE_WRAPPER);
        self.tpm.in_call = true;

        let preview: String = cmd.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "[gsc] TPM inject #{}: sub_E06BE(len={}, cmd={preview})",
            self.tpm.next + 1,
            cmd.len()
        );
    }

    /// Restore the pre-call register/CSR snapshot so the firmware resumes its
    /// idle loop as if the synthetic call never happened.
    fn restore_tpm_state(&mut self) {
        for i in 1..32u8 {
            self.cpu.set_x(i, self.tpm.saved_x[i as usize]);
        }
        let _ = self.cpu.csr_write(0x304, self.tpm.saved_mie);
        let _ = self.cpu.csr_write(0x300, self.tpm.saved_mstatus);
        self.cpu.set_pc(self.tpm.saved_pc);
        self.tpm.in_call = false;
    }

    /// Capture and print the TPM response left by the synthetic call, then
    /// restore state and advance to the next queued command. Returns `true`
    /// when no commands remain (the run loop should halt).
    fn finish_tpm_call(&mut self) -> bool {
        let rc_reg = self.cpu.x(10);
        let cap = self.read_guest_u32(self.tpm.cap_slot);
        let bufptr = self.read_guest_u32(self.tpm.bufptr_slot) as u64;
        // TPM response framing is big-endian: tag[0:2], size[2:6], code[6:10].
        let mut hdr = [0u8; 10];
        let resp_size = if self.cpu.read_memory(bufptr, &mut hdr).is_ok() {
            u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]])
        } else {
            0
        };
        let len = resp_size.min(cap.max(resp_size)).min(512) as usize;
        let mut resp = vec![0u8; len];
        let _ = self.cpu.read_memory(bufptr, &mut resp);
        let code = if resp.len() >= 10 {
            u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]])
        } else {
            0xffff_ffff
        };
        let hexs: String = resp.iter().map(|b| format!("{b:02x}")).collect();
        let status = if code == 0 { "SUCCESS" } else { "rc!=0" };
        eprintln!(
            "[gsc] TPM resp  #{}: ret_a0={rc_reg:#x} size={resp_size} rc={code:#010x} ({status}) bytes={hexs}",
            self.tpm.next + 1
        );

        self.restore_tpm_state();
        self.tpm.next += 1;
        self.tpm.next >= self.tpm_cmds.len()
    }

    /// `yield` mode: plant a command into the TPM task's command-processor
    /// globals at its command-wait yield. After the caller skips the `ecall`,
    /// the firmware task loops back, sees the pending flag, and runs the real
    /// `sub_E06BE` path in its own scheduler context (all upcalls registered).
    fn plant_tpm_command(&mut self, cmd: &[u8]) {
        // Wired transport stages the frame in the real GscFifo dual-port RAM
        // window; otherwise a backed-RAM scratch buffer is used.
        let (buf, cap) = if self.tpm_wired {
            (GSC_FIFO_RAM_BASE, GSC_FIFO_RAM_LEN as u32)
        } else {
            (TPM_SCRATCH_BUF, TPM_SCRATCH_CAPACITY)
        };
        let _ = self.cpu.write_memory(buf, cmd);
        let _ = self
            .cpu
            .write_memory(TPM_GLOBAL_BUF, &(buf as u32).to_le_bytes());
        let _ = self
            .cpu
            .write_memory(TPM_GLOBAL_LEN, &(cmd.len() as u32).to_le_bytes());
        let _ = self.cpu.write_memory(TPM_GLOBAL_CAP, &cap.to_le_bytes());
        let _ = self
            .cpu
            .write_memory(TPM_GLOBAL_PENDING, &1u32.to_le_bytes());
        self.tpm.awaiting = true;
        self.shared.lock().unwrap().tpm_active = true;
        if std::env::var("RAX_GSC_TPM_TRACE").is_ok() {
            self.tpm.trace_budget = 6000;
        }
        let preview: String = cmd.iter().map(|b| format!("{b:02x}")).collect();
        let via = if self.tpm_wired {
            "wired via GscFifo 0x40621000"
        } else {
            "yield"
        };
        eprintln!(
            "[gsc] TPM inject #{} ({via}): {}-byte command {preview}",
            self.tpm.next + 1,
            cmd.len()
        );
    }

    /// `yield` mode: at the response-send entry (`sub_D4B80`) the response is
    /// already marshalled in the `0x220C0` buffer with its length in `a1`.
    /// Capture and print it. A `>= 10`-byte buffer is a real TPM response
    /// (tag/size/rc); a short buffer means the firmware dropped the command
    /// (e.g. the "while AP off" policy). Returns `true` to halt afterward.
    fn capture_tpm_response(&mut self) -> bool {
        let bufptr = self.read_guest_u32(TPM_GLOBAL_BUF) as u64;
        let len = (self.cpu.x(11) as u32).min(1024) as usize;
        let mut resp = vec![0u8; len];
        let _ = self.cpu.read_memory(bufptr, &mut resp);
        let via = if self.tpm_wired { "wired" } else { "yield" };
        if resp.len() >= 10 {
            let code = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            let hexs: String = resp.iter().map(|b| format!("{b:02x}")).collect();
            let status = if code == 0 { "SUCCESS" } else { "rc!=0" };
            eprintln!(
                "[gsc] TPM resp  #{} ({via}): len={len} rc={code:#010x} ({status}) bytes={hexs}",
                self.tpm.next + 1
            );
        } else {
            eprintln!(
                "[gsc] TPM cmd  #{} ({via}): firmware processed the command but returned \
                 no TPM response (len={len}) — see the firmware log above (e.g. it drops \
                 commands \"while AP off\" when PLT_RST_L is asserted / the host is in reset).",
                self.tpm.next + 1
            );
        }
        self.tpm.awaiting = false;
        self.shared.lock().unwrap().tpm_active = false;
        self.tpm.next += 1;
        if self.tpm.next >= self.tpm_cmds.len() {
            return true;
        }
        // More commands queued: short-circuit the host-less send (return
        // success to the caller) so the task loops back to its command-wait
        // yield, where the next command is planted.
        let ra = self.cpu.x(1);
        self.cpu.set_x(10, 0);
        self.cpu.set_pc(ra);
        false
    }

    fn trap_exit(&self, t: crate::isa::riscv::Trap) -> VcpuExit {
        let mepc = self.cpu.csr_read(0x341).unwrap_or(self.cpu.pc());
        let raw = self.cpu.memory().read_u32(mepc).unwrap_or(0);
        VcpuExit::Unknown(format!(
            "gsc riscv trap: cause={} tval={:#x} pc={:#x} mepc={:#x} raw={:#010x} insn=[{}]",
            t.cause,
            t.tval,
            self.cpu.pc(),
            mepc,
            raw,
            self.cpu.disassemble_at(mepc),
        ))
    }
}

impl GscVcpu {
    /// One platform action, completing at most one guest instruction. Host hooks
    /// yield without retirement rather than hiding an unbounded retry loop.
    fn step_platform(&mut self) -> Result<Option<VcpuExit>> {
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }
        self.sync_machine_external_irq();
        let pc = self.cpu.pc();
        self.pc_cell.store(pc, Ordering::Relaxed);
        self.time_cell.store(self.cpu.instret(), Ordering::Relaxed);
        // Runtime PLT_RST_L deassert event: once the firmware has settled at
        // the idle WFI with the AP held in reset, deassert PLT_RST_L (drive
        // GPIO bank0 bit11 high) and pulse a GPIO wake so the kernel leaves
        // WFI and re-samples the line — modeling the host powering on while
        // the GSC is already running.
        if self.plt_rst_event && !self.plt_rst_fired && pc == self.tpm_trigger {
            let booted = {
                let sh = self.shared.lock().unwrap();
                sh.console.windows(11).any(|w| w == b"TPM SPI dis")
            };
            if booted {
                self.plt_rst_fired = true;
                {
                    let mut sh = self.shared.lock().unwrap();
                    // Drive PLT_RST_L high (deasserted) for the rest of the run.
                    let v = sh.store.entry(GPIO_INPUT_BANK0).or_insert(0);
                    *v |= GPIO_PLT_RST_L_MASK;
                    // The GSC reboots on an AP power-state change to re-run AP
                    // RO verification; request that warm reset so the firmware
                    // comes back up with the AP powered on (TPM SPI enabled),
                    // mirroring real "Rebooting GSC for AP RO due to state".
                    sh.reset_requested = true;
                }
                eprintln!(
                    "[gsc] runtime event: PLT_RST_L deasserted (host powering on); \
                     warm-resetting so the GSC re-boots AP-on"
                );
                return Ok(self.take_reset());
            }
        }
        // Entropy: intercept the TPM randomness primitives and fill their
        // output buffer with a PRNG (the kernel crypto service writes zeros
        // in this board model), so RNG/nonce/key output is non-zero.
        if self.entropy_hooks
            && matches!(
                pc,
                TPM_RAND_GENERATE | TPM_RAND_GENERATE_B | TPM_RAND_NONCE | TPM_RAND_NONCE_B
            )
            && self.maybe_fill_random(pc)
        {
            return Ok(None);
        }
        // TPM command injection. `yield` mode (default) plants each command
        // into the firmware TPM task at its command-wait yield so the task
        // processes it in its own scheduler context; `call` mode drives a
        // synthetic out-of-context call to the ExecuteCommand wrapper.
        if !self.tpm_cmds.is_empty() {
            if self.tpm_yield_mode {
                if self.tpm.awaiting
                    && self.tpm.trace_budget > 0
                    && std::env::var("RAX_GSC_TPM_TRACE").is_ok()
                {
                    self.tpm.trace_budget -= 1;
                    eprintln!(
                        "[tpmtrace] {:#010x}: {}  ra={:#x} a0={:#x} a1={:#x} a2={:#x}",
                        pc,
                        self.cpu.disasm_pc(),
                        self.cpu.x(1),
                        self.cpu.x(10),
                        self.cpu.x(11),
                        self.cpu.x(12)
                    );
                }
                // Capture the response at the response-send entry, before
                // the (host-less) send would block.
                if self.tpm.awaiting && pc == TPM_RESPONSE_SEND {
                    if self.capture_tpm_response() {
                        self.halted = true;
                        return Ok(Some(VcpuExit::Shutdown));
                    }
                    return Ok(None);
                }
                // Plant the next command at the task's command-wait yield.
                // When a runtime PLT_RST event is configured, wait until the
                // AP-power-on reboot has happened (so the AP is on).
                if !self.tpm.awaiting
                    && self.tpm.next < self.tpm_cmds.len()
                    && pc == TPM_TASK_YIELD_ECALL
                    && (!self.plt_rst_event || self.reset_count >= 1)
                {
                    let ready = {
                        let sh = self.shared.lock().unwrap();
                        sh.console.windows(8).any(|w| w == b"TPM SPI ")
                    };
                    if ready {
                        let cmd = self.tpm_cmds[self.tpm.next].clone();
                        self.plant_tpm_command(&cmd);
                        self.cpu.set_pc(TPM_TASK_YIELD_NEXT);
                        return Ok(None);
                    }
                }
            } else if self.tpm.in_call {
                if std::env::var("RAX_GSC_TPM_TRACE").is_ok() {
                    eprintln!(
                        "[tpmtrace] {:#010x}: {}  ra={:#x} sp={:#x} a0={:#x} a1={:#x}",
                        pc,
                        self.cpu.disasm_pc(),
                        self.cpu.x(1),
                        self.cpu.x(2),
                        self.cpu.x(10),
                        self.cpu.x(11)
                    );
                }
                if pc == TPM_CALL_SENTINEL {
                    if self.finish_tpm_call() {
                        self.halted = true;
                        return Ok(Some(VcpuExit::Shutdown));
                    }
                    return Ok(None);
                }
                // Off-the-rails guard: firmware code lives in the flash XIP
                // window (>= 0x80000). A jump below it (e.g. a null upcall
                // pointer this out-of-context call never registered) means
                // the synthetic call derailed deep inside the TPM stack.
                // The call already mutated global RAM, so the firmware is
                // not cleanly resumable: report and halt rather than fault.
                if pc < 0x8_0000 {
                    eprintln!(
                        "[gsc] TPM call #{} ran the TPM stack but derailed at {pc:#x} \
                         (unregistered upcall/client — the ExecuteCommand path is \
                         user-process code invoked out of its scheduler context). \
                         See the firmware log above for how far it got.",
                        self.tpm.next + 1
                    );
                    self.halted = true;
                    return Ok(Some(VcpuExit::Shutdown));
                }
                if self
                    .cpu
                    .instret()
                    .saturating_sub(self.tpm.call_start_instret)
                    > TPM_CALL_MAX_INSNS
                {
                    eprintln!(
                        "[gsc] TPM call #{} watchdog tripped at pc={pc:#x}; aborting injection",
                        self.tpm.next + 1
                    );
                    self.halted = true;
                    return Ok(Some(VcpuExit::Shutdown));
                }
            } else if self.tpm.next < self.tpm_cmds.len() && pc == self.tpm_trigger {
                let booted = {
                    let sh = self.shared.lock().unwrap();
                    sh.console.windows(11).any(|w| w == b"TPM SPI dis")
                };
                if booted {
                    let cmd = self.tpm_cmds[self.tpm.next].clone();
                    self.begin_tpm_call(&cmd);
                    return Ok(None);
                }
            }
        }
        // Diagnostic: log each GPIO pin sample (`sub_A2F30` @0xa2f38 has the
        // resolved bank base in a0 and the bit index in s0) to map signals
        // like plt_rst_l / ccd_mode_l to their (bank, bit).
        if pc == 0xa2f38 && std::env::var("RAX_GSC_GPIO_TRACE").is_ok() {
            eprintln!(
                "[gpio] sample bank={:#x} bit={} ra={:#x}",
                self.cpu.x(10),
                self.cpu.x(8),
                self.cpu.x(1)
            );
        }
        if self.ap_ro_stub && pc == 0xce910 {
            let sp = self.cpu.x(2);
            let mut expected = [0u8; 0x40];
            if self.cpu.read_memory(sp + 0x40, &mut expected).is_ok() {
                let _ = self.cpu.write_memory(sp, &expected);
            }
        }
        if self.ap_ro_crypto_stub && pc == 0xb2904 {
            let sp = self.cpu.x(2);
            let mut ptr = [0u8; 4];
            if self.cpu.read_memory(sp + 0x68, &mut ptr).is_ok() {
                let expected = u32::from_le_bytes(ptr) as u64;
                let mut digest = [0u8; 0x20];
                if self.cpu.read_memory(expected, &mut digest).is_ok() {
                    let _ = self.cpu.write_memory(sp + 0x250, &digest);
                }
            }
        }
        if self.ap_ro_crypto_stub && pc == 0xb1efe {
            let actual = self.cpu.x(18); // s2
            let actual_len = self.cpu.x(19); // s3
            let expected = self.cpu.x(21); // s5
            let expected_len = self.cpu.x(9); // s1
            if actual_len == expected_len && (1..=64).contains(&actual_len) {
                let mut digest = vec![0u8; actual_len as usize];
                if self.cpu.read_memory(expected, &mut digest).is_ok() {
                    let _ = self.cpu.write_memory(actual, &digest);
                }
            }
        }
        if self.ap_ro_stub && pc == 0xb7462 {
            // Kernel AP-RO verification returns here after reading AP
            // flash/GVD data over the AP SPI host. Without a real AP flash
            // image signed for this production root, the standalone
            // bring-up stub reports verifier success at the call boundary
            // and lets the firmware's normal success path run.
            self.cpu.set_x(10, 0);
        }
        if self.print_trace && matches!(pc, 0xce272 | 0x14e272) {
            let ptr = self.cpu.x(10);
            let len = self.cpu.x(11).min(96) as usize;
            let mut buf = vec![0u8; len];
            let preview = if self.cpu.read_memory(ptr, &mut buf).is_ok() {
                String::from_utf8_lossy(&buf)
                    .chars()
                    .map(|c| {
                        if c.is_ascii_graphic() || c == ' ' {
                            c
                        } else {
                            '.'
                        }
                    })
                    .collect::<String>()
            } else {
                "<unreadable>".to_string()
            };
            eprintln!(
                "[gsc] print pc={pc:#x} ptr={ptr:#x} len={:#x} {preview:?}",
                self.cpu.x(11)
            );
        }
        let saved_ra_matches = self
            .break_saved_ra
            .map(|expect| {
                let mut w = [0u8; 4];
                self.cpu.read_memory(self.cpu.x(2) + 0x11c, &mut w).is_ok()
                    && u32::from_le_bytes(w) as u64 == expect
            })
            .unwrap_or(true);
        let break_matches = self.break_pc == Some(pc)
            && self.break_ra.map(|ra| self.cpu.x(1) == ra).unwrap_or(true)
            && saved_ra_matches;
        if break_matches && !self.broke {
            self.break_hits_seen += 1;
        }
        if break_matches && !self.broke && self.break_hits_seen >= self.break_hit {
            self.broke = true;
            let x = |i: u8| self.cpu.x(i);
            eprintln!(
                "[gsc] BREAK @{:#x} hit={} ra={:#x} sp={:#x} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x} s0={:#x} s1={:#x} s2={:#x} s3={:#x} s4={:#x} s5={:#x} s6={:#x} s7={:#x} s8={:#x} s9={:#x} s10={:#x} s11={:#x}",
                pc,
                self.break_hits_seen,
                x(1),
                x(2),
                x(10),
                x(11),
                x(12),
                x(13),
                x(14),
                x(15),
                x(8),
                x(9),
                x(18),
                x(19),
                x(20),
                x(21),
                x(22),
                x(23),
                x(24),
                x(25),
                x(26),
                x(27)
            );
            let csr = |addr| self.cpu.csr_read(addr).unwrap_or(0);
            eprintln!(
                "[gsc] BREAK csr mstatus={:#x} mie={:#x} mip={:#x} mideleg={:#x} mtvec={:#x} mepc={:#x} mcause={:#x}",
                csr(0x300),
                csr(0x304),
                csr(0x344),
                csr(0x303),
                csr(0x305),
                csr(0x341),
                csr(0x342)
            );
            // Dump stack words that look like code return-addresses, to
            // reconstruct the call chain that led here.
            let sp = self.cpu.x(2);
            if self.break_stack_bytes != 0 {
                let dump_len = self.break_stack_bytes.min(0x400);
                for row in (0..dump_len).step_by(0x10) {
                    let mut words = Vec::new();
                    for off in (0..0x10u64).step_by(4) {
                        if row + off >= dump_len {
                            break;
                        }
                        let mut w = [0u8; 4];
                        if self.cpu.read_memory(sp + row + off, &mut w).is_ok() {
                            words.push(format!("{:#010x}", u32::from_le_bytes(w)));
                        } else {
                            words.push("????????".to_string());
                        }
                    }
                    eprintln!("[gsc]   stack +{row:03x}: {}", words.join(" "));
                }
            }
            let mut chain = Vec::new();
            for off in (0..0x80u64).step_by(4) {
                let mut w = [0u8; 4];
                if self.cpu.read_memory(sp + off, &mut w).is_ok() {
                    let v = u32::from_le_bytes(w) as u64;
                    if (0x8_0000..0x18_0000).contains(&v) {
                        chain.push(format!("{v:#x}"));
                    }
                }
            }
            eprintln!("[gsc] BREAK callstack: {}", chain.join(" "));
            // Scan registers + stack for pointers to ASCII strings in the
            // image (panic message / source location).
            let mut probes: Vec<u64> = (0..32u8).map(|i| self.cpu.x(i)).collect();
            for off in (0..0x100u64).step_by(4) {
                let mut w = [0u8; 4];
                if self.cpu.read_memory(sp + off, &mut w).is_ok() {
                    probes.push(u32::from_le_bytes(w) as u64);
                }
            }
            let mut seen_str = std::collections::BTreeSet::new();
            for p in probes {
                if !(0x8_0000..0x18_0000).contains(&p) {
                    continue;
                }
                let mut s = [0u8; 48];
                if self.cpu.read_memory(p, &mut s).is_ok() {
                    let n = s.iter().take_while(|&&b| (0x20..0x7f).contains(&b)).count();
                    if n >= 6 {
                        let txt = String::from_utf8_lossy(&s[..n]).to_string();
                        if seen_str.insert(txt.clone()) {
                            eprintln!("[gsc]   str@{p:#x}: {txt:?}");
                        }
                    }
                }
            }
            for (name, base) in [("a0", x(10)), ("a2", x(12)), ("s0", x(8)), ("s3", x(19))] {
                if !(0x1_0000..0x2_0000).contains(&base) {
                    continue;
                }
                let mut words = Vec::new();
                for off in (0..0x40u64).step_by(4) {
                    let mut w = [0u8; 4];
                    if self.cpu.read_memory(base + off, &mut w).is_ok() {
                        words.push(format!("+{off:02x}={:#010x}", u32::from_le_bytes(w)));
                    }
                }
                eprintln!("[gsc]   mem {name}@{base:#x}: {}", words.join(" "));
            }
            if self.break_stop {
                self.halted = true;
                return Ok(Some(VcpuExit::Unknown(format!(
                    "gsc breakpoint stop at {pc:#x}"
                ))));
            }
        }
        if self.cfg.trace == Trace::Insn {
            eprintln!("[gsc] {:#010x}: {}", self.cpu.pc(), self.cpu.disasm_pc());
        }
        let exit = self.cpu.step();
        // A firmware-requested warm reset reboots the hart in place; the
        // next iteration then fetches from the entry point. `take_reset`
        // returns `Some` only when the reboot guard trips.
        if let Some(reset_exit) = self.take_reset() {
            return Ok(Some(reset_exit));
        }
        match exit {
            RiscVExit::Continue => {}
            // WFI marks the point where the Tock driver tables are live.
            // Seeded UART RX bytes can now assert the external interrupt.
            RiscVExit::Wfi => {
                self.shared.lock().unwrap().uart_irq_armed = true;
            }
            RiscVExit::Ecall => {
                if self.syscall_trace {
                    let x = |i: u8| self.cpu.x(i);
                    eprintln!(
                        "[gsc] {pc:#010x} ecall a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x} a6={:#x} a7={:#x}",
                        x(10),
                        x(11),
                        x(12),
                        x(13),
                        x(14),
                        x(15),
                        x(16),
                        x(17),
                    );
                }
                if self.ap_ro_stub
                    && self.cpu.pc() == 0xce778
                    && self.cpu.x(10) == 1003
                    && self.cpu.x(11) == 62
                    && self.cpu.x(12) == 7
                    && self.cpu.x(13) == 0
                    && self.cpu.x(14) == 7
                {
                    // The AP RO app asks the gscvd driver to verify a
                    // cached GVD. In the current standalone emulator there
                    // is no host/AP flash source to populate that object,
                    // so this bring-up knob returns Tock CommandReturn::
                    // success and lets the caller reach the later path.
                    self.cpu.set_x(10, 129);
                    self.cpu.set_x(11, 0);
                    self.cpu.set_x(12, 0);
                    self.cpu.set_x(13, 0);
                    self.cpu.set_pc(self.cpu.pc() + 4);
                    return Ok(None);
                }
                self.cpu.deliver_ecall_trap();
            }
            RiscVExit::Ebreak => {
                self.halted = true;
                return Ok(Some(VcpuExit::Debug));
            }
            RiscVExit::Trap(t) => {
                self.halted = true;
                return Ok(Some(self.trap_exit(t)));
            }
        }
        Ok(None)
    }
}

impl VCpu for GscVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        for _ in 0..MAX_ITERS {
            if let Some(exit) = self.step_platform()? {
                return Ok(exit);
            }
        }
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        let mut regs = RiscVRegisters::default();
        for i in 0..32u8 {
            regs.x[i as usize] = self.cpu.x(i);
            regs.f[i as usize] = self.cpu.f(i);
        }
        regs.pc = self.cpu.pc();
        regs.fcsr = self.cpu.fcsr();
        Ok(CpuState::riscv(regs))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::RiscV(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected riscv state for gsc vCPU".to_string(),
                ));
            }
        };
        for i in 0..32u8 {
            self.cpu.set_x(i, state.regs.x[i as usize]);
            self.cpu.set_f(i, state.regs.f[i as usize]);
        }
        self.cpu.set_pc(state.regs.pc);
        self.cpu.set_fcsr(state.regs.fcsr);
        // The initial PC is the boot entry; warm resets return here.
        self.reset_entry = state.regs.pc;
        self.halted = false;
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.cpu.instret()
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn current_pc(&self) -> u64 {
        self.cpu.pc()
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.step_platform()
    }
}
