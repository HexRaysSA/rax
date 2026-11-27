//! Host console and shared device servicing around coordinated CPU turns.
use super::coordinator::ExecutionTurn;
use super::*;

fn publish_kvm_shutdown(_vm: &dyn Vm) -> Result<()> {
    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    if let Some(kvm) = _vm.as_any().downcast_ref::<crate::backend::kvm::KvmVm>() {
        kvm.power_off()?;
    }
    Ok(())
}

#[derive(Debug)]
pub(super) enum TurnFailure {
    /// Entry failed, or only the CPU reply failed after device publication.
    CpuLocal(Error),
    /// Device or VM state might be incomplete, or the exit was terminal.
    Round(Error),
}

impl From<Error> for TurnFailure {
    fn from(error: Error) -> Self {
        Self::Round(error)
    }
}

impl From<TurnFailure> for Error {
    fn from(failure: TurnFailure) -> Self {
        match failure {
            TurnFailure::CpuLocal(error) | TurnFailure::Round(error) => error,
        }
    }
}

impl TurnFailure {
    fn check_io_reply(
        completion: Result<()>,
        notification: Result<()>,
    ) -> std::result::Result<(), Self> {
        match (completion, notification) {
            (Ok(()), result) => result.map_err(Self::Round),
            (Err(error), Ok(())) => Err(Self::CpuLocal(error)),
            (Err(error), Err(notification_error)) => {
                tracing::warn!(%notification_error, "device notification also failed");
                Err(Self::Round(error))
            }
        }
    }
}

impl Vmm {
    fn riscv_platform(&self) -> Option<Arc<crate::backend::emulator::riscv::platform::Platform>> {
        self.vm
            .as_any()
            .downcast_ref::<crate::backend::emulator::EmulatorVm>()
            .and_then(|vm| vm.riscv_platform())
    }

    /// Publish bytes before handling the command that follows them on stdin.
    pub(super) fn service_console(&self, console: &mut Console) -> bool {
        loop {
            let (guest_bytes, action) = console.poll_batch();
            self.deliver_console_input(&guest_bytes);
            match action {
                Some(ConsoleAction::Help) => eprint!("{}", ESCAPE_HELP),
                Some(ConsoleAction::Snapshot) => self.console_checkpoint(),
                Some(ConsoleAction::Quit) => {
                    info!("console quit requested (Ctrl-A x)");
                    return true;
                }
                None => break,
            }
        }
        // An out-of-band request includes the input already drained above.
        if CHECKPOINT_SIGNAL.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.console_checkpoint();
        }
        self.pc_powered_off()
    }

    fn deliver_console_input(&self, guest_bytes: &[u8]) {
        if let Some(ref uart) = self.s3c_uart {
            // ARMv6: queue console input; the vCPU's own IRQ scan
            // raises the VIC line.
            if !guest_bytes.is_empty() {
                if let Ok(mut u) = uart.lock() {
                    u.queue_input(guest_bytes);
                }
            }
        } else if let Some(ref pl011) = self.pl011 {
            // AArch64: feed the PL011 and drive its SPI line through
            // the VM's interrupt controller (in-kernel GIC on HVF).
            let pending = if let Ok(mut uart) = pl011.lock() {
                if !guest_bytes.is_empty() {
                    debug!(n = guest_bytes.len(), "console input queued to PL011");
                    uart.queue_input(guest_bytes);
                }
                uart.irq_pending()
            } else {
                false
            };
            if let Some(irq) = self.serial_irq {
                if let Err(e) = self.vm.set_irq_line(irq, pending) {
                    debug!(irq, pending, error = %e, "failed to drive UART irq line");
                }
            }
        } else if let Some(platform) = self.riscv_platform() {
            if !guest_bytes.is_empty() {
                match platform.queue_uart_input(guest_bytes) {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Ok(mut serial) = self.serial.lock() {
                            serial.queue_input(guest_bytes);
                        }
                    }
                    Err(error) => debug!(%error, "failed to publish RV64 UART input"),
                }
            }
        } else {
            let pending = if let Ok(mut serial) = self.serial.lock() {
                if !guest_bytes.is_empty() {
                    serial.queue_input(guest_bytes);
                }
                serial.has_pending_interrupt()
            } else {
                false
            };
            drive_legacy_serial_irq(&*self.vm, &self.pic, self.serial_irq, pending);
        }
    }

    fn publish_serial_mmio_irq(&self, addr: u64) -> Result<()> {
        use crate::backend::emulator::riscv::platform::{UART_BASE, UART_LEN};
        if (UART_BASE..UART_BASE + UART_LEN).contains(&addr)
            && let Some(platform) = self.riscv_platform()
        {
            return platform.publish_uart_write();
        }
        let (Some(uart), Some(base), Some(irq)) =
            (&self.pl011, self.serial_mmio_base, self.serial_irq)
        else {
            return Ok(());
        };
        let range = MmioRange {
            base,
            len: PL011_MMIO_LEN,
        };
        if !range.contains(addr) {
            return Ok(());
        }
        let uart = uart
            .lock()
            .map_err(|_| Error::Emulator("PL011 IRQ publication lock poisoned".into()))?;
        self.vm.set_irq_line(irq, uart.irq_pending())
    }

    pub(super) fn dispatch_mmio_write(
        &mut self,
        cpu_index: usize,
        addr: u64,
        data: &[u8],
    ) -> std::result::Result<(), TurnFailure> {
        use crate::backend::emulator::riscv::platform::{UART_BASE, UART_LEN};
        let uart_end = UART_BASE + UART_LEN;
        let riscv_uart =
            if (UART_BASE..uart_end).contains(&addr) && data.len() <= (uart_end - addr) as usize {
                self.riscv_platform()
            } else {
                None
            };
        let vcpu = self
            .vcpus
            .get_mut(cpu_index)
            .ok_or_else(|| Error::InvalidConfig("selected vCPU is missing".into()))?;
        if let Some(platform) = riscv_uart
            && platform.write_uart(addr, data)?
        {
            // The platform publishes the UART and its PLIC input under one
            // lock pair. Acknowledge only after both changes are visible.
            return vcpu.complete_io_out().map_err(TurnFailure::CpuLocal);
        }
        mmio::write(
            self.mmio_bus.get_mut()?,
            &self.local_apics,
            cpu_index,
            addr,
            data,
        )?;
        let completion = vcpu.complete_io_out();
        let irq = self.publish_serial_mmio_irq(addr);
        TurnFailure::check_io_reply(completion, irq)
    }

    fn pending_device_io_turn(&mut self) -> Result<Option<ExecutionTurn>> {
        let native = self.backend_kind == BackendKind::Hvf;
        if !native
            && (self.backend_kind != BackendKind::Emulator
                || !matches!(
                    self.checkpoint_config.arch,
                    ArchKind::X86_64 | ArchKind::Riscv64
                ))
        {
            return Ok(None);
        }
        // Intel HVF retains triple fault in the CPU record. Check for that
        // terminal exit before touching a peer's device. ARM has a VM latch.
        let check_intel_terminal = native && self.checkpoint_config.arch == ArchKind::X86_64;
        let mut selected = Ok(None);
        for cpu_index in 0..self.vcpus.len() {
            if native && !self.coordinator.online[cpu_index] {
                continue;
            }
            #[cfg(feature = "debug")]
            if !self.debugger_allows_cpu(cpu_index) {
                continue;
            }
            let vcpu = &mut self.vcpus[cpu_index];
            let pending = if native {
                vcpu.resume_native_device_io()
            } else if self.checkpoint_config.arch == ArchKind::X86_64 {
                vcpu.pending_software_port_io()
            } else {
                vcpu.pending_software_mmio_write()
            };
            let terminal = matches!(pending, Ok(Some(VcpuExit::Shutdown)));
            if terminal || (matches!(selected, Ok(None)) && !matches!(pending, Ok(None))) {
                selected = pending.map(|exit| {
                    exit.map(|exit| ExecutionTurn {
                        cpu_index,
                        exit,
                        #[cfg(feature = "debug")]
                        debug_step_completed: !native && vcpu.is_single_step(),
                    })
                });
                if terminal || !check_intel_terminal {
                    break;
                }
            }
        }
        #[cfg(feature = "debug")]
        if let Ok(Some(turn)) = &selected {
            self.debugger.last_cpu = turn.cpu_index;
        }
        selected
    }

    fn apply_pending_device_io(&mut self, turn: ExecutionTurn) -> Result<bool> {
        // Restored native exits can come from the same parallel round. An INIT
        // routed after only one exit could clear a peer's undispatched I/O.
        let native = self.backend_kind == BackendKind::Hvf;
        let shutdown = self.apply_execution_turn(turn, !native)?;
        if shutdown && native {
            self.maybe_snapshot(self.coordinator.retired)?;
        }
        Ok(shutdown)
    }

    pub fn run(&mut self) -> Result<()> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        // A terminal checkpoint already has a stopped execution frontier.
        // Detect it before console input, timer polling or CPU selection.
        if self.vm.firmware_shutdown()? || self.pc_powered_off() {
            // The shutdown may have completed before a due capture could
            // be written. Retry it without reentering the guest.
            return self.maybe_snapshot(self.coordinator.retired);
        }
        let _timing = self.timing_context.enter();
        info!(cpus = self.vcpus.len(), "starting execution coordinator");

        // An issued transaction belongs to the previous turn. With no GDB
        // transport, finish it before admitting console input or another CPU.
        #[cfg(feature = "debug")]
        let defer_io_replay = self.gdb_channels.is_some();
        #[cfg(not(feature = "debug"))]
        let defer_io_replay = false;
        if !defer_io_replay {
            while let Some(turn) = self.pending_device_io_turn()? {
                if self.apply_pending_device_io(turn)? {
                    return Ok(());
                }
            }
        }

        // Wait for GDB connection if --wait-gdb was specified
        #[cfg(feature = "debug")]
        if self.wait_gdb {
            if let Some(ref channels) = self.gdb_channels {
                info!("Waiting for GDB to connect and send command...");
                // Block until we receive a command from GDB
                match channels.cmd_rx.recv() {
                    Ok(cmd) => {
                        info!("GDB connected, received initial command");
                        // Handle the initial command and stop
                        self.gdb_stopped = true;
                        if let Some(should_break) = self.handle_gdb_command(cmd)? {
                            if should_break {
                                return Ok(());
                            }
                        }
                    }
                    Err(_) => {
                        info!("GDB channel closed before connection");
                        self.disconnect_debugger_transport()?;
                    }
                }
            }
        }

        // Put the host terminal into raw mode for a faithful interactive serial
        // console (restored on drop, panic, or fatal signal) and start the
        // console mux that reads stdin and forwards bytes to the guest UART,
        // intercepting the Ctrl-A escape prefix for host commands.
        let _raw_tty = RawTty::enable();
        let mut console = Console::spawn();

        // SIGUSR1 requests a checkpoint (the non-keyboard trigger).
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGUSR1, sigusr1_handler as libc::sighandler_t);
        }

        let native_smp = self.vcpus.len() > 1
            && (self.backend_kind == BackendKind::Kvm && self.vm.uses_native_x86_irqchip()
                || self.hvf_parallel_vcpus);
        let mut turns = Vec::new();
        let mut pending = Vec::new();
        if native_smp {
            turns
                .try_reserve_exact(self.vcpus.len())
                .map_err(|error| Error::Emulator(format!("host turn allocation: {error}")))?;
            pending
                .try_reserve_exact(self.vcpus.len())
                .map_err(|error| Error::Emulator(format!("host entry allocation: {error}")))?;
        }

        loop {
            #[cfg(feature = "debug")]
            self.debugger.ready()?;
            if self.pc_powered_off() || self.service_console(&mut console) {
                break;
            }

            // Handle GDB commands (non-blocking)
            #[cfg(feature = "debug")]
            if let Some(ref channels) = self.gdb_channels {
                match channels.cmd_rx.try_recv() {
                    Ok(cmd) => {
                        if let Some(should_break) = self.handle_gdb_command(cmd)? {
                            if should_break {
                                break;
                            }
                            continue;
                        }
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        debug!("GDB disconnected");
                        self.disconnect_debugger_transport()?;
                    }
                }
            }

            // If GDB stopped us, wait for continue/step command
            #[cfg(feature = "debug")]
            if self.gdb_stopped {
                if let Some(ref channels) = self.gdb_channels {
                    match channels.cmd_rx.recv() {
                        Ok(cmd) => {
                            if let Some(should_break) = self.handle_gdb_command(cmd)? {
                                if should_break {
                                    break;
                                }
                                // Command handled but didn't resume execution, wait for more
                                continue;
                            }
                            // Command returned None = resume execution (step/continue)
                            // Fall through to run the VCPU
                        }
                        Err(_) => {
                            self.disconnect_debugger_transport()?;
                        }
                    }
                } else {
                    continue;
                }
            }

            // These turns already carry their retirement charge. Honor the
            // current resume mask, then complete I/O without entering the CPU.
            if defer_io_replay && let Some(turn) = self.pending_device_io_turn()? {
                if self.apply_pending_device_io(turn)? {
                    break;
                }
                continue;
            }

            let parallel = native_smp;
            #[cfg(feature = "debug")]
            let parallel = parallel && self.gdb_channels.is_none();
            if parallel {
                if let Err(error) = self.execute_native_round(&mut turns, &mut pending) {
                    // The round joins all posted owners, including after a
                    // partial posting failure. Successful peers can already
                    // own device exits that require completion.
                    if !turns.is_empty()
                        && let Err(dispatch_error) = self.apply_native_round(&mut turns)
                    {
                        tracing::warn!(%dispatch_error, "peer exit dispatch also failed");
                    }
                    return Err(error);
                }
                if self.apply_native_round(&mut turns)? {
                    break;
                }
                self.maybe_snapshot(self.coordinator.retired)?;
            } else if let Some(turn) = self.execute_turn()? {
                if self.apply_execution_turn(turn, true)? {
                    break;
                }
            } else {
                self.maybe_snapshot(self.coordinator.retired)?;
            }
        }

        // Flush and close trace file
        #[cfg(feature = "trace")]
        crate::observability::trace::close();

        Ok(())
    }

    pub(super) fn apply_native_round(&mut self, turns: &mut Vec<ExecutionTurn>) -> Result<bool> {
        // The ARM HVF power owner is terminal even when collecting the round
        // yields no Shutdown exit. Leave unserviced MMIO in its CPU owner.
        let arm_hvf_shutdown = self.backend_kind == BackendKind::Hvf
            && self.checkpoint_config.arch == ArchKind::Aarch64
            && (turns
                .iter()
                .any(|turn| matches!(turn.exit, VcpuExit::Shutdown))
                || self.vm.firmware_shutdown()?);
        let mut first_cpu_error = None;
        for turn in turns.drain(..) {
            if arm_hvf_shutdown
                && matches!(
                    turn.exit,
                    VcpuExit::MmioRead { .. }
                        | VcpuExit::MmioWrite { .. }
                        | VcpuExit::MmioRmw { .. }
                )
            {
                continue;
            }
            match self.apply_execution_turn(turn, false) {
                Ok(false) => {}
                Ok(true) => return first_cpu_error.map_or(Ok(true), Err),
                Err(TurnFailure::CpuLocal(error)) => {
                    // Verify that the failure did not fence the shared owner.
                    // Release the boundary before a peer's device callback.
                    if let Err(boundary_error) = self.vm.checkpoint_boundary() {
                        tracing::warn!(%boundary_error, "peer dispatch requires a healthy stopped VM");
                        return Err(first_cpu_error.unwrap_or(error));
                    }
                    first_cpu_error.get_or_insert(error);
                }
                Err(TurnFailure::Round(error)) => {
                    if let Some(first) = first_cpu_error {
                        tracing::warn!(%error, "peer exit dispatch also failed");
                        return Err(first);
                    }
                    return Err(error);
                }
            }
        }
        if let Some(error) = first_cpu_error {
            return Err(error);
        }
        if arm_hvf_shutdown {
            return Ok(true);
        }
        // Every exit in this round predates the effects of a delivered INIT.
        // Complete a peer's device exit before applying a reset to that CPU.
        self.route_interprocessor_requests()?;
        self.poll_vm_clocks()?;
        Ok(false)
    }

    fn apply_execution_turn(
        &mut self,
        turn: ExecutionTurn,
        checkpoint_after_turn: bool,
    ) -> std::result::Result<bool, TurnFailure> {
        let mut shutdown = false;
        #[cfg(feature = "debug")]
        let mut debug_stop = turn.debug_step_completed;
        if turn.cpu_index >= self.vcpus.len() {
            return Err(Error::InvalidConfig("selected vCPU is missing".into()).into());
        }
        let rtc = port_io::touches_rtc(&turn.exit);
        if rtc {
            // Account for ticks due before the guest changes the RTC registers.
            self.poll_pc_rtc()?;
        }
        let vcpu = &mut self.vcpus[turn.cpu_index];

        let keyboard = self.pc_devices.as_ref().map(|pc| port_io::KeyboardIrqs {
            pc,
            pic: &self.pic,
            vm: &*self.vm,
        });
        match turn.exit {
            VcpuExit::Hlt => {
                // HLT is normal - kernel waits for interrupts
            }
            VcpuExit::Shutdown => {
                publish_kvm_shutdown(&*self.vm)?;
                match vcpu.get_state()? {
                    CpuState::X86_64(state) => {
                        let regs = state.regs;
                        let sregs = state.sregs;
                        info!(
                            rip = format!("{:#x}", regs.rip),
                            rsp = format!("{:#x}", regs.rsp),
                            rsi = format!("{:#x}", regs.rsi),
                            rflags = format!("{:#x}", regs.rflags),
                            cr0 = format!("{:#x}", sregs.cr0),
                            cr3 = format!("{:#x}", sregs.cr3),
                            cr4 = format!("{:#x}", sregs.cr4),
                            cs_sel = format!("{:#x}", sregs.cs.selector),
                            cs_base = format!("{:#x}", sregs.cs.base),
                            ds_sel = format!("{:#x}", sregs.ds.selector),
                            gdt_base = format!("{:#x}", sregs.gdt.base),
                            gdt_limit = format!("{:#x}", sregs.gdt.limit),
                            "vCPU shutdown"
                        );
                    }
                    CpuState::Hexagon(state) => {
                        let regs = state.regs;
                        let sp = regs.r[29];
                        info!(
                            pc = format!("{:#x}", regs.pc()),
                            sp = format!("{:#x}", sp),
                            usr = format!("{:#x}", regs.usr()),
                            "vCPU shutdown"
                        );
                    }
                    CpuState::Aarch64(state) => {
                        let regs = state.regs;
                        info!(
                            pc = format!("{:#x}", regs.pc),
                            sp = format!("{:#x}", regs.sp),
                            pstate = format!("{:#x}", regs.pstate),
                            "vCPU shutdown"
                        );
                    }
                    _ => {
                        info!("vCPU shutdown (unsupported architecture)");
                    }
                }
                shutdown = true;
            }
            exit @ (VcpuExit::IoIn { .. } | VcpuExit::IoInString { .. }) => {
                let (port, size, count) = match exit {
                    VcpuExit::IoIn { port, size } => (port, size, 1),
                    VcpuExit::IoInString { port, size, count } => (port, size, count),
                    _ => unreachable!("matched port input exit"),
                };
                debug!(port, size, count, "PIO read");
                let completion = if let Some(result) = vcpu.retry_software_port_input() {
                    result
                } else {
                    let data = port_io::read(
                        self.io_bus.get_mut()?,
                        &self.serial,
                        self.backend_kind,
                        keyboard.as_ref(),
                        port,
                        size,
                        count,
                    )?;
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()
                };
                // Publish a Register C acknowledgement before sampling time
                // again, even if the CPU could not accept the port reply.
                let irq = if rtc {
                    self.sync_pc_rtc_irq(None)
                } else {
                    self.sync_pc_serial_pio_input(port)
                };
                TurnFailure::check_io_reply(completion, irq)?;
            }
            VcpuExit::IoOut { port, data } => {
                debug!(port = port, size = data.len(), "PIO write");

                shutdown = port_io::write(
                    self.io_bus.get_mut()?,
                    &self.serial,
                    &self.pic,
                    &*self.vm,
                    self.backend_kind,
                    self.serial_irq,
                    keyboard.as_ref(),
                    port,
                    &data,
                )?;
                if shutdown {
                    // Fence entry before acknowledging the accepted S5 output.
                    if let Some(pc) = &self.pc_devices {
                        pc.set_powered_off(true);
                    }
                    publish_kvm_shutdown(&*self.vm)?;
                }
                let completion = vcpu.complete_io_out();
                if rtc {
                    TurnFailure::check_io_reply(completion, self.sync_pc_rtc_irq(None))?;
                } else {
                    completion.map_err(|error| {
                        if shutdown {
                            TurnFailure::Round(error)
                        } else {
                            TurnFailure::CpuLocal(error)
                        }
                    })?;
                }
            }
            VcpuExit::MmioRead { addr, size } => {
                let mut data = vec![0u8; size as usize];
                mmio::read(
                    self.mmio_bus.get_mut()?,
                    &self.local_apics,
                    turn.cpu_index,
                    addr,
                    &mut data,
                )?;
                vcpu.complete_io_in(&data);
                let completion = vcpu.io_completion_result();
                // The device has consumed the input even if the native reply
                // must be retried. Publish the line before any checkpoint.
                let irq = self.publish_serial_mmio_irq(addr);
                TurnFailure::check_io_reply(completion, irq)?;
            }
            VcpuExit::MmioWrite { addr, data } => {
                self.dispatch_mmio_write(turn.cpu_index, addr, &data)?;
            }
            VcpuExit::MmioRmw {
                addr,
                size,
                operation,
            } => {
                let old = mmio::rmw(
                    self.mmio_bus.get_mut()?,
                    &self.local_apics,
                    turn.cpu_index,
                    addr,
                    size,
                    operation,
                )?;
                // Device locks are released before native register/flag
                // callbacks or instruction completion can reenter the VM.
                vcpu.complete_io_in(&old);
                let completion = vcpu.io_completion_result();
                let irq = self.publish_serial_mmio_irq(addr);
                TurnFailure::check_io_reply(completion, irq)?;
            }
            VcpuExit::SystemEvent { .. } => {
                publish_kvm_shutdown(&*self.vm)?;
                shutdown = true;
            }
            VcpuExit::FailEntry { reason } => {
                return Err(TurnFailure::CpuLocal(Error::KernelLoad(format!(
                    "vCPU fail entry: reason={reason:#x}"
                ))));
            }
            VcpuExit::InternalError => {
                return Err(Error::KernelLoad("vCPU internal error".to_string()).into());
            }
            VcpuExit::Debug => {
                // INT3 breakpoint - kernel debugging, just continue
            }
            VcpuExit::Exception(vector) => {
                // Check for breakpoint exception (vector 3) when GDB is attached
                #[cfg(feature = "debug")]
                if vector == 3 && self.gdb_channels.is_some() {
                    // INT3 was hit - RIP is now AFTER the INT3, back up 1 byte
                    let bp_addr = vcpu.get_regs().map(|r| r.rip).unwrap_or(0) - 1;

                    if self.gdb_breakpoints.contains(&bp_addr) {
                        debug!(addr = format!("{:#x}", bp_addr), "Software breakpoint hit");
                        let mut regs = vcpu.get_regs().unwrap_or_default();
                        regs.rip = bp_addr;
                        let _ = vcpu.set_regs(&regs);

                        debug_stop = true;
                    } else {
                        debug!(
                            addr = format!("{:#x}", bp_addr),
                            "Natural INT3 instruction hit"
                        );
                    }
                }
                // Other exceptions - just continue for now
            }
            #[cfg(feature = "debug")]
            VcpuExit::GdbBreakpoint { addr } => {
                debug!(addr = format!("{:#x}", addr), "GDB breakpoint hit");
                debug_stop = true;
            }
            #[cfg(feature = "debug")]
            VcpuExit::GdbStep => {
                debug!("GDB single step complete");

                debug_stop = true;
            }
            exit => return Err(Error::KernelLoad(format!("unhandled exit: {exit:?}")).into()),
        }

        // Publish only a completed instruction boundary. In particular, an
        // input exit advances RIP before complete_io_in installs its value.
        if checkpoint_after_turn {
            self.route_interprocessor_requests()?;
            self.maybe_snapshot(self.coordinator.retired)?;
        }
        #[cfg(feature = "debug")]
        if debug_stop {
            self.stop_debugger(turn.cpu_index, 5)?;
            if let Some(ref channels) = self.gdb_channels {
                let _ = channels.resp_tx.send(GdbResponse::ThreadStop {
                    signal: 5,
                    index: turn.cpu_index,
                });
            }
        }
        if shutdown {
            #[cfg(feature = "debug")]
            if let Some(ref channels) = self.gdb_channels {
                let _ = channels.resp_tx.send(GdbResponse::Exited(0));
            }
        }
        Ok(shutdown)
    }
}
