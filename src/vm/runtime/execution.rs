//! Host console and shared device servicing around coordinated CPU turns.
use super::*;

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
        false
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
            drive_legacy_serial_irq(
                &*self.vm,
                self.backend_kind,
                &self.pic,
                self.serial_irq,
                pending,
            );
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
    ) -> Result<()> {
        let vcpu = self
            .vcpus
            .get_mut(cpu_index)
            .ok_or_else(|| Error::InvalidConfig("selected vCPU is missing".into()))?;
        mmio::write(
            self.mmio_bus.get_mut()?,
            &self.local_apics,
            cpu_index,
            addr,
            data,
        )?;
        let completion = vcpu.complete_io_out();
        let irq = self.publish_serial_mmio_irq(addr);
        completion?;
        irq
    }

    pub fn run(&mut self) -> Result<()> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        info!(cpus = self.vcpus.len(), "starting execution coordinator");

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

        let coordinator_services_pc_interrupts = self.uses_retired_pc_interrupt_timing();
        loop {
            #[cfg(feature = "debug")]
            self.debugger.ready()?;
            if self.service_console(&mut console) {
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

            if !coordinator_services_pc_interrupts {
                // Give existing PIC requests precedence over the next PIT
                // edge so repeated IRQ0 cannot starve the UART's IRQ4.
                self.poll_legacy_pic()?;
                self.poll_pc_pit()?;
                self.route_interprocessor_requests()?;
                for index in 0..self.vcpus.len() {
                    if self.coordinator.online[index] {
                        #[cfg(feature = "debug")]
                        if !self.debugger_allows_cpu(index) {
                            continue;
                        }
                        self.poll_local_apic(index)?;
                    }
                }
            }

            let turn = self.execute_turn()?;

            let Some(turn) = turn else {
                self.maybe_snapshot(self.coordinator.retired)?;
                continue;
            };
            let mut shutdown = false;
            #[cfg(feature = "debug")]
            let mut debug_stop = turn.debug_step_completed;
            let vcpu = self
                .vcpus
                .get_mut(turn.cpu_index)
                .ok_or_else(|| Error::InvalidConfig("selected vCPU is missing".into()))?;

            match turn.exit {
                VcpuExit::Hlt => {
                    // HLT is normal - kernel waits for interrupts
                }
                VcpuExit::Shutdown => {
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
                VcpuExit::IoIn { port, size } => {
                    debug!(port = port, size = size, "PIO read");
                    let data = port_io::read(
                        self.io_bus.get_mut()?,
                        &self.serial,
                        self.backend_kind,
                        port,
                        size,
                        1,
                    )?;
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()?;
                }
                VcpuExit::IoInString { port, size, count } => {
                    let data = port_io::read(
                        self.io_bus.get_mut()?,
                        &self.serial,
                        self.backend_kind,
                        port,
                        size,
                        count,
                    )?;
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()?;
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
                        port,
                        &data,
                    )?;
                    vcpu.complete_io_out()?;
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
                    completion?;
                    irq?;
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
                    completion?;
                    irq?;
                }
                VcpuExit::SystemEvent { .. } => shutdown = true,
                VcpuExit::FailEntry { reason } => {
                    return Err(Error::KernelLoad(format!(
                        "vCPU fail entry: reason={reason:#x}"
                    )));
                }
                VcpuExit::InternalError => {
                    return Err(Error::KernelLoad("vCPU internal error".to_string()));
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
                exit => return Err(Error::KernelLoad(format!("unhandled exit: {exit:?}"))),
            }

            self.route_interprocessor_requests()?;

            // Publish only a completed instruction boundary. In particular, an
            // input exit advances RIP before complete_io_in installs its value.
            self.maybe_snapshot(self.coordinator.retired)?;
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
                break;
            }
        }

        // Flush and close trace file
        #[cfg(feature = "trace")]
        crate::observability::trace::close();

        Ok(())
    }
}
