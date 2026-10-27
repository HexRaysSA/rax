//! Host console and shared device servicing around coordinated CPU turns.
use super::*;

impl Vmm {
    pub fn run(&mut self) -> Result<()> {
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

        loop {
            // Drain host stdin through the console mux: forward guest bytes to the
            // UART and act on host escape commands. Then drive the legacy serial
            // RX/TX interrupt line. Release the serial lock before taking the PIC
            // lock to keep a consistent lock order.
            {
                let (guest_bytes, actions) = console.poll();
                let mut quit = false;
                for action in actions {
                    match action {
                        ConsoleAction::Help => eprint!("{}", ESCAPE_HELP),
                        ConsoleAction::Quit => {
                            info!("console quit requested (Ctrl-A x)");
                            quit = true;
                        }
                        ConsoleAction::Snapshot => self.console_checkpoint(),
                    }
                }
                if quit {
                    break;
                }
                // SIGUSR1-triggered checkpoint (same effect as Ctrl-A s).
                if CHECKPOINT_SIGNAL.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    self.console_checkpoint();
                }
                if let Some(ref uart) = self.s3c_uart {
                    // ARMv6: queue console input; the vCPU's own IRQ scan
                    // raises the VIC line.
                    if !guest_bytes.is_empty() {
                        if let Ok(mut u) = uart.lock() {
                            u.queue_input(&guest_bytes);
                        }
                    }
                } else if let Some(ref pl011) = self.pl011 {
                    // AArch64: feed the PL011 and drive its SPI line through
                    // the VM's interrupt controller (in-kernel GIC on HVF).
                    let pending = if let Ok(mut uart) = pl011.lock() {
                        if !guest_bytes.is_empty() {
                            debug!(n = guest_bytes.len(), "console input queued to PL011");
                            uart.queue_input(&guest_bytes);
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
                } else {
                    let pending = if let Ok(mut serial) = self.serial.lock() {
                        if !guest_bytes.is_empty() {
                            serial.queue_input(&guest_bytes);
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
                        // GDB disconnected, continue without GDB
                        debug!("GDB disconnected");
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
                            // GDB disconnected
                            self.gdb_stopped = false;
                        }
                    }
                } else {
                    continue;
                }
            }

            // Deliver device interrupts that were already pending before
            // sampling the next timer edge. On a slow software backend, adding
            // IRQ0 first on every host iteration can otherwise indefinitely
            // starve lower-priority legacy lines such as the serial IRQ4.
            {
                let vcpu = self
                    .vcpus
                    .get_mut(0)
                    .ok_or_else(|| Error::InvalidConfig("no vcpu available".to_string()))?;

                if vcpu.can_inject_interrupt() {
                    if let Ok(mut pic) = self.pic.lock() {
                        pic.try_deliver_pending(|vector| vcpu.inject_interrupt(vector))?;
                    }
                }
            }

            // Tick the PIT and check for timer interrupts
            if let Ok(mut pit) = self.pit.lock() {
                let timer_due = pit.tick() || pit.has_pending_interrupt();
                if timer_due {
                    if let Ok(mut pic) = self.pic.lock() {
                        // A software-emulated guest can take longer than one
                        // PIT period per host iteration. Coalesce the timer
                        // event until the PIC is idle; otherwise fixed-priority
                        // IRQ0 is recreated continuously and lower IRQs starve.
                        if !pic.has_active_irq() {
                            // The PIT OUT pin produces one edge per event.
                            // Pulse the PIC input and leave it low afterward.
                            pic.pulse_irq(0);
                            pit.clear_interrupt();
                        }
                    }
                }
            }

            self.route_interprocessor_requests()?;
            for index in 0..self.vcpus.len() {
                if self.coordinator.online[index] {
                    self.poll_local_apic(index)?;
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
                    let is_serial = port >= SERIAL_BASE && port < SERIAL_BASE + 8;
                    let mut data = vec![0u8; size as usize];
                    if is_serial {
                        if let Ok(mut serial) = self.serial.lock() {
                            for (i, byte) in data.iter_mut().enumerate() {
                                *byte = IoDevice::read(&mut *serial, port + i as u16);
                            }
                        }
                    } else if port == 0x1F0 || port == 0x170 {
                        // IDE/ATAPI data register: a single fixed port carries the
                        // whole PIO word/dword (insw/insd). Read every byte from the
                        // SAME port — unlike the byte-lane model the bus uses for
                        // multi-byte ports — so consecutive reads drain the device's
                        // PIO buffer in order.
                        for i in 0..data.len() {
                            self.io_bus.read(port, &mut data[i..i + 1])?;
                        }
                    } else {
                        self.io_bus.read(port, &mut data)?;
                    }
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()?;
                }
                VcpuExit::IoInString { port, size, count } => {
                    // Batched `rep ins`: read count*size bytes, all from the same
                    // fixed port (the `rep` reads DX repeatedly), in one exit. The
                    // vCPU writes the whole destination block via complete_io_in.
                    let total = (count as usize).saturating_mul(size as usize);
                    let mut data = vec![0u8; total];
                    for i in 0..total {
                        self.io_bus.read(port, &mut data[i..i + 1])?;
                    }
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()?;
                }
                VcpuExit::IoOut { port, data } => {
                    debug!(port = port, size = data.len(), "PIO write");

                    let acpi_shutdown = port == 0x604
                        && data.len() >= 2
                        && u16::from_le_bytes([data[0], data[1]]) == 0x2000;
                    if acpi_shutdown {
                        info!("ACPI shutdown requested");
                        shutdown = true;
                    } else {
                        let is_serial = port >= SERIAL_BASE && port < SERIAL_BASE + 8;
                        if is_serial {
                            let pending = if let Ok(mut serial) = self.serial.lock() {
                                for (i, byte) in data.iter().enumerate() {
                                    IoDevice::write(&mut *serial, port + i as u16, *byte);
                                }
                                serial.has_pending_interrupt()
                            } else {
                                false
                            };
                            // Drive the serial IRQ (TX-empty / line-status), same as
                            // the RX path above.
                            drive_legacy_serial_irq(
                                &*self.vm,
                                self.backend_kind,
                                &self.pic,
                                self.serial_irq,
                                pending,
                            );
                        } else if port == 0xE9 {
                            // Bochs debug port - output directly
                            for byte in &data {
                                eprint!("{}", *byte as char);
                            }
                        } else if port == 0x1F0 || port == 0x170 {
                            // IDE/ATAPI data register: write every byte of the PIO
                            // word/dword to the SAME fixed port (see the IoIn path).
                            for i in 0..data.len() {
                                self.io_bus.write(port, &data[i..i + 1])?;
                            }
                        } else {
                            self.io_bus.write(port, &data)?;
                        }
                    }
                }
                VcpuExit::MmioRead { addr, size } => {
                    let mut data = vec![0u8; size as usize];
                    self.mmio_bus.read(addr, &mut data)?;
                    vcpu.complete_io_in(&data);
                    vcpu.io_completion_result()?;
                }
                VcpuExit::MmioWrite { addr, data } => {
                    self.mmio_bus.write(addr, &data)?;
                }
                VcpuExit::MmioRmw {
                    addr,
                    size,
                    operation,
                } => {
                    let old = self.mmio_bus.read_modify_write(addr, size, operation)?;
                    // Device locks are released before native register/flag
                    // callbacks or instruction completion can reenter the VM.
                    vcpu.complete_io_in(&old);
                    vcpu.io_completion_result()?;
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
                self.gdb_stopped = true;
                self.gdb_single_step = false;
                for vcpu in &mut self.vcpus {
                    vcpu.set_single_step(false);
                }
                if let Some(ref channels) = self.gdb_channels {
                    let _ = channels.resp_tx.send(GdbResponse::StopReply(5));
                }
            }
            if shutdown {
                break;
            }
        }

        // Flush and close trace file
        #[cfg(feature = "trace")]
        crate::observability::trace::close();

        Ok(())
    }
}
