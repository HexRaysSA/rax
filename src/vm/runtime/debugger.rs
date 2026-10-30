//! Single-owner debugger queries and selected register access.
use super::*;
use crate::debug::gdb::{Resume, ResumeAction, ThreadId};
#[derive(Debug)]
pub(super) struct State {
    pub(super) general: usize,
    pub(super) execution: ThreadId,
    pub(super) resume: Option<Vec<ResumeAction>>,
    pub(super) stop: (usize, u8),
    pub(super) last_cpu: usize,
    pub(super) failure: Option<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            general: 0,
            execution: ThreadId::All,
            resume: None,
            stop: (0, 5),
            last_cpu: 0,
            failure: None,
        }
    }
}
impl Vmm {
    /// Handle a GDB command from the debug server.
    /// Returns Some(true) to break the run loop, Some(false) to continue, None for commands that resume execution.
    #[cfg(feature = "debug")]
    pub(super) fn handle_gdb_command(&mut self, cmd: GdbCommand) -> Result<Option<bool>> {
        use crate::debug::gdb::protocol::encode_hex;

        let responses = match &self.gdb_channels {
            Some(ch) => ch.resp_tx.clone(),
            None => return Ok(None),
        };

        match cmd {
            GdbCommand::Attach => {
                let index = self.debugger.last_cpu;
                self.detach_debugger()?;
                for cpu in &mut self.vcpus {
                    cpu.set_debugger_active(true);
                }
                self.stop_debugger(index, 2)?;
                let _ = responses.send(GdbResponse::Attached);
            }
            GdbCommand::ConnectionClosed => {
                self.detach_debugger()?;
            }
            GdbCommand::Threads => {
                let ids = (1..=self.vcpus.len())
                    .map(|n| format!("{n:x}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let _ = responses.send(GdbResponse::Text(format!("m{ids}")));
            }
            GdbCommand::CurrentThread => {
                let _ = responses.send(GdbResponse::Text(format!(
                    "QC{:x}",
                    self.debugger.general + 1
                )));
            }
            GdbCommand::SelectThread { execution, thread } => {
                if let Some(index) = thread.index(self.vcpus.len(), self.debugger.general) {
                    if execution {
                        self.debugger.execution = thread;
                    } else {
                        self.debugger.general = index;
                    }
                    let _ = responses.send(GdbResponse::Ok);
                } else {
                    let _ = responses.send(GdbResponse::Error(1));
                }
            }
            GdbCommand::ThreadInfo { thread, describe } => {
                if let Some(index) = thread.index(self.vcpus.len(), self.debugger.general) {
                    let reply = if describe {
                        GdbResponse::Text(encode_hex(format!("CPU {index}").as_bytes()))
                    } else {
                        GdbResponse::Ok
                    };
                    let _ = responses.send(reply);
                } else {
                    let _ = responses.send(GdbResponse::Error(1));
                }
            }
            GdbCommand::Continue | GdbCommand::Step | GdbCommand::Resume(_) => {
                let actions = match cmd {
                    GdbCommand::Resume(actions) => actions,
                    GdbCommand::Continue => vec![Resume {
                        action: ResumeAction::Continue,
                        thread: self.debugger.execution,
                    }],
                    _ => vec![Resume {
                        action: ResumeAction::Step,
                        thread: ThreadId::Id(
                            self.debugger
                                .execution
                                .index(self.vcpus.len(), self.debugger.general)
                                .unwrap_or(self.debugger.general)
                                + 1,
                        ),
                    }],
                };
                match self.resume_debugger(&actions)? {
                    Some(true) => return Ok(None),
                    Some(false) => {
                        let (index, signal) = self.debugger.stop;
                        let _ = responses.send(GdbResponse::ThreadStop { signal, index });
                    }
                    None => {
                        let _ = responses.send(GdbResponse::Error(1));
                    }
                }
            }
            GdbCommand::Interrupt => {
                self.stop_debugger(self.debugger.last_cpu, 2)?;
                let _ = responses.send(GdbResponse::ThreadStop {
                    signal: 2,
                    index: self.debugger.last_cpu,
                });
            }
            GdbCommand::ReadRegisters => {
                let reply = crate::debug::gdb::x86_registers::read(
                    self.vcpus[self.debugger.general].as_ref(),
                )?
                .map_or(GdbResponse::Error(1), GdbResponse::Registers);
                let _ = responses.send(reply);
            }
            GdbCommand::WriteRegisters(data) => {
                let result = crate::debug::gdb::x86_registers::write(
                    self.vcpus[self.debugger.general].as_mut(),
                    &data,
                );
                match result {
                    Ok(ok) => {
                        let _ = responses.send(if ok {
                            GdbResponse::Ok
                        } else {
                            GdbResponse::Error(1)
                        });
                    }
                    Err(error) => {
                        self.debugger.failure = Some(error.to_string());
                        self.gdb_stopped = true;
                        return Err(error);
                    }
                }
            }
            GdbCommand::WriteRegister { index, data } => {
                let result = crate::debug::gdb::x86_registers::write_one(
                    self.vcpus[self.debugger.general].as_mut(),
                    index,
                    &data,
                );
                match result {
                    Ok(ok) => {
                        let _ = responses.send(if ok {
                            GdbResponse::Ok
                        } else {
                            GdbResponse::Error(1)
                        });
                    }
                    Err(error) => {
                        self.debugger.failure = Some(error.to_string());
                        self.gdb_stopped = true;
                        return Err(error);
                    }
                }
            }
            GdbCommand::ReadMemory { addr, len } => {
                let mem = self.guest_mem.memory();
                let mut data = vec![0u8; len];
                if mem
                    .read_slice(&mut data, vm_memory::GuestAddress(addr))
                    .is_ok()
                {
                    let hex = encode_hex(&data);
                    let _ = responses.send(GdbResponse::Memory(hex));
                } else {
                    let _ = responses.send(GdbResponse::Error(1));
                }
            }
            GdbCommand::WriteMemory { addr, data } => {
                let mem = self.guest_mem.memory();
                if crate::vm::memory::reservations::write(mem, addr, &data).is_ok() {
                    if !data.is_empty() {
                        for vcpu in &mut self.vcpus {
                            let end = addr.saturating_add(data.len().saturating_sub(1) as u64);
                            let end_page = end & !0xFFF;
                            let mut page = addr & !0xFFF;
                            loop {
                                vcpu.invalidate_code_cache(page);
                                if page == end_page {
                                    break;
                                }
                                page = page.wrapping_add(0x1000);
                            }
                        }
                    }
                    let _ = responses.send(GdbResponse::Ok);
                } else {
                    let _ = responses.send(GdbResponse::Error(1));
                }
            }
            GdbCommand::SetBreakpoint { addr } | GdbCommand::RemoveBreakpoint { addr } => {
                let insert = matches!(cmd, GdbCommand::SetBreakpoint { .. });
                let reply = if self.debug_breakpoint(addr, insert)? {
                    GdbResponse::Ok
                } else {
                    GdbResponse::Error(1)
                };
                let _ = responses.send(reply);
            }
            GdbCommand::QueryHaltReason => {
                if !self.gdb_stopped {
                    self.stop_debugger(self.debugger.last_cpu, 2)?;
                }
                let (index, signal) = self.debugger.stop;
                let _ = responses.send(GdbResponse::ThreadStop { signal, index });
            }
            GdbCommand::Detach => {
                self.detach_debugger()?;
                let _ = responses.send(GdbResponse::Detached);
                return Ok(Some(false));
            }
            GdbCommand::Kill => {
                return Ok(Some(true)); // Break run loop
            }
        }

        Ok(Some(false)) // Don't break, but don't resume execution either
    }
}
