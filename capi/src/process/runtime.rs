//! Dedicated owner-thread state. No WindowsProcess or Rc crosses a channel.
use super::*;
use rax_engine::user::console::{CapturedConsole, Console, OutputStream};
use rax_engine::user::windows::context::RegContext;
use rax_engine::user::windows::process::{RunStatus, ThreadState};
use rax_engine::user::windows::{ExitStatus, SpawnError, WindowsConfig, WindowsProcess};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub(super) enum Command {
    Run { turns: u64, timeout_us: u64 },
    Info,
    ReadMemory { address: u64, size: usize },
    WriteMemory { address: u64, bytes: Vec<u8> },
    ReadContext(u32),
    WriteContext { tid: u32, bytes: Vec<u8> },
    Feed(Vec<u8>),
    Drain { stream: OutputStream, size: usize },
    Shutdown,
}

pub(super) enum Response {
    Unit,
    Bytes(Vec<u8>),
    Run(RaxProcessResult),
}
pub(super) type Work = (Command, Option<mpsc::SyncSender<Result<Response>>>);

struct State {
    process: WindowsProcess,
    console: CapturedConsole,
    cancelled: Arc<AtomicBool>,
    last: RaxProcessResult,
    terminal: Option<ExitStatus>,
}

fn spawn_error(error: SpawnError) -> Failure {
    let status = match &error {
        SpawnError::Io(_) => RaxStatus::Io,
        SpawnError::BadImage(_) | SpawnError::Load { .. } => RaxStatus::Format,
        SpawnError::Memory(_) => RaxStatus::NoMem,
    };
    Failure(status, error.to_string())
}

pub(super) fn worker(
    config: WindowsConfig,
    image: Vec<u8>,
    cancelled: Arc<AtomicBool>,
    ready: mpsc::SyncSender<Result<()>>,
    commands: mpsc::Receiver<Work>,
) {
    let Console::Captured(console) = config.console.clone() else {
        let _ = ready.send(Err(bad("process requires a captured console")));
        return;
    };
    let process = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        WindowsProcess::spawn_image(config, image)
    }));
    let process = match process {
        Ok(Ok(process)) => process,
        Ok(Err(error)) => {
            let _ = ready.send(Err(spawn_error(error)));
            return;
        }
        Err(_) => {
            let _ = ready.send(Err(internal("process creation panicked")));
            return;
        }
    };
    let mut state = State {
        process,
        console,
        cancelled,
        last: Default::default(),
        terminal: None,
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    while let Ok((command, reply)) = commands.recv() {
        if matches!(command, Command::Shutdown) {
            break;
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.execute(command)));
        let panicked = result.is_err();
        if let Some(reply) = reply {
            let _ = reply.send(result.unwrap_or_else(|_| {
                Err(internal(
                    "process worker panicked; handle is no longer executable",
                ))
            }));
        }
        if panicked {
            break;
        }
    }
    // All runtime state, including Rc-backed CRT continuations, dies here.
}

impl State {
    fn run(&mut self, turns: u64, timeout_us: u64) -> RaxProcessResult {
        let start = Instant::now();
        let mut result = RaxProcessResult::default();
        result.reason = RAX_PROCESS_BUDGET;
        if let Some(status) = &self.terminal {
            result.reason = if matches!(status, ExitStatus::Exited(_)) {
                RAX_PROCESS_EXITED
            } else {
                RAX_PROCESS_FAILED
            };
            if let ExitStatus::Exited(code) = status {
                result.exit_code = *code;
            }
            return result;
        }
        for _ in 0..turns {
            if self.cancelled.load(Ordering::Acquire) {
                result.reason = RAX_PROCESS_CANCELLED;
                break;
            }
            if timeout_us != 0 && start.elapsed() >= Duration::from_micros(timeout_us) {
                result.reason = RAX_PROCESS_TIMEOUT;
                break;
            }
            result.turns_started += 1;
            match self.process.run_slice(1, &self.cancelled) {
                RunStatus::BudgetExhausted => {}
                RunStatus::Blocked => {
                    result.reason = RAX_PROCESS_BLOCKED;
                    break;
                }
                RunStatus::Cancelled => {
                    result.reason = RAX_PROCESS_CANCELLED;
                    break;
                }
                RunStatus::Complete(status) => {
                    match &status {
                        ExitStatus::Exited(code) => {
                            result.reason = RAX_PROCESS_EXITED;
                            result.exit_code = *code;
                        }
                        ExitStatus::Internal(_) => {
                            result.reason = RAX_PROCESS_FAILED;
                        }
                    }
                    self.terminal = Some(status);
                    break;
                }
            }
        }
        result.elapsed_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.last = result;
        result
    }

    fn info(&self) -> Result<Vec<u8>> {
        let p = self.process.state();
        let hx = |v: u64| format!("0x{v:x}");
        let threads: Vec<_> = p.threads.values().map(|t| {
            let registers: Vec<_> = (0..t.cpu.gpr_count()).map(|i| hx(t.cpu.gpr(i))).collect();
            let context = RegContext::capture(&t.cpu);
            json!({"id":t.tid,"pc":hx(t.cpu.pc()),"sp":hx(t.cpu.sp()),"teb":hx(t.teb),
                "state":match t.state { ThreadState::Ready => "ready",ThreadState::Waiting(_) => "waiting",ThreadState::Exited(_) => "exited" },
                "suspend_count":t.suspend,"registers":registers,"flags":context.flags_register(),
                "context_format":"windows_context","context_bytes":RegContext::size(p.arch)})
        }).collect();
        let modules: Vec<_> = p.modules.list.iter().enumerate().filter(|(i,_)| p.modules.is_live(*i)).map(|(_,m)| {
            json!({"name":m.name,"path":m.path,"base":hx(m.base),"size":m.size,"entry":hx(m.entry)})
        }).collect();
        let mappings: Vec<_> = p.space.vma_snapshot().into_iter().map(|v| json!({"start":hx(v.start),"end":hx(v.end),"permissions":v.perms.bits(),"name":v.name.as_deref()})).collect();
        let (input, stdout, stderr) = self
            .console
            .pending()
            .map_err(|e| internal(e.to_string()))?;
        let value = json!({"schema_version":1,"personality":"windows","architecture":p.arch.name(),
            "status":reason_name(self.last.reason),"exit_code":match &self.terminal { Some(ExitStatus::Exited(code)) => Some(*code),_=>None },
            "diagnostic":self.terminal.as_ref().map(ToString::to_string),"threads":threads,"modules":modules,"mappings":mappings,
            "committed_bytes":p.vm.committed_bytes(),"memory_limit_bytes":p.vm.commit_limit(),
            "console":{"stdin_pending":input,"stdout_pending":stdout,"stderr_pending":stderr},
            "capabilities":{"host_filesystem":false,"captured_console":true,"context_format":"windows_context","checkpoint":false}});
        let mut bytes = serde_json::to_vec(&value).map_err(|e| internal(e.to_string()))?;
        if bytes.len() >= options::MAX_INFO {
            return Err(Failure(
                RaxStatus::Bounds,
                "process inspection exceeds 4 MiB".into(),
            ));
        }
        bytes.push(0);
        Ok(bytes)
    }

    fn execute(&mut self, command: Command) -> Result<Response> {
        match command {
            Command::Run { turns, timeout_us } => Ok(Response::Run(self.run(turns, timeout_us))),
            Command::Info => Ok(Response::Bytes(self.info()?)),
            Command::ReadMemory { address, size } => {
                let mut bytes = vec![0; size];
                self.process
                    .state()
                    .space
                    .read(address, &mut bytes)
                    .map_err(memory_error)?;
                Ok(Response::Bytes(bytes))
            }
            Command::WriteMemory { address, bytes } => {
                self.process
                    .state()
                    .space
                    .write(address, &bytes)
                    .map_err(memory_error)?;
                // No native code is retained across caller-modified code pages.
                for t in self.process.state_mut().threads.values_mut() {
                    t.cpu.discard_native_code();
                }
                Ok(Response::Unit)
            }
            Command::ReadContext(tid) => {
                let t = self
                    .process
                    .state()
                    .threads
                    .get(&tid)
                    .ok_or_else(|| bad("unknown process thread"))?;
                Ok(Response::Bytes(
                    RegContext::capture(&t.cpu).bytes().to_vec(),
                ))
            }
            Command::WriteContext { tid, bytes } => {
                let p = self.process.state_mut();
                if bytes.len() != RegContext::size(p.arch) {
                    return Err(bad("incorrect Windows CONTEXT byte size"));
                }
                let t = p
                    .threads
                    .get_mut(&tid)
                    .ok_or_else(|| bad("unknown process thread"))?;
                RegContext::from_bytes(p.arch, bytes)
                    .apply(&mut t.cpu)
                    .map_err(|status| bad(format!("invalid Windows CONTEXT: {status:#010x}")))?;
                t.cpu.discard_native_code();
                Ok(Response::Unit)
            }
            Command::Feed(bytes) => {
                self.console
                    .feed(&bytes)
                    .map_err(|e| Failure(RaxStatus::Bounds, e.to_string()))?;
                Ok(Response::Unit)
            }
            Command::Drain { stream, size } => {
                let mut bytes = vec![0; size];
                let count = self
                    .console
                    .drain(stream, &mut bytes)
                    .map_err(|e| internal(e.to_string()))?;
                bytes.truncate(count);
                Ok(Response::Bytes(bytes))
            }
            Command::Shutdown => unreachable!("shutdown is handled before dispatch"),
        }
    }
}

fn memory_error(error: rax_engine::error::GuestMemoryFault) -> Failure {
    use rax_engine::error::MemoryFaultKind;
    Failure(
        if error.kind == MemoryFaultKind::Permission {
            RaxStatus::Perm
        } else {
            RaxStatus::Map
        },
        format!("guest memory fault: {error:?}"),
    )
}

pub(super) fn reason_name(reason: u32) -> &'static str {
    match reason {
        RAX_PROCESS_READY => "ready",
        RAX_PROCESS_BUDGET => "budget",
        RAX_PROCESS_BLOCKED => "blocked",
        RAX_PROCESS_CANCELLED => "cancelled",
        RAX_PROCESS_EXITED => "exited",
        RAX_PROCESS_FAILED => "failed",
        RAX_PROCESS_TIMEOUT => "timeout",
        _ => "unknown",
    }
}
