//! Native exit conversion and explicit userspace I/O completion ownership.
use super::{KvmVcpu, io};
use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;

/// No native reference escapes this conversion. Input buffers remain mapped
/// by the owning vCPU; output operands are copied before another native entry.
enum NativeExit {
    Input(io::Input, *mut u8, usize),
    Output(io::Output, usize),
    Direct(VcpuExit),
}

/// # Safety
/// `run` names the live, aligned mapping owned by the exclusively borrowed
/// vCPU, after KVM_RUN returned its initialized KVM_EXIT_IO descriptor. No
/// native entry or concurrent mutation may occur while reading these fields.
unsafe fn port_descriptor(
    run: *const kvm_bindings::kvm_run,
    port: u16,
    direction: u32,
) -> std::result::Result<(u8, u32), String> {
    // SAFETY: the caller retains the mapping and has stopped native entry.
    if unsafe { (*run).exit_reason } != kvm_bindings::KVM_EXIT_IO {
        return Err("native port exit has a different run descriptor".into());
    }
    // SAFETY: the checked tag selects this initialized union variant. The
    // header fields are disjoint from the separately mapped PIO data page.
    let descriptor = unsafe { (*run).__bindgen_anon_1.io };
    if descriptor.port != port || u32::from(descriptor.direction) != direction {
        return Err("native port exit differs from its descriptor".into());
    }
    Ok((descriptor.size, descriptor.count))
}

fn public_event(event: io::Event) -> VcpuExit {
    match event {
        io::Event::Input(io::Input::Port {
            port,
            size,
            count: 1,
        }) => VcpuExit::IoIn { port, size },
        io::Event::Input(io::Input::Port { port, size, count }) => {
            VcpuExit::IoInString { port, size, count }
        }
        io::Event::Input(io::Input::Mmio { address, size }) => VcpuExit::MmioRead {
            addr: address,
            size,
        },
        io::Event::PortOutput { port, bytes } => VcpuExit::IoOut { port, data: bytes },
        io::Event::MmioOutput { address, bytes } => VcpuExit::MmioWrite {
            addr: address,
            data: bytes,
        },
    }
}

impl KvmVcpu {
    fn fail_native_io(&mut self, error: impl std::fmt::Display) -> Error {
        let failure = format!("KVM native I/O failed: {error}; guest entry disabled");
        self.state_failure = Some(failure.clone());
        Error::Emulator(failure)
    }

    fn copy_input_reply(&mut self) -> Result<()> {
        let reply = self.io.input_reply().map_err(Error::Emulator)?;
        if let Some(reply) = reply {
            let Some((pointer, length)) = self.pending_io_in else {
                return Err(self.fail_native_io("completed input lost its native buffer"));
            };
            if length != reply.len() {
                return Err(self.fail_native_io("completed input changed its native length"));
            }
            // SAFETY: this buffer was returned by the preceding native exit;
            // its vCPU/run mapping remains owned and no intervening native run
            // occurred. Metadata and the exact reply length were validated.
            // The source is a separate owned Vec, so the regions cannot alias.
            // This exclusive vCPU borrow excludes concurrent access/unwinding.
            unsafe {
                std::ptr::copy_nonoverlapping(reply.as_ptr(), pointer, length);
            }
        }
        Ok(())
    }

    fn read_native_exit(&mut self) -> Result<NativeExit> {
        // Retain a raw header address, not a Rust reference, across entry.
        // Its mapping is stable for the live VcpuFd's lifetime.
        let header = self.vcpu_fd.get_kvm_run() as *const kvm_bindings::kvm_run;
        Ok(match self.vcpu_fd.run()? {
            kvm_ioctls::VcpuExit::IoIn(port, data) => {
                // SAFETY: KVM_RUN returned IO_IN on this exclusively borrowed,
                // live mapped CPU. Its PIO data slice is disjoint from the
                // initialized header; no native run is active during the read.
                let (size, count) =
                    unsafe { port_descriptor(header, port, kvm_bindings::KVM_EXIT_IO_IN) }
                        .map_err(Error::Emulator)?;
                NativeExit::Input(
                    io::Input::Port { port, size, count },
                    data.as_mut_ptr(),
                    data.len(),
                )
            }
            kvm_ioctls::VcpuExit::IoOut(port, data) => {
                // SAFETY: same mapping/header lifetime and exclusion as above,
                // with the initialized IO_OUT tag and read-only payload.
                let (size, count) =
                    unsafe { port_descriptor(header, port, kvm_bindings::KVM_EXIT_IO_OUT) }
                        .map_err(Error::Emulator)?;
                NativeExit::Output(
                    io::Output::Port {
                        port,
                        size,
                        count,
                        bytes: data.to_vec(),
                    },
                    data.len(),
                )
            }
            kvm_ioctls::VcpuExit::MmioRead(address, data) => NativeExit::Input(
                io::Input::Mmio {
                    address,
                    size: u8::try_from(data.len()).map_err(|_| {
                        Error::Emulator("native MMIO input length exceeds u8".into())
                    })?,
                },
                data.as_mut_ptr(),
                data.len(),
            ),
            kvm_ioctls::VcpuExit::MmioWrite(address, data) => NativeExit::Output(
                io::Output::Mmio {
                    address,
                    bytes: data.to_vec(),
                },
                data.len(),
            ),
            kvm_ioctls::VcpuExit::Hlt => NativeExit::Direct(VcpuExit::Hlt),
            kvm_ioctls::VcpuExit::Shutdown => NativeExit::Direct(VcpuExit::Shutdown),
            kvm_ioctls::VcpuExit::SystemEvent(type_, flags) => {
                NativeExit::Direct(VcpuExit::SystemEvent {
                    type_,
                    flags: flags.first().copied().unwrap_or(0),
                })
            }
            kvm_ioctls::VcpuExit::FailEntry(reason, _) => {
                NativeExit::Direct(VcpuExit::FailEntry { reason })
            }
            kvm_ioctls::VcpuExit::InternalError => NativeExit::Direct(VcpuExit::InternalError),
            exit => NativeExit::Direct(VcpuExit::Unknown(format!("{exit:?}"))),
        })
    }

    pub(super) fn run_native(&mut self) -> Result<VcpuExit> {
        self.state_ready()?;
        if let Some(event) = self.io.event().map_err(Error::Emulator)? {
            if matches!(event, io::Event::Input(_)) {
                return Err(Error::InvalidConfig(
                    "KVM native entry requires completion of the pending input".into(),
                ));
            }
            return Ok(public_event(event));
        }
        self.copy_input_reply()?;
        let native = match self.read_native_exit() {
            Ok(native) => native,
            Err(Error::Kvm(error)) if error.errno() == libc::EINTR => {
                // KVM API section5 completes the preceding userspace IO before
                // testing the entry interruption. No new guest exit is invented.
                self.io
                    .finish_native_completion()
                    .map_err(Error::Emulator)?;
                self.pending_io_in = None;
                return Err(Error::Kvm(error));
            }
            Err(error) => return Err(self.fail_native_io(error)),
        };
        self.io
            .finish_native_completion()
            .map_err(Error::Emulator)?;
        self.pending_io_in = None;
        let staged = match native {
            NativeExit::Input(request, pointer, length) => {
                self.io.begin_input(request, length).map(|()| {
                    self.pending_io_in = Some((pointer, length));
                })
            }
            NativeExit::Output(request, length) => self.io.begin_output(request, length),
            NativeExit::Direct(exit) => return Ok(exit),
        };
        if let Err(error) = staged {
            return Err(self.fail_native_io(error));
        }
        match self.io.event().map_err(Error::Emulator)? {
            Some(event) => Ok(public_event(event)),
            None => Err(self.fail_native_io("new native request has no event")),
        }
    }

    pub(super) fn complete_native_input(&mut self, bytes: &[u8]) {
        self.io.complete_input(bytes);
    }

    pub(super) fn acknowledge_native_output(&mut self) -> Result<()> {
        self.io.acknowledge_output().map_err(Error::Emulator)
    }

    pub(super) fn native_completion_status(&self) -> Result<()> {
        self.io
            .ready_for_native_completion()
            .map_err(Error::Emulator)
    }
}
