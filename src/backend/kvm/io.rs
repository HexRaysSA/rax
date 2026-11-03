//! Owned native I/O requests, replies and acknowledged output progress.
//!
//! Native buffer pointers stay with the vCPU adapter and never enter this
//! record. KVM API section 5 requires a further KVM_RUN to complete native I/O;
//! accepting a device reply alone does not establish that native boundary.
//! Metadata checks take O(1); retained payloads take O(n) bytes and copy time.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Input {
    Port { port: u16, size: u8, count: u32 },
    Mmio { address: u64, size: u8 },
}

fn port_bytes(size: u8, count: u32) -> Result<usize, String> {
    if !matches!(size, 1 | 2 | 4) || count == 0 {
        return Err("invalid native port element width or count".into());
    }
    usize::from(size)
        .checked_mul(count as usize)
        .ok_or_else(|| "native port byte count overflow".into())
}

impl Input {
    pub(super) fn bytes(&self) -> Result<usize, String> {
        match *self {
            Self::Port { size, count, .. } => port_bytes(size, count),
            Self::Mmio { size, .. } if (1..=8).contains(&size) => Ok(usize::from(size)),
            Self::Mmio { .. } => Err("invalid native MMIO input length".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Output {
    Port {
        port: u16,
        size: u8,
        count: u32,
        bytes: Vec<u8>,
    },
    Mmio {
        address: u64,
        bytes: Vec<u8>,
    },
}

impl Output {
    fn validate(&self, native_bytes: usize) -> Result<(), String> {
        let (expected, supplied) = match self {
            Self::Port {
                size, count, bytes, ..
            } => (port_bytes(*size, *count)?, bytes.len()),
            Self::Mmio { bytes, .. } => {
                if !(1..=8).contains(&bytes.len()) {
                    return Err("invalid native MMIO output length".into());
                }
                (bytes.len(), bytes.len())
            }
        };
        if expected != supplied || expected != native_bytes {
            return Err("native output metadata differs from its buffer".into());
        }
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Port { bytes, .. } | Self::Mmio { bytes, .. } => bytes,
        }
    }

    fn element_size(&self) -> usize {
        match self {
            Self::Port { size, .. } => usize::from(*size),
            Self::Mmio { bytes, .. } => bytes.len(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Input(Input),
    PortOutput { port: u16, bytes: Vec<u8> },
    MmioOutput { address: u64, bytes: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pending {
    Input {
        request: Input,
        reply: Option<Vec<u8>>,
    },
    Output {
        request: Output,
        acknowledged: usize,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct State {
    pending: Option<Pending>,
    failure: Option<String>,
}

impl State {
    fn healthy(&self) -> Result<(), String> {
        self.failure.clone().map_or(Ok(()), Err)
    }

    fn idle(&self) -> Result<(), String> {
        self.healthy()?;
        if self.pending.is_some() {
            return Err("native I/O completion remains pending".into());
        }
        Ok(())
    }

    fn fail(&mut self, error: String) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
    }

    pub(super) fn begin_input(
        &mut self,
        request: Input,
        native_bytes: usize,
    ) -> Result<(), String> {
        self.idle()?;
        if request.bytes()? != native_bytes {
            return Err("native input metadata differs from its buffer".into());
        }
        self.pending = Some(Pending::Input {
            request,
            reply: None,
        });
        Ok(())
    }

    pub(super) fn begin_output(
        &mut self,
        request: Output,
        native_bytes: usize,
    ) -> Result<(), String> {
        self.idle()?;
        request.validate(native_bytes)?;
        self.pending = Some(Pending::Output {
            request,
            acknowledged: 0,
        });
        Ok(())
    }

    /// Re-emitting an unacknowledged request has no state-changing effect.
    /// A native port batch emits one width-preserving element at a time, always
    /// at the same port. Its full count/payload remain owned until native completion.
    pub(super) fn event(&self) -> Result<Option<Event>, String> {
        self.healthy()?;
        match &self.pending {
            Some(Pending::Input {
                request,
                reply: None,
            }) => Ok(Some(Event::Input(request.clone()))),
            Some(Pending::Output {
                request,
                acknowledged,
            }) if *acknowledged < request.bytes().len() => {
                let end = *acknowledged + request.element_size();
                let bytes = request.bytes()[*acknowledged..end].to_vec();
                Ok(Some(match request {
                    Output::Port { port, .. } => Event::PortOutput { port: *port, bytes },
                    Output::Mmio { address, .. } => Event::MmioOutput {
                        address: *address,
                        bytes,
                    },
                }))
            }
            _ => Ok(None),
        }
    }

    /// Compatibility callback errors are terminal and retain the original
    /// request. A short reply must never leave stale native buffer bytes operative.
    pub(super) fn complete_input(&mut self, bytes: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let Some(Pending::Input { request, reply }) = &mut self.pending else {
            self.fail("unexpected native input completion".into());
            return;
        };
        if reply.is_some() {
            self.fail("duplicate native input completion".into());
            return;
        }
        let expected = match request.bytes() {
            Ok(expected) => expected,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        if bytes.len() != expected {
            self.fail(format!(
                "native input expected {expected} bytes, received {}",
                bytes.len()
            ));
            return;
        }
        let mut owned = Vec::new();
        if let Err(error) = owned.try_reserve_exact(expected) {
            self.fail(format!("native input reply allocation: {error}"));
            return;
        }
        owned.extend_from_slice(bytes);
        *reply = Some(owned);
    }

    pub(super) fn acknowledge_output(&mut self) -> Result<(), String> {
        self.healthy()?;
        match &mut self.pending {
            Some(Pending::Output {
                request,
                acknowledged,
            }) if *acknowledged < request.bytes().len() => {
                *acknowledged += request.element_size();
                Ok(())
            }
            _ => {
                let error = "unexpected native output acknowledgment".to_string();
                self.fail(error.clone());
                Err(error)
            }
        }
    }

    /// The device phase is complete; a native KVM_RUN is still required.
    pub(super) fn ready_for_native_completion(&self) -> Result<(), String> {
        self.healthy()?;
        if self.event()?.is_some() {
            return Err("native I/O requires a device reply or acknowledgment".into());
        }
        Ok(())
    }

    pub(super) fn input_reply(&self) -> Result<Option<&[u8]>, String> {
        self.ready_for_native_completion()?;
        Ok(match &self.pending {
            Some(Pending::Input {
                reply: Some(reply), ..
            }) => Some(reply),
            _ => None,
        })
    }

    /// Called only after the adapter observes successful native completion.
    /// A preparation error must leave this record and its native buffer intact.
    pub(super) fn finish_native_completion(&mut self) -> Result<(), String> {
        self.ready_for_native_completion()?;
        self.pending = None;
        Ok(())
    }

    pub(super) fn has_native_completion(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
#[path = "io_tests.rs"]
mod tests;
