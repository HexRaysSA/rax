//! Retained scalar output and its caller-acknowledged retirement phase.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Retirement {
    pub next_pc: u64,
    pub acknowledged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingWrite {
    pub address: u64,
    pub data: Vec<u8>,
    /// None imports the historically already-retired V4/V5 output.
    pub retirement: Option<Retirement>,
}

impl PendingWrite {
    pub(crate) fn awaits_dispatch(&self) -> bool {
        self.retirement
            .as_ref()
            .is_none_or(|phase| !phase.acknowledged)
    }

    /// The caller has successfully dispatched the device write. Record that
    /// fact before the fallible PC publication, so reentry cannot dispatch twice.
    pub(crate) fn acknowledge<E>(
        &mut self,
        write_pc: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(phase) = &mut self.retirement {
            phase.acknowledged = true;
            write_pc(phase.next_pc)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn output(next_pc: u64) -> PendingWrite {
        PendingWrite {
            address: 0x9000030,
            data: vec![0xa5; 8],
            retirement: Some(Retirement {
                next_pc,
                acknowledged: false,
            }),
        }
    }

    #[test]
    fn failed_pc_publication_never_requests_a_second_device_dispatch() {
        for after_mutation in [false, true] {
            let mut pending = output(4);
            let mut pc = 0;
            let mut dispatched = 0;
            assert!(pending.awaits_dispatch());
            if pending.awaits_dispatch() {
                dispatched += 1;
            }
            assert_eq!(
                pending.acknowledge(|next| {
                    if after_mutation {
                        pc = next;
                    }
                    Err("SDK failure")
                }),
                Err("SDK failure")
            );
            assert!(!pending.awaits_dispatch());
            assert_eq!(pc, if after_mutation { 4 } else { 0 });
            for _ in 0..2 {
                if pending.awaits_dispatch() {
                    dispatched += 1;
                }
                assert_eq!(
                    pending.acknowledge(|next| {
                        pc = next;
                        Err("SDK failure")
                    }),
                    Err("SDK failure")
                );
            }
            assert_eq!(dispatched, 1);
            assert_eq!(pc, 4);
            assert_eq!(
                pending.acknowledge(|next| {
                    pc = next;
                    Ok::<_, &str>(())
                }),
                Ok(())
            );
            assert_eq!(pc, 4);
            assert_eq!(pending.address, 0x9000030);
            assert_eq!(pending.data, vec![0xa5; 8]);
        }
    }

    #[test]
    fn legacy_output_acknowledgement_performs_no_additional_pc_write() {
        let mut pending = output(4);
        pending.retirement = None;
        assert!(pending.awaits_dispatch());
        let result: Result<(), &str> =
            pending.acknowledge(|_| panic!("legacy PC was already advanced"));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn deferred_output_retires_to_an_absolute_wrapping_frontier() {
        for (before, next) in [(0, 4), (u64::MAX - 3, 0)] {
            let mut pc = before;
            let mut pending = output(next);
            pending
                .acknowledge(|next| {
                    pc = next;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(pc, next);
            assert!(!pending.awaits_dispatch());
            pending
                .acknowledge(|next| {
                    pc = next;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(pc, next);
        }
    }
}
