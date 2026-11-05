//! Bounded output ownership; acceptance and EOI are distinct transitions.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) request: PendingIrq,
    pub(crate) delivery_mode: u8,
    pub(crate) logical_destination: bool,
}

impl IoApic {
    /// Inspect a message without transferring ownership. Routes that cannot
    /// accept it leave the controller's original request and status intact.
    pub(crate) fn pending_message(&self, index: usize) -> Option<Message> {
        let request = *self.pending.get(index)?;
        let rte = self.redirection_table[usize::from(request.gsi)];
        Some(Message {
            request,
            delivery_mode: ((rte >> RTE_DELIVERY_MODE_SHIFT) & 7) as u8,
            logical_destination: rte & (1 << 11) != 0,
        })
    }

    /// Commit only the exact message observed by the caller. A reprogrammed
    /// route cannot be consumed using a stale destination/vector descriptor.
    pub(crate) fn accept_message(&mut self, message: Message) -> bool {
        let Some(index) = self
            .pending
            .iter()
            .position(|request| request.gsi == message.request.gsi)
        else {
            return false;
        };
        if self.pending_message(index) != Some(message) {
            return false;
        }
        let request = self.pending.remove(index);
        self.accept(&request);
        true
    }

    pub(super) fn cancel_pending(&mut self, entry: usize) {
        if self
            .pending
            .iter()
            .any(|request| usize::from(request.gsi) == entry)
        {
            self.pending
                .retain(|request| usize::from(request.gsi) != entry);
            self.redirection_table[entry] &= !RTE_DELIVERY_STATUS;
        }
    }

    pub(super) fn refresh_pending(&mut self, entry: usize) {
        let rte = self.redirection_table[entry];
        if rte & RTE_MASK != 0 || (rte & RTE_TRIGGER_MODE != 0 && !self.line_asserted[entry]) {
            self.cancel_pending(entry);
            return;
        }
        if let Some(request) = self
            .pending
            .iter_mut()
            .find(|request| usize::from(request.gsi) == entry)
        {
            request.vector = rte as u8;
            request.destination = (rte >> RTE_DEST_SHIFT) as u8;
            request.level_triggered = rte & RTE_TRIGGER_MODE != 0;
        }
    }

    pub(super) fn accept(&mut self, request: &PendingIrq) {
        let entry = usize::from(request.gsi);
        self.redirection_table[entry] &= !RTE_DELIVERY_STATUS;
        // Remote IRR belongs to fixed/lowest-priority level messages. Special
        // delivery modes do not participate in this vector EOI handshake.
        let mode = (self.redirection_table[entry] >> RTE_DELIVERY_MODE_SHIFT) & 7;
        if request.level_triggered && matches!(mode, 0 | 1) {
            self.redirection_table[entry] |= RTE_REMOTE_IRR;
        }
    }

    /// Complete a directed or broadcast EOI. A matching in-service level can
    /// issue another message only if its source remains asserted and unmasked.
    pub(crate) fn end_of_interrupt(&mut self, vector: u8) {
        for entry in 0..IOAPIC_NUM_RTE {
            let rte = self.redirection_table[entry];
            if rte as u8 == vector && rte & RTE_REMOTE_IRR != 0 {
                self.redirection_table[entry] &= !RTE_REMOTE_IRR;
                if rte & RTE_TRIGGER_MODE != 0 && self.line_asserted[entry] {
                    self.evaluate_entry(entry);
                }
            }
        }
    }
}
