//! Communication endpoint views follow the final local handle, not Arc Drop.
use super::{ObjId, Object, Objects};
use crate::user::windows::memory::{SharedViewOwner, VirtualMemory, VmError};

/// Typed process-local LPC endpoint. This object never owns a host port handle
/// and alone does not establish a connection or admit message services.
#[derive(Debug)]
pub struct LpcPort {
    view: Option<SharedViewOwner>,
    peer: Option<Peer>,
}

#[derive(Debug)]
enum Peer {
    Csr(Box<crate::user::windows::object_namespace::csr::CsrPeer>),
    Cache(Box<crate::user::windows::object_namespace::cache::CachePeer>),
}

impl LpcPort {
    pub(crate) fn new(view: Option<SharedViewOwner>) -> Self {
        Self { view, peer: None }
    }

    pub(crate) fn csr(
        view: SharedViewOwner,
        peer: crate::user::windows::object_namespace::csr::CsrPeer,
    ) -> Self {
        Self {
            view: Some(view),
            peer: Some(Peer::Csr(Box::new(peer))),
        }
    }

    pub(crate) fn cache(peer: crate::user::windows::object_namespace::cache::CachePeer) -> Self {
        Self {
            view: None,
            peer: Some(Peer::Cache(Box::new(peer))),
        }
    }

    pub(crate) fn peer(&self) -> Option<&crate::user::windows::object_namespace::csr::CsrPeer> {
        match &self.peer {
            Some(Peer::Csr(peer)) => Some(peer),
            _ => None,
        }
    }

    pub(crate) fn peer_mut(
        &mut self,
    ) -> Option<&mut crate::user::windows::object_namespace::csr::CsrPeer> {
        match &mut self.peer {
            Some(Peer::Csr(peer)) => Some(peer),
            _ => None,
        }
    }

    pub(crate) fn cache_peer(
        &self,
    ) -> Option<&crate::user::windows::object_namespace::cache::CachePeer> {
        match &self.peer {
            Some(Peer::Cache(peer)) => Some(peer),
            _ => None,
        }
    }

    pub(crate) fn cache_peer_mut(
        &mut self,
    ) -> Option<&mut crate::user::windows::object_namespace::cache::CachePeer> {
        match &mut self.peer {
            Some(Peer::Cache(peer)) => Some(peer),
            _ => None,
        }
    }

    pub(crate) fn view(&self) -> Option<&SharedViewOwner> {
        self.view.as_ref()
    }

    pub(super) fn take_view(&mut self) -> Option<SharedViewOwner> {
        self.view.take()
    }

    pub(super) fn retire_cache_peer(&mut self) {
        if matches!(&self.peer, Some(Peer::Cache(_))) {
            self.peer = None;
        }
    }
}

impl Objects {
    /// Closing a duplicate preserves the local view. The last handle retires
    /// it even when an internal wait/reference still retains the object.
    pub(super) fn retire_lpc_handle(&mut self, id: ObjId) {
        if let Some(Object::LpcPort(port)) = self.obj_mut(id) {
            port.retire_cache_peer();
            if let Some(view) = port.take_view() {
                self.retired_lpc_views.push(view);
            }
        }
    }

    /// Covers rollback of an unpublished endpoint as well as final release.
    pub(super) fn retire_lpc_object(&mut self, object: &mut Object) {
        if let Object::LpcPort(port) = object {
            port.retire_cache_peer();
            if let Some(view) = port.take_view() {
                self.retired_lpc_views.push(view);
            }
        }
    }

    /// Native/HLE completion and process drain use the same retirement queue.
    /// A failed release stays queued; an already unmapped/replaced view is a
    /// successful no-op under its allocation generation token.
    pub(crate) fn reclaim_lpc_views(&mut self, vm: &mut VirtualMemory) -> Result<(), VmError> {
        while let Some(view) = self.retired_lpc_views.last() {
            vm.retire_shared_view(view)?;
            self.retired_lpc_views.pop();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
