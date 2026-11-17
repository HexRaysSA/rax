use std::io;
use std::os::fd::OwnedFd;

use super::Access;
use crate::user::mm::process_owner::client::RemoteError;
use crate::user::mm::process_owner::wire::{
    Request, Response, ViewFailure, ViewOperation, ViewValue,
};

impl Access {
    pub(in crate::user::mm::process_owner) fn check(&self) -> Result<(), RemoteError> {
        self.endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
            .current(self.space, None)?;
        Ok(())
    }

    pub(in crate::user::mm::process_owner) fn view(
        &self,
        operation: ViewOperation,
    ) -> Result<(ViewValue, Vec<OwnedFd>), RemoteError> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let active = endpoint.current(self.space, None)?;
        let (response, frame) = endpoint.exchange(&Request::View {
            serial: active.serial,
            operation,
        })?;
        match response {
            Response::View { result: Ok(value) } => Ok((value, frame.files)),
            Response::View { result: Err(error) } if frame.files.is_empty() => match error {
                ViewFailure::Memory { error } => Err(RemoteError::Memory(error)),
                ViewFailure::Preparation { error } => Err(RemoteError::Preparation(error)),
                ViewFailure::HostMemory => Err(self.fail(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "fileless host memory requires a native process-view transport",
                ))),
            },
            _ => Err(endpoint.reject().into()),
        }
    }

    pub(in crate::user::mm::process_owner) fn fail(&self, error: io::Error) -> RemoteError {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.close();
        }
        RemoteError::Transport(error)
    }
}
