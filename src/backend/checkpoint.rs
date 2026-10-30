//! Backend-owned exclusion held across a complete checkpoint operation.

use crate::error::{Error, Result};

trait Held {}
impl<T> Held for T {}

/// A stopped backend boundary. Only a producing backend can issue a matching
/// owner identity; hardware operations use it without recursively taking the
/// exclusion lock. The lease remains on the calling checkpoint thread.
pub struct CheckpointBoundary<'a> {
    owner: Option<usize>,
    _lease: Box<dyn Held + 'a>,
}

impl<'a> CheckpointBoundary<'a> {
    pub fn empty() -> Self {
        Self {
            owner: None,
            _lease: Box::new(()),
        }
    }

    pub(crate) fn held<T: 'a>(owner: usize, lease: T) -> Self {
        Self {
            owner: Some(owner),
            _lease: Box::new(lease),
        }
    }

    pub(crate) fn require_owner(&self, owner: usize) -> Result<()> {
        if self.owner == Some(owner) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "checkpoint boundary belongs to another backend VM".into(),
            ))
        }
    }
}
