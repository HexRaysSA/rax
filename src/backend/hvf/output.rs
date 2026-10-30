//! Retain a native output until device dispatch is acknowledged.
//! Guest retirement and host-step completion happen after the acknowledgment.

pub(crate) struct State<T> {
    pending: Option<(T, u64)>,
    failure: Option<String>,
}

impl<T> Default for State<T> {
    fn default() -> Self {
        Self {
            pending: None,
            failure: None,
        }
    }
}

impl<T: Clone> State<T> {
    pub(crate) fn ready(&self) -> Result<(), String> {
        self.healthy()?;
        if self.pending.is_some() {
            return Err("HVF output acknowledgment is pending".into());
        }
        Ok(())
    }

    pub(crate) fn healthy(&self) -> Result<(), String> {
        self.failure.clone().map_or(Ok(()), Err)
    }

    pub(crate) fn pending(&self) -> Result<Option<T>, String> {
        self.healthy()?;
        Ok(self.pending.as_ref().map(|(exit, _)| exit.clone()))
    }

    pub(crate) fn begin(&mut self, exit: T, length: u64) -> Result<T, String> {
        self.ready()?;
        if !(1..=15).contains(&length) {
            return Err("invalid HVF output instruction length".into());
        }
        self.pending = Some((exit.clone(), length));
        Ok(exit)
    }

    /// The device has already accepted the output. A failed architectural
    /// completion is terminal; retrying dispatch would repeat a device effect.
    pub(crate) fn acknowledge(
        &mut self,
        complete: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        self.healthy()?;
        let Some((_, length)) = self.pending.as_ref() else {
            let error = "unexpected HVF output acknowledgment".to_string();
            self.failure = Some(error.clone());
            return Err(error);
        };
        if let Err(error) = complete(*length) {
            let error =
                format!("HVF output completion failed after device acknowledgment: {error}");
            self.failure = Some(error.clone());
            return Err(error);
        }
        self.pending = None;
        Ok(())
    }
}
