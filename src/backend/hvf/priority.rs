//! Canonical software TPR with a stopped native SDK mirror.
use std::sync::Mutex;

pub(crate) trait Register {
    fn load(&self) -> u32;
    fn store(&self, value: u32);
}
pub(crate) trait Host {
    fn read_tpr(&mut self) -> Result<u64, String>;
    fn write_tpr(&mut self, value: u64) -> Result<(), String>;
}
pub(crate) struct State<R> {
    register: R,
    failure: Mutex<Option<String>>,
}
impl<R: Register> State<R> {
    pub(crate) fn new(register: R) -> Self {
        Self {
            register,
            failure: Mutex::new(None),
        }
    }
    pub(crate) fn rebind(&mut self, register: R) {
        self.register = register;
    }
    pub(crate) fn ready(&self) -> Result<(), String> {
        match self.failure.lock() {
            Ok(guard) => guard.clone().map_or_else(
                || {
                    if self.register.load() > 255 {
                        Err("HVF canonical TPR has reserved bits".into())
                    } else {
                        Ok(())
                    }
                },
                Err,
            ),
            Err(_) => Err("HVF priority failure latch poisoned".into()),
        }
    }
    pub(crate) fn poison(&self, reason: String) -> String {
        let error = format!("HVF priority publication failed; guest entry prohibited: {reason}");
        if let Ok(mut guard) = self.failure.lock() {
            if guard.is_none() {
                *guard = Some(error.clone());
            }
        }
        error
    }
    pub(crate) fn read(&self) -> Result<u64, String> {
        self.ready()?;
        let value = self.register.load();
        if value > 255 {
            return Err("HVF canonical TPR has reserved bits".into());
        }
        Ok(u64::from(value))
    }
    pub(crate) fn commit_import(&self, value: u32) -> Result<(), String> {
        self.ready()?;
        if value > 255 {
            return Err("invalid full TPR import".into());
        }
        self.register.store(value);
        Ok(())
    }
    pub(crate) fn write(&self, host: &mut impl Host, value: u64) -> Result<(), String> {
        self.ready()?;
        if value > 255 {
            return Err("invalid full TPR value".into());
        }
        host.write_tpr(value).map_err(|e| self.poison(e))?;
        self.register.store(value as u32);
        Ok(())
    }
    pub(crate) fn prepare_entry(&self, host: &mut impl Host) -> Result<(), String> {
        let canonical = self.read()?;
        if host.read_tpr()? != canonical {
            host.write_tpr(canonical).map_err(|e| self.poison(e))?;
        }
        Ok(())
    }
}
