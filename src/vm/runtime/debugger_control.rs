//! All-stop scheduling and shared breakpoint publication at the VMM boundary.
use super::*;
mod transaction;
use crate::debug::gdb::{Resume, ResumeAction, threads::resume_plan};
impl Vmm {
    pub(super) fn debugger_allows_cpu(&self, index: usize) -> bool {
        self.debugger.failure.is_none()
            && !self.gdb_stopped
            && self
                .debugger
                .resume
                .as_ref()
                .is_none_or(|p| p.get(index).is_some_and(|a| *a != ResumeAction::Stop))
    }
    /// None rejects the complete request; true resumes; false reports a stop.
    pub(super) fn resume_debugger(&mut self, actions: &[Resume]) -> Result<Option<bool>> {
        if let Some(error) = &self.debugger.failure {
            return Err(Error::Emulator(error.clone()));
        }
        let Some(plan) = resume_plan(actions, self.vcpus.len(), self.debugger.general) else {
            return Ok(None);
        };
        let running = plan.iter().any(|a| *a != ResumeAction::Stop);
        if running
            && !plan
                .iter()
                .zip(&self.coordinator.online)
                .any(|(a, on)| *on && *a != ResumeAction::Stop)
        {
            return Ok(None);
        }
        if plan
            .iter()
            .zip(&self.coordinator.online)
            .any(|(a, on)| !on && *a == ResumeAction::Step)
        {
            return Ok(None);
        }
        let before: Vec<_> = self.vcpus.iter().map(|c| c.is_single_step()).collect();
        for index in 0..self.vcpus.len() {
            let step = plan[index] == ResumeAction::Step;
            self.vcpus[index].set_single_step(step);
            if self.vcpus[index].is_single_step() != step {
                for (cpu, old) in self.vcpus.iter_mut().zip(&before) {
                    cpu.set_single_step(*old);
                }
                if self
                    .vcpus
                    .iter()
                    .zip(&before)
                    .any(|(cpu, old)| cpu.is_single_step() != *old)
                {
                    return Err(
                        self.poison_debugger("debug step rollback failed; CPU entry excluded")
                    );
                }
                return Ok(None);
            }
        }
        self.gdb_single_step = plan.contains(&ResumeAction::Step);
        self.debugger.resume = Some(plan);
        self.gdb_stopped = !running;
        if !running {
            let index = actions[0]
                .thread
                .index(self.vcpus.len(), self.debugger.general)
                .expect("validated stop thread");
            self.stop_debugger(index, 2)?;
        }
        Ok(Some(running))
    }
    pub(super) fn stop_debugger(&mut self, index: usize, signal: u8) -> Result<()> {
        if let Some(error) = &self.debugger.failure {
            return Err(Error::Emulator(error.clone()));
        }
        self.gdb_stopped = true;
        self.gdb_single_step = false;
        self.debugger.general = index;
        self.debugger.stop = (index, signal);
        self.debugger.resume = Some(vec![ResumeAction::Stop; self.vcpus.len()]);
        for cpu in &mut self.vcpus {
            cpu.set_single_step(false);
            if cpu.is_single_step() {
                self.debugger.failure =
                    Some("debug stop failed to disable stepping; CPU entry excluded".into());
                return Err(Error::Emulator(self.debugger.failure.clone().unwrap()));
            }
        }
        Ok(())
    }
    /// Publish an execute breakpoint to every CPU without altering guest text.
    pub(super) fn debug_breakpoint(&mut self, addr: u64, insert: bool) -> Result<bool> {
        if let Some(error) = &self.debugger.failure {
            return Err(Error::Emulator(error.clone()));
        }
        if self
            .vcpus
            .iter()
            .any(|cpu| !cpu.supports_debug_breakpoints())
        {
            return Ok(false);
        }
        if self.gdb_breakpoints.contains(&addr) == insert {
            return Ok(true);
        }
        let result = transaction::all_cpus(self.vcpus.len(), insert, |index, insert| {
            if insert {
                self.vcpus[index].set_debug_breakpoint(addr)
            } else {
                self.vcpus[index].clear_debug_breakpoint(addr)
            }
        });
        match result {
            Ok(true) => (),
            Ok(false) => return Ok(false),
            Err(reason) => return Err(self.poison_debugger(&reason)),
        }
        if insert {
            self.gdb_breakpoints.insert(addr);
        } else {
            self.gdb_breakpoints.remove(&addr);
        }
        Ok(true)
    }
    fn poison_debugger(&mut self, reason: &str) -> Error {
        self.gdb_stopped = true;
        self.debugger.failure = Some(reason.into());
        Error::Emulator(reason.into())
    }
    pub(super) fn detach_debugger(&mut self) -> Result<()> {
        if let Some(error) = &self.debugger.failure {
            return Err(Error::Emulator(error.clone()));
        }
        let addresses: Vec<_> = self.gdb_breakpoints.iter().copied().collect();
        for addr in addresses {
            if !self.debug_breakpoint(addr, false)? {
                return Err(self.poison_debugger(
                    "debug detach could not clear a breakpoint; CPU entry excluded",
                ));
            }
        }
        for cpu in &mut self.vcpus {
            cpu.set_single_step(false);
            if cpu.is_single_step() {
                self.debugger.failure =
                    Some("debug detach failed to disable stepping; CPU entry excluded".into());
                self.gdb_stopped = true;
                return Err(Error::Emulator(self.debugger.failure.clone().unwrap()));
            }
            cpu.set_debugger_active(false);
        }
        self.gdb_stopped = false;
        self.gdb_single_step = false;
        self.debugger = debugger::State::default();
        Ok(())
    }
}
