//! A program that stays: started once, called any number of times, ended
//! once.
//!
//! [`run_on`](super::run_on) makes a process for one call and ends it with
//! the call. A library is used otherwise: its initializers run once, its
//! functions are called again and again on the state the earlier calls
//! left, and its finalizers run when its user has done with it. An
//! [`Instance`] is such a process.
//!
//! The process lives on a host thread of its own, which is its first guest
//! thread: that thread runs the initializers, then each call as it is
//! asked for, one after another, then the finalizers. The threads a call
//! starts go on running when the call has returned, and end with the
//! instance at the latest.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use crate::Error;
use crate::ir::{FuncIdx, Module, Pointer, Value};

use super::exec::internal;
use super::host::Host;
use super::process::Process;
use super::{Code, Engine, Exit, Outcome, Policy};

/// How a call of an instance came out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Called {
    /// The function returned these values, and the instance is there for
    /// the next call.
    Returned(Vec<Value>),
    /// The call ended the program, or the program had ended: by a fault, at
    /// a limit, or because it ended itself. The instance takes no more
    /// calls.
    Ended(Exit),
}

/// Where a pointer that the program gave out comes to when its holder
/// moves it; see [`Instance::offset`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moved {
    /// The pointer that many bytes on: into the same object, or to one
    /// past its end.
    To(Pointer),
    /// That would be beyond the object.
    Outside,
    /// The object is no longer there, or the program has ended.
    Gone,
}

/// What the instance's thread is asked to do.
pub(super) enum Request {
    Call {
        entry: FuncIdx,
        arguments: Vec<Value>,
        reply: Sender<Result<Called, Error>>,
    },
    Offset {
        pointer: Pointer,
        bytes: u64,
        reply: Sender<Moved>,
    },
    Finish,
}

/// A process that lasts from [`Instance::start`] to [`Instance::finish`].
pub struct Instance {
    requests: Sender<Request>,
    /// The process's thread, which returns how the program ended.
    worker: Option<JoinHandle<Result<Outcome, Error>>>,
}

impl Instance {
    /// Start a process of `module`: create its data and run its
    /// initializers. With `code`, which must have been compiled from this
    /// module, the program runs as native code.
    ///
    /// # Errors
    ///
    /// `EXEC_CAPABILITY` names a capability the module declares and `host`
    /// does not grant; `EXEC_ENGINE` if `code` is of another module. A
    /// module whose data does not fit the memory limit, or whose
    /// initializers do not all return, is started all the same: its first
    /// call says how the program ended.
    pub fn start(
        module: Arc<Module>,
        code: Option<Arc<Code>>,
        policy: Policy,
        mut host: Box<dyn Host>,
    ) -> Result<Self, Error> {
        let (requests, received) = channel();
        let (started, starting) = channel();
        let worker = std::thread::Builder::new()
            .name("portable instance".into())
            .spawn(move || {
                let engine = match &code {
                    Some(code) => Engine::Native(code),
                    None => Engine::Interpreter,
                };
                let process = match Process::start(&module, policy, &mut *host, engine) {
                    Ok(process) => {
                        let _ = started.send(Ok(()));
                        process
                    }
                    Err(error) => {
                        let _ = started.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                match process {
                    Ok(process) => process.serve(&received),
                    // The data did not fit: every call is told so.
                    Err(outcome) => {
                        refuse(&received, &outcome.exit);
                        Ok(outcome)
                    }
                }
            })
            .map_err(|_| Error::resource("EXEC_THREAD", "no thread for the instance"))?;
        starting
            .recv()
            .map_err(|_| internal("the instance's thread ended before it started"))??;
        Ok(Self {
            requests,
            worker: Some(worker),
        })
    }

    /// Call `entry` with `arguments` and wait for it to return.
    ///
    /// # Errors
    ///
    /// `EXEC_ENTRY` if the arguments do not match the function's parameter
    /// types in number or shape; the instance is as it was.
    pub fn call(&self, entry: FuncIdx, arguments: &[Value]) -> Result<Called, Error> {
        let (reply, answer) = channel();
        let request = Request::Call {
            entry,
            arguments: arguments.to_vec(),
            reply,
        };
        if self.requests.send(request).is_err() {
            return Err(internal("the instance's thread has ended"));
        }
        answer
            .recv()
            .map_err(|_| internal("the instance's thread ended during a call"))?
    }

    /// Move a pointer the program returned `bytes` on within the object it
    /// points into: to hand a call the address of a later part of what an
    /// earlier call returned. The pointer keeps the object it may access;
    /// nothing is read or written. A pointer into no object, such as a
    /// null pointer, is moved by nothing only.
    ///
    /// The instance's thread answers between two calls, so this waits for
    /// a call that is running.
    pub fn offset(&self, pointer: Pointer, bytes: u64) -> Moved {
        let (reply, answer) = channel();
        let request = Request::Offset {
            pointer,
            bytes,
            reply,
        };
        // An instance whose thread has ended has no objects.
        if self.requests.send(request).is_err() {
            return Moved::Gone;
        }
        answer.recv().unwrap_or(Moved::Gone)
    }

    /// End the program: run its finalizers, unless it has ended already,
    /// stop its other threads, and say how it ended and how many steps it
    /// took in all. A program that was only called and never ended itself
    /// ends by returning nothing.
    pub fn finish(mut self) -> Result<Outcome, Error> {
        self.end()
    }

    fn end(&mut self) -> Result<Outcome, Error> {
        let _ = self.requests.send(Request::Finish);
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| internal("the instance's thread panicked"))?,
            None => Err(internal("the instance has ended")),
        }
    }
}

impl Drop for Instance {
    /// An instance that is dropped is finished.
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.end();
        }
    }
}

/// Answer every call with how the program ended, until no more is asked.
pub(super) fn refuse(requests: &Receiver<Request>, exit: &Exit) {
    while let Ok(request) = requests.recv() {
        match request {
            Request::Call { reply, .. } => {
                let _ = reply.send(Ok(Called::Ended(exit.clone())));
            }
            Request::Offset { reply, .. } => {
                let _ = reply.send(Moved::Gone);
            }
            Request::Finish => break,
        }
    }
}
