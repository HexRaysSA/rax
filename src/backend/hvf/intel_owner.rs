//! Permanent SDK owner. The core is constructed, accessed and dropped here;
//! it need not be Send. Only closures and their results cross the channel.
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

type Operation<T> = Box<dyn FnOnce(&mut T) + Send + 'static>;
pub(crate) type Failure = Arc<dyn Fn(String) + Send + Sync>;

pub(crate) enum StartError<E> {
    Spawn(std::io::Error),
    Create(E),
    Owner(String),
}

pub(crate) struct Owner<T: 'static> {
    sender: Option<mpsc::Sender<Operation<T>>>,
    worker: Option<JoinHandle<()>>,
    failed: Failure,
}

impl<T: 'static> Owner<T> {
    pub(crate) fn spawn<E: Send + 'static>(
        name: String,
        create: impl FnOnce() -> Result<T, E> + Send + 'static,
        failed: Failure,
    ) -> Result<Self, StartError<E>> {
        let (sender, receiver) = mpsc::channel::<Operation<T>>();
        let (ready, created) = mpsc::sync_channel(1);
        let worker_failed = failed.clone();
        let worker = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut core = match create() {
                        Ok(core) => core,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    if ready.send(Ok(())).is_err() {
                        return;
                    }
                    for operation in receiver {
                        operation(&mut core);
                    }
                }));
                if let Err(panic) = result {
                    worker_failed("Intel HVF owner panicked".into());
                    std::panic::resume_unwind(panic);
                }
            })
            .map_err(StartError::Spawn)?;
        match created.recv() {
            Ok(Ok(())) => Ok(Self {
                sender: Some(sender),
                worker: Some(worker),
                failed,
            }),
            result => {
                drop(sender);
                let joined = worker.join();
                if joined.is_err() {
                    failed("Intel HVF owner panicked during creation".into());
                }
                match result {
                    Ok(Err(error)) => Err(StartError::Create(error)),
                    _ => Err(StartError::Owner(
                        "Intel HVF owner stopped during creation".into(),
                    )),
                }
            }
        }
    }

    pub(crate) fn call<R: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut T) -> R + Send + 'static,
    ) -> Result<R, String> {
        let (reply, result) = mpsc::sync_channel(1);
        let error = || {
            let error = "Intel HVF owner is unavailable".to_string();
            (self.failed)(error.clone());
            error
        };
        self.sender
            .as_ref()
            .ok_or_else(error)?
            .send(Box::new(move |core| {
                let _ = reply.send(operation(core));
            }))
            .map_err(|_| error())?;
        result.recv().map_err(|_| error())
    }

    /// Disconnect before joining so the idle worker can destroy its core.
    /// No other caller can submit work after &mut self closes the sender.
    pub(crate) fn close(&mut self) -> Result<(), String> {
        drop(self.sender.take());
        if self
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_err())
        {
            let error = "Intel HVF owner teardown panicked".to_string();
            (self.failed)(error.clone());
            return Err(error);
        }
        Ok(())
    }
}

impl<T: 'static> Drop for Owner<T> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
