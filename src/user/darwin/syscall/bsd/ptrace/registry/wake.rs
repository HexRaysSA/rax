//! Wake only the stopped socket peer, using its kernel audit identity.
//! libproc returns an errno value, not the kill(2) -1 convention. The native
//! probe verifies ESRCH for a stale pidversion and success for the real token.

use super::Record;
use std::io;
use std::os::unix::net::UnixStream;

#[derive(Debug)]
pub(super) struct Wake {
    #[cfg(target_vendor = "apple")]
    token: [u32; 8],
}

impl Wake {
    pub fn prepare(stream: &UnixStream, expected: Record) -> io::Result<Option<Self>> {
        super::identity::require(stream, expected.pid, expected.uid)?;
        #[cfg(target_vendor = "apple")]
        {
            use std::os::fd::AsRawFd;
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
            // SAFETY: the kernel receives a writable, correctly sized SDK layout.
            let got = unsafe {
                libc::proc_pidinfo(
                    expected.pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    size,
                )
            };
            if got != size {
                return Err(io::Error::last_os_error());
            }
            // SSTOP from XNU sys/proc.h. A running peer must receive no SIGCONT.
            if unsafe { info.assume_init() }.pbi_status != 4 {
                return Ok(None);
            }
            let token = super::identity::option(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
            )?;
            return Ok(Some(Self { token }));
        }
        #[cfg(not(target_vendor = "apple"))]
        Ok(None)
    }

    pub fn signal(mut self) -> io::Result<()> {
        #[cfg(target_vendor = "apple")]
        {
            unsafe extern "C" {
                fn proc_signal_with_audittoken(
                    token: *mut [u32; 8],
                    signal: libc::c_int,
                ) -> libc::c_int;
            }
            // SAFETY: the token is the complete 32-byte kernel socket identity;
            // libproc resolves pidversion before signalling, preventing PID reuse.
            let result = unsafe { proc_signal_with_audittoken(&mut self.token, libc::SIGCONT) };
            if result == 0 {
                Ok(())
            } else if result > 0 {
                Err(io::Error::from_raw_os_error(result))
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(target_vendor = "apple"))]
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn a_running_peer_is_not_woken_and_a_stale_audit_generation_is_rejected() {
        let temp = super::super::tests::Temporary::new();
        let root = temp.root();
        let endpoint = root.publish().unwrap();
        let mut dial = root.connect(endpoint.record.pid).unwrap();
        let stream = dial.finish().unwrap().unwrap();
        assert!(Wake::prepare(&stream, endpoint.record).unwrap().is_none());
        let mut token: [u32; 8] = super::super::identity::option(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
        )
        .unwrap();
        token[7] ^= 0x80000000;
        assert_eq!(
            Wake { token }.signal().unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
