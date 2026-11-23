use super::{Error, WorkspaceFlavor, permitted};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timestamp {
    pub(crate) seconds: i64,
    pub(crate) nanoseconds: i64,
}

impl Timestamp {
    fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => Self {
                seconds: duration.as_secs() as i64,
                nanoseconds: i64::from(duration.subsec_nanos()),
            },
            Err(error) => {
                let duration = error.duration();
                let fraction = i64::from(duration.subsec_nanos());
                Self {
                    seconds: -(duration.as_secs() as i64) - i64::from(fraction != 0),
                    nanoseconds: if fraction == 0 {
                        0
                    } else {
                        1_000_000_000 - fraction
                    },
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timestamps {
    pub(crate) accessed: Timestamp,
    pub(crate) modified: Timestamp,
    pub(crate) changed: Timestamp,
    pub(crate) created: Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetTime {
    Now,
    Omit,
    At(Timestamp),
}

pub(in crate::user) struct TimeUpdate {
    pub(crate) times: [SetTime; 2],
    pub(crate) allow_write: bool,
    pub(in crate::user) flavor: WorkspaceFlavor,
}

impl SetTime {
    fn value(self, prior: Timestamp, now: Timestamp) -> Timestamp {
        match self {
            Self::Now => now,
            Self::Omit => prior,
            Self::At(time) => time,
        }
    }
}

#[derive(Debug)]
struct Values {
    mode: u32,
    times: Timestamps,
}

#[derive(Debug)]
pub(in crate::user::supplied_fs) struct Attributes {
    owner: (u32, u32),
    values: Mutex<Values>,
    xattrs: std::sync::Arc<super::Xattrs>,
}

impl Attributes {
    pub(super) fn new(
        mode: u32,
        owner: (u32, u32),
        budget: std::sync::Arc<Mutex<super::Budget>>,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            owner,
            xattrs: std::sync::Arc::new(super::Xattrs::new(budget)),
            values: Mutex::new(Values {
                mode: mode & 0o7777,
                times: Timestamps {
                    accessed: now,
                    modified: now,
                    changed: now,
                    created: now,
                },
            }),
        }
    }

    pub(super) fn clone_values(
        &self,
    ) -> Result<(u32, Timestamps, super::xattr::Values, usize), Error> {
        let values = self.values.lock().map_err(|_| Error::Io)?;
        let (xattrs, bytes) = self.xattrs.clone_values()?;
        Ok((values.mode, values.times, xattrs, bytes))
    }

    pub(super) fn from_clone(
        mode: u32,
        mut times: Timestamps,
        owner: (u32, u32),
        xattrs: super::Xattrs,
    ) -> Self {
        times.changed = Timestamp::now();
        Self {
            owner,
            values: Mutex::new(Values { mode, times }),
            xattrs: std::sync::Arc::new(xattrs),
        }
    }

    pub(in crate::user::supplied_fs) fn owner(&self) -> (u32, u32) {
        self.owner
    }

    pub(in crate::user::supplied_fs) fn xattrs(
        &self,
        need: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<&std::sync::Arc<super::Xattrs>, Error> {
        if ids.0 != 0 && !permitted(self.mode(), self.owner, need, ids, groups) {
            return Err(Error::AccessDenied);
        }
        Ok(&self.xattrs)
    }

    pub(in crate::user::supplied_fs) fn xattrs_changed(&self) {
        let mut values = self.values.lock().expect("workspace inode attributes");
        values.times.changed = Timestamp::now();
    }

    pub(in crate::user::supplied_fs) fn mode(&self) -> u32 {
        self.values.lock().expect("workspace inode attributes").mode
    }

    pub(in crate::user::supplied_fs) fn timestamps(&self) -> Timestamps {
        self.values
            .lock()
            .expect("workspace inode attributes")
            .times
    }

    fn owns(&self, uid: u32) -> bool {
        uid == 0 || uid == self.owner.0
    }

    pub(in crate::user::supplied_fs) fn set_mode(
        &self,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        if !self.owns(ids.0) {
            return Err(Error::PermissionDenied);
        }
        let mut values = self.values.lock().map_err(|_| Error::Io)?;
        let may_set_gid = ids.0 == 0 || ids.1 == self.owner.1 || groups.contains(&self.owner.1);
        let mask = if may_set_gid { 0o7777 } else { 0o5777 };
        values.mode = mode & mask;
        values.times.changed = Timestamp::now();
        Ok(())
    }

    pub(in crate::user::supplied_fs) fn set_times(
        &self,
        update: TimeUpdate,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        let requested = update.times;
        if requested == [SetTime::Omit; 2] {
            return Ok(());
        }
        let mut values = self.values.lock().map_err(|_| Error::Io)?;
        if !self.owns(ids.0) {
            if !update.allow_write {
                return Err(Error::PermissionDenied);
            }
            if !permitted(values.mode, self.owner, 2, ids, groups) {
                return Err(Error::AccessDenied);
            }
        }
        let now = Timestamp::now();
        values.times.accessed = requested[0].value(values.times.accessed, now);
        values.times.modified = requested[1].value(values.times.modified, now);
        if update.flavor == WorkspaceFlavor::Darwin && requested[1] != SetTime::Omit {
            values.times.created = values.times.created.min(values.times.modified);
        }
        values.times.changed = now;
        Ok(())
    }

    pub(super) fn modified(&self) {
        let mut values = self.values.lock().expect("workspace inode attributes");
        let now = Timestamp::now();
        values.times.modified = now;
        values.times.changed = now;
    }
}
