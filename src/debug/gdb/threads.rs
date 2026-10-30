//! RSP thread designators and ordered per-thread resume actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadId {
    Any,
    All,
    Id(usize),
}
impl ThreadId {
    pub fn parse(raw: &str) -> Option<Self> {
        if raw == "-1" {
            return Some(Self::All);
        }
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        match usize::from_str_radix(raw, 16).ok()? {
            0 => Some(Self::Any),
            id => Some(Self::Id(id)),
        }
    }
    pub fn index(self, count: usize, current: usize) -> Option<usize> {
        match self {
            Self::Id(id) => id.checked_sub(1).filter(|&n| n < count),
            Self::Any | Self::All => (current < count).then_some(current),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    Continue,
    Step,
    Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    pub action: ResumeAction,
    pub thread: ThreadId,
}
/// Parse every action before changing CPU state. Bare-metal signal delivery is
/// unrepresented: a nonzero signal is an error rather than an ignored success.
pub fn parse_resume(raw: &str) -> Option<Vec<Resume>> {
    let mut actions = Vec::new();
    for item in raw.split(';') {
        let (action, thread) = match item.split_once(':') {
            Some((a, t)) => (a, ThreadId::parse(t)?),
            None => (item, ThreadId::All),
        };
        let action = match action {
            "c" | "C00" => ResumeAction::Continue,
            "s" | "S00" => ResumeAction::Step,
            "t" => ResumeAction::Stop,
            _ => return None,
        };
        actions.push(Resume { action, thread });
    }
    (!actions.is_empty()).then_some(actions)
}
/// GNU RSP applies the first matching action; unmatched CPUs remain stopped.
/// O(C*A) time and O(C) storage for C CPUs and A packet actions.
pub fn resume_plan(actions: &[Resume], count: usize, current: usize) -> Option<Vec<ResumeAction>> {
    if actions.is_empty() || current >= count {
        return None;
    }
    if actions
        .iter()
        .any(|a| a.thread.index(count, current).is_none())
    {
        return None;
    }
    Some(
        (0..count)
            .map(|index| {
                actions
                    .iter()
                    .find(|a| {
                        a.thread == ThreadId::All || a.thread.index(count, current) == Some(index)
                    })
                    .map_or(ResumeAction::Stop, |a| a.action)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_action_validation_precedes_any_plan() {
        for raw in ["", "s:2;c:99", "s:2;", "S05:2", "s:p1.2", "s:2:c"] {
            assert!(
                parse_resume(raw)
                    .and_then(|a| resume_plan(&a, 4, 0))
                    .is_none(),
                "{raw}"
            );
        }
    }
    #[test]
    fn first_matching_action_and_any_thread_are_exact() {
        let plan = resume_plan(&parse_resume("c;s:2").unwrap(), 4, 2).unwrap();
        assert_eq!(plan, vec![ResumeAction::Continue; 4]);
        let plan = resume_plan(&parse_resume("s:0").unwrap(), 4, 2).unwrap();
        assert_eq!(
            plan,
            vec![
                ResumeAction::Stop,
                ResumeAction::Stop,
                ResumeAction::Step,
                ResumeAction::Stop
            ]
        );
        assert_eq!(ThreadId::parse("-1"), Some(ThreadId::All));
        assert!(ThreadId::parse("+1").is_none());
        assert!(ThreadId::parse("ffffffffffffffffffffffffffffffff").is_none());
    }
}
