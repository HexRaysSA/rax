//! Fixed registry leaves and named values read by installed process startup.
use super::*;

pub(super) const LEGACY_EXTENSION_FLAG: &str = "LoadAppInit_DLLs";

pub(super) const SYSTEM_SETUP_VALUES: &[&str] = &[SYSTEM_SETUP_IN_PROGRESS, "OOBEInProgress"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProcessConfigKey {
    Rpc,
    RpcPolicy,
    ActiveComputerName,
    Ccg,
    DisabledLegacyExtensions,
    MachineAppCompatFlags,
}

impl ProcessConfigKey {
    pub(super) const ALL: [Self; 5] = [
        Self::Rpc,
        Self::RpcPolicy,
        Self::ActiveComputerName,
        Self::Ccg,
        Self::MachineAppCompatFlags,
    ];

    pub(super) fn path(self) -> &'static str {
        match self {
            Self::Rpc => r"\Registry\Machine\Software\Microsoft\Rpc",
            Self::RpcPolicy => r"\Registry\Machine\Software\Policies\Microsoft\Windows NT\Rpc",
            Self::ActiveComputerName => {
                r"\Registry\Machine\System\CurrentControlSet\Control\ComputerName\ActiveComputerName"
            }
            Self::Ccg => r"\Registry\Machine\System\CurrentControlSet\Services\CCG",
            Self::DisabledLegacyExtensions => {
                r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            }
            Self::MachineAppCompatFlags => {
                r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
            }
        }
    }

    pub(super) fn values(self) -> &'static [&'static str] {
        match self {
            Self::Rpc => &["MaxRpcSize", "IdleTimerWindow"],
            Self::RpcPolicy => &[
                "StateInformation",
                "ExtErrorInformation",
                "IgnoreDelegationFailure",
                "RestrictRemoteClients",
                "EnableAuthEpResolution",
                "MaxNonPagedPoolPerConnection",
                "EnableTcpPortScaling",
            ],
            Self::ActiveComputerName => &["ComputerName"],
            Self::Ccg => &[],
            Self::DisabledLegacyExtensions => &[LEGACY_EXTENSION_FLAG],
            Self::MachineAppCompatFlags => &["LogFlags"],
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Rpc => "RPC configuration",
            Self::RpcPolicy => "RPC policy",
            Self::ActiveComputerName => "active computer name",
            Self::Ccg => "CCG service",
            Self::DisabledLegacyExtensions => "disabled legacy extensions",
            Self::MachineAppCompatFlags => "machine AppCompatFlags",
        }
    }

    pub(super) fn accepts_values(self, view: RegistryView, values: &[Value]) -> bool {
        match self {
            Self::DisabledLegacyExtensions => {
                view == RegistryView::Native64
                    && matches!(values, [value] if value.kind == 4 && value.data == [0; 4])
            }
            Self::MachineAppCompatFlags => view == RegistryView::Native64,
            _ => true,
        }
    }

    pub(super) fn check_name(
        self,
        registry: &Registry,
        view: RegistryView,
        canonical: &[u16],
    ) -> io::Result<()> {
        let same = |expected: &str| {
            let expected = expected.encode_utf16();
            canonical.len() == expected.clone().count()
                && canonical.iter().zip(expected).all(|(&actual, desired)| {
                    registry.upcase[usize::from(actual)] == registry.upcase[usize::from(desired)]
                })
        };
        if same(self.path())
            || self == Self::Rpc
                && view == RegistryView::Wow32
                && same(r"\Registry\Machine\Software\WOW6432Node\Microsoft\Rpc")
        {
            return Ok(());
        }
        const CURRENT: &str = r"\Registry\Machine\System\CurrentControlSet";
        const CONTROL_SET: &str = r"\Registry\Machine\System\ControlSet";
        if let Some(suffix) = self.path().strip_prefix(CURRENT) {
            let offset = CONTROL_SET.len();
            if let Some(digits) = canonical.get(offset..offset + 3) {
                if digits.iter().all(|digit| (48..=57).contains(digit)) {
                    let number = String::from_utf16_lossy(digits);
                    if same(&format!("{CONTROL_SET}{number}{suffix}")) {
                        return Ok(());
                    }
                }
            }
        }
        Err(invalid(&format!(
            "{} canonical name is outside fixed selection",
            self.label()
        )))
    }
}

pub(super) fn covered_values(path: &[u16]) -> Option<&'static [&'static str]> {
    if path.iter().copied().eq(SYSTEM_SETUP_KEY.encode_utf16()) {
        return Some(SYSTEM_SETUP_VALUES);
    }
    ProcessConfigKey::ALL
        .into_iter()
        .chain([ProcessConfigKey::DisabledLegacyExtensions])
        .find(|root| path.iter().copied().eq(root.path().encode_utf16()))
        .map(ProcessConfigKey::values)
}

pub(super) fn covers_name(names: &[&str], upcase: &[u16], name: &[u16]) -> bool {
    names.iter().any(|name_to_match| {
        let expected = name_to_match.encode_utf16();
        name.len() == expected.clone().count()
            && name.iter().zip(expected).all(|(&observed, selected)| {
                upcase[usize::from(observed)] == upcase[usize::from(selected)]
            })
    })
}

#[cfg(test)]
#[path = "process_config_tests.rs"]
mod tests;
