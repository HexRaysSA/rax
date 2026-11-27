//! Fixed registry leaves and named values read by installed process startup.
use super::*;

pub(super) const LEGACY_EXTENSION_FLAG: &str = "LoadAppInit_DLLs";

pub(super) const SYSTEM_SETUP_VALUES: &[&str] = &[SYSTEM_SETUP_IN_PROGRESS, "OOBEInProgress"];

pub(super) const POWERSHELL_WOW_KEY: &str =
    r"\Registry\Machine\Software\WOW6432Node\Microsoft\PowerShell";
const DOT_NET_FRAMEWORK_WOW_KEY: &str =
    r"\Registry\Machine\Software\WOW6432Node\Microsoft\.NETFramework";
#[cfg(test)]
const DOT_NET_POLICY_WOW_KEY: &str =
    r"\Registry\Machine\Software\WOW6432Node\Microsoft\.NETFramework\Policy";
#[cfg(test)]
const DOT_NET_POLICY_V4_WOW_KEY: &str =
    r"\Registry\Machine\Software\WOW6432Node\Microsoft\.NETFramework\Policy\v4.0";

#[path = "process_config/winsock_catalog.rs"]
pub(super) mod winsock_catalog;
use winsock_catalog::Catalog;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProcessConfigKey {
    Rpc,
    RpcPolicy,
    ActiveComputerName,
    TcpipParameters,
    DnsClientParameters,
    DnsClientPolicy,
    DnsClientSystemPolicy,
    WinsockParameters,
    WinsockAppIdCatalog,
    WinsockProtocolCatalog,
    WinsockNamespaceCatalog,
    Ccg,
    DisabledLegacyExtensions,
    MachineAppCompatFlags,
    OsDataAppCompatFlags,
    PowerShell,
    PowerShellV1,
    PowerShellV3,
    PowerShellEngineV1,
    PowerShellEngineV3,
    MiniNt,
    DotNetPolicy,
    DotNetPolicyV4,
    DotNetPolicyUpgrades,
    DotNetPolicyStandards,
    DotNetStandardCli2002,
    DotNetStandardCli2005,
    DotNetStandardV1,
    DotNetFramework,
}

impl ProcessConfigKey {
    pub(super) const ALL: [Self; 28] = [
        Self::Rpc,
        Self::RpcPolicy,
        Self::ActiveComputerName,
        Self::TcpipParameters,
        Self::DnsClientParameters,
        Self::DnsClientPolicy,
        Self::DnsClientSystemPolicy,
        // Capture the fixed children before linking the Parameters handle.
        Self::WinsockAppIdCatalog,
        Self::WinsockProtocolCatalog,
        Self::WinsockNamespaceCatalog,
        Self::WinsockParameters,
        Self::Ccg,
        Self::MachineAppCompatFlags,
        Self::OsDataAppCompatFlags,
        Self::PowerShellEngineV1,
        Self::PowerShellEngineV3,
        Self::PowerShellV1,
        Self::PowerShellV3,
        Self::PowerShell,
        Self::MiniNt,
        Self::DotNetPolicyV4,
        Self::DotNetPolicyUpgrades,
        Self::DotNetStandardCli2002,
        Self::DotNetStandardCli2005,
        Self::DotNetStandardV1,
        Self::DotNetPolicyStandards,
        Self::DotNetPolicy,
        Self::DotNetFramework,
    ];

    pub(super) fn path(self) -> &'static str {
        match self {
            Self::Rpc => r"\Registry\Machine\Software\Microsoft\Rpc",
            Self::RpcPolicy => r"\Registry\Machine\Software\Policies\Microsoft\Windows NT\Rpc",
            Self::ActiveComputerName => {
                r"\Registry\Machine\System\CurrentControlSet\Control\ComputerName\ActiveComputerName"
            }
            Self::TcpipParameters => {
                r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters"
            }
            Self::DnsClientParameters => {
                r"\Registry\Machine\System\CurrentControlSet\Services\Dnscache\Parameters"
            }
            Self::DnsClientPolicy => {
                r"\Registry\Machine\Software\Policies\Microsoft\Windows NT\DNSClient"
            }
            Self::DnsClientSystemPolicy => {
                r"\Registry\Machine\Software\Policies\Microsoft\System\DNSClient"
            }
            Self::WinsockParameters => {
                r"\Registry\Machine\System\CurrentControlSet\Services\WinSock2\Parameters"
            }
            Self::WinsockAppIdCatalog => {
                r"\Registry\Machine\System\CurrentControlSet\Services\WinSock2\Parameters\AppId_Catalog"
            }
            Self::WinsockProtocolCatalog => {
                r"\Registry\Machine\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9"
            }
            Self::WinsockNamespaceCatalog => {
                r"\Registry\Machine\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5"
            }
            Self::Ccg => r"\Registry\Machine\System\CurrentControlSet\Services\CCG",
            Self::DisabledLegacyExtensions => {
                r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            }
            Self::MachineAppCompatFlags => {
                r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
            }
            Self::OsDataAppCompatFlags => {
                r"\Registry\Machine\OSDATA\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
            }
            Self::PowerShell => r"\Registry\Machine\Software\Microsoft\PowerShell",
            Self::PowerShellV1 => r"\Registry\Machine\Software\Microsoft\PowerShell\1",
            Self::PowerShellV3 => r"\Registry\Machine\Software\Microsoft\PowerShell\3",
            Self::PowerShellEngineV1 => {
                r"\Registry\Machine\Software\Microsoft\PowerShell\1\PowerShellEngine"
            }
            Self::PowerShellEngineV3 => {
                r"\Registry\Machine\Software\Microsoft\PowerShell\3\PowerShellEngine"
            }
            Self::MiniNt => r"\Registry\Machine\System\CurrentControlSet\Control\MiniNT",
            Self::DotNetPolicy => r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy",
            Self::DotNetPolicyV4 => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\v4.0"
            }
            Self::DotNetPolicyUpgrades => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\Upgrades"
            }
            Self::DotNetPolicyStandards => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\standards"
            }
            Self::DotNetStandardCli2002 => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\standards\Standard CLI 2002"
            }
            Self::DotNetStandardCli2005 => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\standards\Standard CLI 2005"
            }
            Self::DotNetStandardV1 => {
                r"\Registry\Machine\Software\Microsoft\.NETFramework\Policy\standards\v1.0.0"
            }
            Self::DotNetFramework => r"\Registry\Machine\Software\Microsoft\.NETFramework",
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
            Self::TcpipParameters => &["Hostname", "NV Hostname", "Domain", "NV Domain"],
            Self::DnsClientPolicy => &["PrimaryDomainName"],
            Self::WinsockParameters => &[
                "Current_NameSpace_Catalog",
                "Current_Protocol_Catalog",
                "NameSpace_Callout",
                "WinSock_Registry_Version",
                "Ws2_32NumHandleBuckets",
            ],
            Self::DnsClientParameters
            | Self::DnsClientSystemPolicy
            | Self::WinsockAppIdCatalog
            | Self::Ccg
            | Self::OsDataAppCompatFlags
            | Self::PowerShell
            | Self::MiniNt
            | Self::DotNetPolicy
            | Self::DotNetPolicyStandards => &[],
            Self::DotNetPolicyV4 => &["30319"],
            Self::DotNetPolicyUpgrades => &["4.0.30319"],
            Self::DotNetStandardCli2002 | Self::DotNetStandardCli2005 | Self::DotNetStandardV1 => {
                &["v4.0.30319"]
            }
            Self::DotNetFramework => &["InstallRoot", "InstallRootARM64"],
            Self::WinsockProtocolCatalog => Catalog::Protocol.header_values(),
            Self::WinsockNamespaceCatalog => Catalog::Namespace.header_values(),
            Self::DisabledLegacyExtensions => &[LEGACY_EXTENSION_FLAG],
            Self::MachineAppCompatFlags => &["LogFlags"],
            Self::PowerShellV1 => &["Install"],
            Self::PowerShellV3 => &[
                "ConsoleHostShortcutTarget",
                "ConsoleHostShortcutTargetX86",
                "Install",
            ],
            Self::PowerShellEngineV1 | Self::PowerShellEngineV3 => &[
                "ApplicationBase",
                "ConsoleHostAssemblyName",
                "ConsoleHostModuleName",
                "NetFrameworkV4IsInstalled",
                "PowerShellVersion",
                "PSCompatibleVersion",
                "PSPluginWkrModuleName",
                "RuntimeVersion",
            ],
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Rpc => "RPC configuration",
            Self::RpcPolicy => "RPC policy",
            Self::ActiveComputerName => "active computer name",
            Self::TcpipParameters => "TCP/IP host and domain configuration",
            Self::DnsClientParameters => "DNS Client parameters",
            Self::DnsClientPolicy => "DNS Client policy",
            Self::DnsClientSystemPolicy => "DNS Client system policy",
            Self::WinsockParameters => "Winsock catalog selection",
            Self::WinsockAppIdCatalog => "Winsock application-ID catalog",
            Self::WinsockProtocolCatalog => Catalog::Protocol.label(),
            Self::WinsockNamespaceCatalog => Catalog::Namespace.label(),
            Self::Ccg => "CCG service",
            Self::DisabledLegacyExtensions => "disabled legacy extensions",
            Self::MachineAppCompatFlags => "machine AppCompatFlags",
            Self::OsDataAppCompatFlags => "OSDATA AppCompatFlags",
            Self::PowerShell => "Windows PowerShell installation",
            Self::PowerShellV1 => "Windows PowerShell version 1 registration",
            Self::PowerShellV3 => "Windows PowerShell version 3 registration",
            Self::PowerShellEngineV1 => "Windows PowerShell version 1 engine registration",
            Self::PowerShellEngineV3 => "Windows PowerShell version 3 engine registration",
            Self::MiniNt => "Windows PE installation marker",
            Self::DotNetPolicy => ".NET Framework runtime policy",
            Self::DotNetPolicyV4 => ".NET Framework v4.0 runtime policy",
            Self::DotNetPolicyUpgrades => ".NET Framework upgrade policy",
            Self::DotNetPolicyStandards => ".NET Framework standards policy",
            Self::DotNetStandardCli2002 => ".NET Framework Standard CLI 2002 policy",
            Self::DotNetStandardCli2005 => ".NET Framework Standard CLI 2005 policy",
            Self::DotNetStandardV1 => ".NET Framework v1.0.0 standards policy",
            Self::DotNetFramework => ".NET Framework installation",
        }
    }

    pub(super) fn accepts_values(self, view: RegistryView, values: &[Value]) -> bool {
        match self {
            Self::DisabledLegacyExtensions => {
                view == RegistryView::Native64
                    && matches!(values, [value] if value.kind == 4 && value.data == [0; 4])
            }
            Self::MachineAppCompatFlags | Self::OsDataAppCompatFlags => {
                view == RegistryView::Native64
            }
            _ => true,
        }
    }

    pub(super) fn captures_child_membership(self) -> bool {
        matches!(
            self,
            Self::WinsockAppIdCatalog
                | Self::PowerShell
                | Self::DotNetPolicy
                | Self::DotNetPolicyStandards
        )
    }

    pub(super) fn admits_descendant_routes(self) -> bool {
        matches!(self, Self::WinsockAppIdCatalog | Self::PowerShell)
            || self.winsock_catalog().is_some()
    }

    #[cfg(target_os = "windows")]
    pub(super) fn uses_dot_net_framework_view(self) -> bool {
        self.path().starts_with(Self::DotNetFramework.path())
    }

    #[cfg(target_os = "windows")]
    pub(super) fn captures_cached_record(self) -> bool {
        self == Self::DotNetPolicy || self.preserves_value_order()
    }

    pub(super) fn preserves_value_order(self) -> bool {
        matches!(
            self,
            Self::DotNetPolicyV4
                | Self::DotNetPolicyUpgrades
                | Self::DotNetPolicyStandards
                | Self::DotNetStandardCli2002
                | Self::DotNetStandardCli2005
                | Self::DotNetStandardV1
        )
    }

    pub(super) fn winsock_catalog(self) -> Option<Catalog> {
        match self {
            Self::WinsockProtocolCatalog => Some(Catalog::Protocol),
            Self::WinsockNamespaceCatalog => Some(Catalog::Namespace),
            _ => None,
        }
    }

    pub(super) fn link_children(
        self,
        registry: &Registry,
        view: RegistryView,
        parent: &mut Key,
    ) -> io::Result<()> {
        let children: &[Self] = match self {
            Self::WinsockParameters => &[
                Self::WinsockAppIdCatalog,
                Self::WinsockProtocolCatalog,
                Self::WinsockNamespaceCatalog,
            ],
            Self::PowerShell => &[Self::PowerShellV1, Self::PowerShellV3],
            Self::PowerShellV1 => &[Self::PowerShellEngineV1],
            Self::PowerShellV3 => &[Self::PowerShellEngineV3],
            Self::DotNetPolicy => &[
                Self::DotNetPolicyV4,
                Self::DotNetPolicyUpgrades,
                Self::DotNetPolicyStandards,
            ],
            Self::DotNetPolicyStandards => &[
                Self::DotNetStandardCli2002,
                Self::DotNetStandardCli2005,
                Self::DotNetStandardV1,
            ],
            Self::DotNetFramework => &[Self::DotNetPolicy],
            _ => return Ok(()),
        };
        for &child in children {
            let selection = (ViewRoot::ProcessConfig(child), view);
            let Some(selected) = registry.views.roots.get(&selection) else {
                continue;
            };
            let name = child
                .path()
                .rsplit('\\')
                .next()
                .expect("fixed process configuration child name")
                .encode_utf16()
                .collect::<Vec<_>>();
            let route = match selected {
                Some(key) => {
                    if key.open_denial.is_none() {
                        let physical = tree::child_path(&parent.path, &name)?;
                        if parent.children == 0
                            || parent.fold(&physical) != parent.fold(&key.path)
                            || parent.enumeration.as_ref().is_some_and(|entries| {
                                let selected_name = parent.fold(&name);
                                !entries
                                    .iter()
                                    .any(|entry| parent.fold(&entry.name) == selected_name)
                            })
                        {
                            return Err(invalid(&format!(
                                "{} differs from its parent",
                                child.label()
                            )));
                        }
                    }
                    Lookup::Present(key.clone())
                }
                None if registry.views.missing_paths.contains(&selection) => Lookup::MissingPath,
                None => Lookup::Missing,
            };
            parent.selected_paths.insert(parent.fold(&name), route);
        }
        Ok(())
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
        if view == RegistryView::Wow32
            && let Some(suffix) = self.path().strip_prefix(Self::PowerShell.path())
            && same(&format!("{POWERSHELL_WOW_KEY}{suffix}"))
        {
            return Ok(());
        }
        if view == RegistryView::Wow32
            && let Some(suffix) = self.path().strip_prefix(Self::DotNetFramework.path())
            && same(&format!("{DOT_NET_FRAMEWORK_WOW_KEY}{suffix}"))
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

impl Key {
    pub(super) fn uses_winsock_catalog_membership(&self) -> bool {
        self.logical_path.as_deref().is_some_and(|path| {
            path.iter()
                .copied()
                .eq(ProcessConfigKey::WinsockAppIdCatalog.path().encode_utf16())
        })
    }

    pub(super) fn knows_winsock_child_absent(&self, folded: &[u16]) -> bool {
        self.uses_winsock_catalog_membership()
            && self.enumeration.as_ref().is_some_and(|entries| {
                !entries.iter().any(|child| {
                    child
                        .name
                        .iter()
                        .map(|&u| self.upcase[usize::from(u)])
                        .eq(folded.iter().copied())
                })
            })
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
