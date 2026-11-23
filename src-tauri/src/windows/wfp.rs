//! Tunnel Guard's own WFP sublayer. A terminating block covers each address
//! family and direction, with higher-weight exceptions inside the same layer.
//! The exceptions are soft permits so Windows Firewall can still block them.
//!
//! Two filter sets exist. `V1` is the original layout and is only kept so an
//! installed policy can be recognised, upgraded in one transaction and, if the
//! upgrade fails its checks, restored. `V2` is what new installs get:
//! - the sublayer has the top weight, so no third-party sublayer outranks it
//!   (equal weights are evaluated in an unspecified order and are reported);
//! - forwarded traffic (WSL2, Hyper-V and Docker NAT, connection sharing) is
//!   blocked unless it enters or leaves through the tunnel;
//! - Mihomo is only permitted when it runs elevated or as SYSTEM, so a copy
//!   started by the user from the same path cannot bypass the tunnel;
//! - DHCPv6 is permitted for the Windows service host like DHCPv4.

pub(crate) mod group_network;

use super::wide;
use crate::{settings, status::GuardState, Result};
use std::{
    env,
    ffi::{c_void, OsStr},
    io,
    path::{Path, PathBuf},
    ptr::{null, null_mut, NonNull},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
        },
        NetworkManagement::{
            IpHelper::ConvertInterfaceAliasToLuid, Ndis::NET_LUID_LH, WindowsFilteringPlatform::*,
        },
        Security::{
            AccessCheck, Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            DuplicateToken, GetSecurityDescriptorLength, SecurityIdentification, GENERIC_MAPPING,
            PRIVILEGE_SET, PSECURITY_DESCRIPTOR, TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        System::{
            Rpc::RPC_C_AUTHN_WINNT,
            Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    },
};

/// Environment variables through which the elevated PowerShell worker hands
/// the exact Mihomo path and adapter it has just checked to this process, so
/// a settings file changed in the meantime cannot alter the permitted program.
pub(super) const CORE_ENV: &str = "TUNNEL_GUARD_WFP_CORE";
pub(super) const ADAPTER_ENV: &str = "TUNNEL_GUARD_WFP_ADAPTER";
/// The running Mihomo that owns the verified controller.
pub(super) const CORE_PID_ENV: &str = "TUNNEL_GUARD_WFP_CORE_PID";

/// Matches tokens with the Administrators group enabled (elevated) or SYSTEM.
/// A filtered UAC token carries Administrators as deny-only and does not match.
const ELEVATED_USERS: &str = "O:SYG:SYD:(A;;CC;;;BA)(A;;CC;;;SY)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    V1,
    V2,
}

impl Policy {
    fn sublayer(self) -> GUID {
        GUID::from_u128(match self {
            Self::V1 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32010,
            Self::V2 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32020,
        })
    }

    fn verified(self) -> GUID {
        GUID::from_u128(match self {
            Self::V1 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32011,
            Self::V2 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32021,
        })
    }

    fn filter_base(self) -> u128 {
        match self {
            Self::V1 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32100,
            Self::V2 => 0x64fc98a5_0706_4a82_a8ea_ffbf83e32200,
        }
    }

    fn weight(self) -> u16 {
        match self {
            Self::V1 => 0xe000,
            Self::V2 => u16::MAX,
        }
    }

    fn layers(self) -> &'static [GUID] {
        const ALE: [GUID; 4] = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ];
        const ALL: [GUID; 6] = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            FWPM_LAYER_IPFORWARD_V4,
            FWPM_LAYER_IPFORWARD_V6,
        ];
        match self {
            Self::V1 => &ALE,
            Self::V2 => &ALL,
        }
    }
}

const POLICIES: [Policy; 2] = [Policy::V1, Policy::V2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
    DefaultBlock,
    Loopback,
    Tunnel,
    Mihomo,
    Dhcp,
    ForwardIn,
    ForwardOut,
    BootBlock,
}

#[derive(Clone, Copy)]
struct Rule {
    policy: Policy,
    key: GUID,
    layer: GUID,
    kind: RuleKind,
    outbound: bool,
    ipv4: bool,
}

impl Rule {
    fn flags(self) -> u32 {
        if self.kind == RuleKind::BootBlock {
            FWPM_FILTER_FLAG_BOOTTIME
        } else {
            FWPM_FILTER_FLAG_PERSISTENT
        }
    }

    fn action(self) -> u32 {
        match self.kind {
            RuleKind::DefaultBlock | RuleKind::BootBlock => FWP_ACTION_BLOCK,
            _ => FWP_ACTION_PERMIT,
        }
    }

    fn weight(self) -> u8 {
        if self.action() == FWP_ACTION_BLOCK {
            0
        } else {
            15
        }
    }

    fn condition_count(self) -> u32 {
        match self.kind {
            RuleKind::DefaultBlock => 0,
            RuleKind::Dhcp => 4,
            RuleKind::Mihomo if self.policy == Policy::V2 => 2,
            _ => 1,
        }
    }

    fn interface_condition(self) -> Option<GUID> {
        match self.kind {
            RuleKind::Tunnel if self.outbound => Some(FWPM_CONDITION_IP_NEXTHOP_INTERFACE),
            // At the forwarding layer the local interface is the arrival one.
            RuleKind::Tunnel | RuleKind::ForwardIn => Some(FWPM_CONDITION_IP_LOCAL_INTERFACE),
            RuleKind::ForwardOut => Some(FWPM_CONDITION_IP_FORWARD_INTERFACE),
            _ => None,
        }
    }

    fn dhcp_ports(self) -> (u16, u16) {
        if self.ipv4 {
            (68, 67)
        } else {
            (546, 547)
        }
    }
}

fn rules(policy: Policy) -> impl Iterator<Item = Rule> {
    use RuleKind::{
        BootBlock, DefaultBlock, Dhcp, ForwardIn, ForwardOut, Loopback, Mihomo, Tunnel,
    };
    let base = policy.filter_base();
    let key = move |offset: usize| GUID::from_u128(base + offset as u128);
    let ale = [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, true),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, false),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, true),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false, false),
    ]
    .into_iter()
    .enumerate()
    .flat_map(move |(group, (layer, outbound, ipv4))| {
        [DefaultBlock, Loopback, Tunnel, Mihomo, Dhcp]
            .into_iter()
            .enumerate()
            .filter(move |(_, kind)| *kind != Dhcp || ipv4 || policy == Policy::V2)
            .map(move |(index, kind)| Rule {
                policy,
                key: key(group * 16 + index),
                layer,
                kind,
                outbound,
                ipv4,
            })
    });
    // Routed traffic never reaches the ALE layers. Either side of a forwarded
    // packet being the tunnel covers both directions of a NAT session.
    let forward = [
        (FWPM_LAYER_IPFORWARD_V4, true),
        (FWPM_LAYER_IPFORWARD_V6, false),
    ]
    .into_iter()
    .enumerate()
    .filter(move |_| policy == Policy::V2)
    .flat_map(move |(offset, (layer, ipv4))| {
        [DefaultBlock, ForwardIn, ForwardOut]
            .into_iter()
            .enumerate()
            .map(move |(index, kind)| Rule {
                policy,
                key: key((4 + offset) * 16 + index),
                layer,
                kind,
                outbound: true,
                ipv4,
            })
    });
    // Persistent ALE filters take over once BFE starts.
    let boot = [
        (FWPM_LAYER_OUTBOUND_IPPACKET_V4, true),
        (FWPM_LAYER_OUTBOUND_IPPACKET_V6, false),
    ]
    .into_iter()
    .enumerate()
    .map(move |(index, (layer, ipv4))| Rule {
        policy,
        key: key(0x80 + index),
        layer,
        kind: BootBlock,
        outbound: true,
        ipv4,
    });
    ale.chain(forward).chain(boot)
}

fn check(code: u32, operation: &str) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    Err(format!("WFP: {operation} (0x{code:08X})."))
}

fn same_guid(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

struct Engine(HANDLE);

impl Engine {
    fn open() -> Result<Self> {
        let mut handle = null_mut();
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: 5000,
            ..Default::default()
        };
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) },
            "открытие службы фильтрации",
        )?;
        Ok(Self(handle))
    }

    fn write(&self) -> Result<Transaction<'_>> {
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "начало транзакции",
        )?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }

    fn filter(&self, key: &GUID) -> Result<Option<Allocation<FWPM_FILTER0>>> {
        let mut value = null_mut();
        let code = unsafe { FwpmFilterGetByKey0(self.0, key, &mut value) };
        queried(code, FWP_E_FILTER_NOT_FOUND as u32, value, "чтение фильтра")
    }

    fn sublayer(&self, key: &GUID) -> Result<Option<Allocation<FWPM_SUBLAYER0>>> {
        let mut value = null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(self.0, key, &mut value) };
        queried(code, FWP_E_SUBLAYER_NOT_FOUND as u32, value, "чтение слоя")
    }

    /// Key and weight of every sublayer the caller may read.
    fn sublayers(&self) -> Result<Vec<(GUID, u16)>> {
        let mut handle = null_mut();
        check(
            unsafe { FwpmSubLayerCreateEnumHandle0(self.0, null(), &mut handle) },
            "перечисление слоёв",
        )?;
        let result = collect(
            |entries, count| unsafe { FwpmSubLayerEnum0(self.0, handle, BATCH, entries, count) },
            |layer: &FWPM_SUBLAYER0| Some((layer.subLayerKey, layer.weight)),
        );
        unsafe { FwpmSubLayerDestroyEnumHandle0(self.0, handle) };
        result
    }

    /// Sublayer, flags and action type of every filter in a layer.
    fn filters(&self, layer: GUID) -> Result<Vec<(GUID, u32, u32)>> {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut handle = null_mut();
        check(
            unsafe { FwpmFilterCreateEnumHandle0(self.0, &template, &mut handle) },
            "перечисление фильтров",
        )?;
        let result = collect(
            |entries, count| unsafe { FwpmFilterEnum0(self.0, handle, BATCH, entries, count) },
            |filter: &FWPM_FILTER0| Some((filter.subLayerKey, filter.flags, filter.action.r#type)),
        );
        unsafe { FwpmFilterDestroyEnumHandle0(self.0, handle) };
        result
    }
}

const BATCH: u32 = 256;

/// Drains a WFP enumeration, copying what `read` keeps out of each entry
/// before the batch is released.
fn collect<T, R>(
    mut next: impl FnMut(*mut *mut *mut T, *mut u32) -> u32,
    mut read: impl FnMut(&T) -> Option<R>,
) -> Result<Vec<R>> {
    let mut values = Vec::new();
    loop {
        let mut entries: *mut *mut T = null_mut();
        let mut count = 0u32;
        check(next(&mut entries, &mut count), "перечисление объектов")?;
        if !entries.is_null() {
            let list = unsafe { std::slice::from_raw_parts(entries, count as usize) };
            values.extend(
                list.iter()
                    .filter_map(|entry| unsafe { entry.as_ref() })
                    .filter_map(&mut read),
            );
            let mut ptr = entries.cast::<c_void>();
            unsafe { FwpmFreeMemory0(&mut ptr) };
        }
        if count < BATCH {
            return Ok(values);
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}

struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl Transaction<'_> {
    fn commit(mut self) -> Result<()> {
        check(
            unsafe { FwpmTransactionCommit0(self.engine.0) },
            "запись фильтров",
        )?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe { FwpmTransactionAbort0(self.engine.0) };
        }
    }
}

struct Allocation<T>(NonNull<T>);

impl<T> Allocation<T> {
    fn new(ptr: *mut T) -> Result<Self> {
        NonNull::new(ptr)
            .map(Self)
            .ok_or_else(|| "WFP вернула пустой объект.".into())
    }

    fn get(&self) -> &T {
        unsafe { self.0.as_ref() }
    }
}

impl<T> Drop for Allocation<T> {
    fn drop(&mut self) {
        let mut ptr = self.0.as_ptr().cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut ptr) };
    }
}

fn queried<T>(
    code: u32,
    missing: u32,
    ptr: *mut T,
    operation: &str,
) -> Result<Option<Allocation<T>>> {
    if code == missing {
        return Ok(None);
    }
    check(code, operation)?;
    Ok(Some(Allocation::new(ptr)?))
}

struct ObjectSecurity(PSECURITY_DESCRIPTOR);

impl ObjectSecurity {
    fn new() -> Result<Self> {
        // Read-only status is available without elevating the UI. Only
        // Administrators and SYSTEM can change these objects.
        Self::from_sddl("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)")
    }

    fn from_sddl(sddl: &str) -> Result<Self> {
        let sddl = wide(OsStr::new(sddl));
        let mut sd = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(Self(sd))
    }

    /// The self-relative descriptor as a WFP condition value.
    fn blob(&self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: unsafe { GetSecurityDescriptorLength(self.0) },
            data: self.0.cast(),
        }
    }
}

impl Drop for ObjectSecurity {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn interface_luid(alias: &str) -> Result<u64> {
    let mut luid = NET_LUID_LH::default();
    let name = wide(OsStr::new(alias));
    check(
        unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) },
        "поиск адаптера TUN",
    )?;
    Ok(unsafe { luid.Value })
}

fn application_id(path: &Path) -> Result<Allocation<FWP_BYTE_BLOB>> {
    let path = wide(path.as_os_str());
    let mut id = null_mut();
    check(
        unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut id) },
        "определение пути Mihomo",
    )?;
    Allocation::new(id)
}

fn condition(
    field: GUID,
    comparison: FWP_MATCH_TYPE,
    data_type: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: comparison,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: data_type,
            Anonymous: value,
        },
    }
}

/// Values the conditions point into; they must outlive each `FwpmFilterAdd0`.
struct Values<'a> {
    luid: &'a mut u64,
    mihomo: *mut FWP_BYTE_BLOB,
    dhcp: *mut FWP_BYTE_BLOB,
    elevated: *mut FWP_BYTE_BLOB,
}

fn conditions(rule: Rule, values: &mut Values) -> Vec<FWPM_FILTER_CONDITION0> {
    use RuleKind::*;
    let app = |blob| {
        condition(
            FWPM_CONDITION_ALE_APP_ID,
            FWP_MATCH_EQUAL,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 { byteBlob: blob },
        )
    };
    match rule.kind {
        DefaultBlock => vec![],
        Loopback | BootBlock => vec![condition(
            FWPM_CONDITION_FLAGS,
            if rule.kind == Loopback {
                FWP_MATCH_FLAGS_ALL_SET
            } else {
                FWP_MATCH_FLAGS_NONE_SET
            },
            FWP_UINT32,
            FWP_CONDITION_VALUE0_0 {
                uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
            },
        )],
        Tunnel | ForwardIn | ForwardOut => rule
            .interface_condition()
            .into_iter()
            .map(|field| {
                condition(
                    field,
                    FWP_MATCH_EQUAL,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 {
                        uint64: &mut *values.luid,
                    },
                )
            })
            .collect(),
        Mihomo if rule.policy == Policy::V1 => vec![app(values.mihomo)],
        Mihomo => vec![
            app(values.mihomo),
            condition(
                FWPM_CONDITION_ALE_USER_ID,
                FWP_MATCH_EQUAL,
                FWP_SECURITY_DESCRIPTOR_TYPE,
                FWP_CONDITION_VALUE0_0 {
                    sd: values.elevated,
                },
            ),
        ],
        Dhcp => {
            let (local, remote) = rule.dhcp_ports();
            vec![
                condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_MATCH_EQUAL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 { uint8: 17 },
                ),
                condition(
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    FWP_MATCH_EQUAL,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: local },
                ),
                condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_EQUAL,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: remote },
                ),
                // DHCP can discover a server via broadcast/multicast or renew
                // with a unicast server. Limit these ports to the service host.
                app(values.dhcp),
            ]
        }
    }
}

fn add_sublayer(
    engine: &Engine,
    security: &ObjectSecurity,
    policy: Policy,
    key: GUID,
    name: &str,
) -> Result<()> {
    let mut name = wide(OsStr::new(name));
    let layer = FWPM_SUBLAYER0 {
        subLayerKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        weight: policy.weight(),
        ..Default::default()
    };
    check(
        unsafe { FwpmSubLayerAdd0(engine.0, &layer, security.0) },
        "создание слоя",
    )
}

/// Everything a filter set is built from.
struct Connection {
    luid: u64,
    mihomo: Allocation<FWP_BYTE_BLOB>,
    dhcp: Allocation<FWP_BYTE_BLOB>,
}

fn stage_filters(
    engine: &Engine,
    security: &ObjectSecurity,
    policy: Policy,
    connection: &Connection,
) -> Result<()> {
    let elevated_users = ObjectSecurity::from_sddl(ELEVATED_USERS)?;
    let mut elevated = elevated_users.blob();
    let mut luid = connection.luid;
    add_sublayer(engine, security, policy, policy.sublayer(), "Tunnel Guard")?;
    for rule in rules(policy) {
        let mut values = Values {
            luid: &mut luid,
            mihomo: connection.mihomo.0.as_ptr(),
            dhcp: connection.dhcp.0.as_ptr(),
            elevated: &mut elevated,
        };
        let mut conditions = conditions(rule, &mut values);
        let mut name = wide(OsStr::new("Tunnel Guard"));
        let filter = FWPM_FILTER0 {
            filterKey: rule.key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: rule.flags(),
            layerKey: rule.layer,
            subLayerKey: policy.sublayer(),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: rule.weight(),
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: rule.action(),
                ..Default::default()
            },
            ..Default::default()
        };
        check(
            unsafe { FwpmFilterAdd0(engine.0, &filter, security.0, null_mut()) },
            &format!("создание фильтра {:?}", rule.kind),
        )?;
    }
    Ok(())
}

fn valid_filter(rule: Rule, filter: &FWPM_FILTER0) -> bool {
    filter.flags
        & (FWPM_FILTER_FLAG_PERSISTENT
            | FWPM_FILTER_FLAG_BOOTTIME
            | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT)
        == rule.flags()
        && (rule.kind == RuleKind::BootBlock || filter.flags & FWPM_FILTER_FLAG_DISABLED == 0)
        && filter.providerKey.is_null()
        && same_guid(filter.layerKey, rule.layer)
        && same_guid(filter.subLayerKey, rule.policy.sublayer())
        && filter.action.r#type == rule.action()
        && filter.numFilterConditions == rule.condition_count()
        && filter.weight.r#type == FWP_UINT8
        && unsafe { filter.weight.Anonymous.uint8 == rule.weight() }
}

fn expected_interface(rule: Rule, filter: &FWPM_FILTER0, luid: u64) -> bool {
    let Some(field) = rule.interface_condition() else {
        return true;
    };
    if filter.numFilterConditions != 1 || filter.filterCondition.is_null() {
        return false;
    }
    let condition = unsafe { &*filter.filterCondition };
    same_guid(condition.fieldKey, field)
        && condition.matchType == FWP_MATCH_EQUAL
        && condition.conditionValue.r#type == FWP_UINT64
        && unsafe { condition.conditionValue.Anonymous.uint64.as_ref() == Some(&luid) }
}

struct Inspection {
    any: bool,
    complete: bool,
    verified: bool,
    tunnel_matches: bool,
}

impl Inspection {
    fn active(&self) -> bool {
        self.complete && self.verified
    }
}

fn inspect(engine: &Engine, policy: Policy, expected_luid: Option<u64>) -> Result<Inspection> {
    let layer = engine.sublayer(&policy.sublayer())?;
    let complete_layer = layer.as_ref().is_some_and(|layer| {
        layer.get().flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
            && layer.get().weight == policy.weight()
    });
    let marker = engine.sublayer(&policy.verified())?;
    let mut result = Inspection {
        any: layer.is_some() || marker.is_some(),
        complete: complete_layer,
        verified: marker
            .is_some_and(|marker| marker.get().flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0),
        tunnel_matches: expected_luid.is_some(),
    };
    for rule in rules(policy) {
        let Some(filter) = engine.filter(&rule.key)? else {
            result.complete = false;
            continue;
        };
        result.any = true;
        result.complete &= valid_filter(rule, filter.get());
        if rule.interface_condition().is_some() {
            result.tunnel_matches &=
                expected_luid.is_some_and(|luid| expected_interface(rule, filter.get(), luid));
        }
    }
    Ok(result)
}

/// Whether a sublayer that WFP may evaluate before ours holds a permit (or a
/// callout) that clears the action right: such a "hard" permit is the only
/// thing that overrides our block. Best effort: without read access to
/// foreign objects the answer is `false`.
fn foreign_hard_permit(engine: &Engine, policy: Policy) -> Result<bool> {
    let ours: Vec<GUID> = POLICIES
        .iter()
        .flat_map(|policy| [policy.sublayer(), policy.verified()])
        .collect();
    let rivals: Vec<GUID> = engine
        .sublayers()?
        .into_iter()
        .filter(|(key, weight)| {
            *weight >= policy.weight() && !ours.iter().any(|own| same_guid(*own, *key))
        })
        .map(|(key, _)| key)
        .collect();
    if rivals.is_empty() {
        return Ok(false);
    }
    for layer in policy.layers() {
        let hard = engine
            .filters(*layer)?
            .into_iter()
            .any(|(sublayer, flags, action)| {
                flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT != 0
                    && flags & FWPM_FILTER_FLAG_DISABLED == 0
                    && matches!(
                        action,
                        FWP_ACTION_PERMIT
                            | FWP_ACTION_CALLOUT_TERMINATING
                            | FWP_ACTION_CALLOUT_UNKNOWN
                    )
                    && rivals.iter().any(|rival| same_guid(*rival, sublayer))
            });
        if hard {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) struct WfpStatus {
    pub(super) state: GuardState,
    /// The tunnel filters name the configured adapter (or none exist).
    pub(super) tunnel_matches: bool,
    /// A verified `V1` set is active and can be upgraded in place.
    pub(super) outdated: bool,
    pub(super) foreign_hard_permit: bool,
}

pub(super) fn status(adapter: Option<&str>) -> Result<WfpStatus> {
    let expected_luid = adapter.and_then(|name| interface_luid(name).ok());
    let engine = Engine::open()?;
    let old = inspect(&engine, Policy::V1, expected_luid)?;
    let new = inspect(&engine, Policy::V2, expected_luid)?;
    let active = match (old.any, new.any) {
        (false, true) if new.active() => Some(Policy::V2),
        (true, false) if old.active() => Some(Policy::V1),
        _ => None,
    };
    let state = match active {
        Some(_) => GuardState::On,
        None if old.any || new.any => GuardState::Partial,
        None => GuardState::Off,
    };
    Ok(WfpStatus {
        state,
        tunnel_matches: old.tunnel_matches && new.tunnel_matches,
        outdated: active == Some(Policy::V1),
        foreign_hard_permit: active
            .is_some_and(|policy| foreign_hard_permit(&engine, policy).unwrap_or(false)),
    })
}

/// Reads the Mihomo path and adapter the elevated script has just verified.
fn checked_connection() -> Result<Connection> {
    let core = checked_core()?;
    let adapter = env::var(ADAPTER_ENV).map_err(|_| "Не передано имя TUN-адаптера.")?;
    connection(&core, &adapter)
}

fn connection(core: &Path, adapter: &str) -> Result<Connection> {
    let named_mihomo = core
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("mihomo.exe"));
    if !core.is_absolute() || !named_mihomo || !core.is_file() {
        return Err("Путь Mihomo не прошёл проверку.".into());
    }
    if adapter.trim().is_empty()
        || adapter.contains(['*', '?', '[', ']'])
        || adapter.chars().any(char::is_control)
    {
        return Err("Имя TUN-адаптера не прошло проверку.".into());
    }
    let system_root = env::var_os("SystemRoot").ok_or("SystemRoot не найден.")?;
    let dhcp = Path::new(&system_root).join("System32").join("svchost.exe");
    Ok(Connection {
        luid: interface_luid(adapter)?,
        mihomo: application_id(core)?,
        dhcp: application_id(&dhcp)?,
    })
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Runs the access check WFP performs for `ALE_USER_ID` against the token of
/// a process: whether the Mihomo permit of `V2` will match it.
fn process_matches_elevated_users(pid: u32) -> Result<bool> {
    let last_error = || io::Error::last_os_error().to_string();
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(last_error());
    }
    let process = OwnedHandle(process);
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) } == 0 {
        return Err(last_error());
    }
    let token = OwnedHandle(token);
    let mut identity = null_mut();
    if unsafe { DuplicateToken(token.0, SecurityIdentification, &mut identity) } == 0 {
        return Err(last_error());
    }
    let identity = OwnedHandle(identity);
    let descriptor = ObjectSecurity::from_sddl(ELEVATED_USERS)?;
    let mapping = GENERIC_MAPPING {
        GenericRead: 1,
        GenericWrite: 1,
        GenericExecute: 1,
        GenericAll: 1,
    };
    let mut privileges = PRIVILEGE_SET::default();
    let mut length = std::mem::size_of::<PRIVILEGE_SET>() as u32;
    let mut granted = 0u32;
    let mut allowed = 0;
    let ok = unsafe {
        AccessCheck(
            descriptor.0,
            identity.0,
            1,
            &mapping,
            &mut privileges,
            &mut length,
            &mut granted,
            &mut allowed,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(allowed != 0)
}

/// Refuses to install `V2` while the verified Mihomo would be blocked by it,
/// instead of cutting the tunnel until the post-checks roll it back.
fn check_core_process(core: &Path) -> Result<()> {
    let pid: u32 = env::var(CORE_PID_ENV)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .ok_or("Не передан процесс Mihomo.")?;
    let running = unsafe { super::process_path(pid) }.ok_or("Процесс Mihomo не найден.")?;
    if running.to_string_lossy().to_lowercase() != core.to_string_lossy().to_lowercase() {
        return Err("Процесс Mihomo не совпадает с проверенным путём.".into());
    }
    if !process_matches_elevated_users(pid)? {
        return Err(
            "Mihomo запущен без прав администратора: новые фильтры его не пропустят. \
             Запусти v2rayN от имени администратора."
                .into(),
        );
    }
    Ok(())
}

fn checked_core() -> Result<PathBuf> {
    env::var_os(CORE_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| "Не передан путь Mihomo.".into())
}

fn delete_policy(engine: &Engine, policy: Policy) -> Result<()> {
    for rule in rules(policy) {
        let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &rule.key) };
        if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code, "удаление фильтра")?;
        }
    }
    for layer in [policy.verified(), policy.sublayer()] {
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &layer) };
        if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            check(code, "удаление слоя")?;
        }
    }
    Ok(())
}

fn apply() -> Result<()> {
    let connection = checked_connection()?;
    check_core_process(&checked_core()?)?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    for policy in POLICIES {
        if inspect(&engine, policy, None)?.any {
            return Err("Сначала выключи текущие фильтры WFP.".into());
        }
    }
    stage_filters(&engine, &security, Policy::V2, &connection)?;
    transaction.commit()
}

/// Replaces an active `V1` set with an unverified `V2` set in one transaction,
/// so no traffic passes unfiltered in between.
fn upgrade() -> Result<()> {
    let connection = checked_connection()?;
    check_core_process(&checked_core()?)?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    let old = inspect(&engine, Policy::V1, Some(connection.luid))?;
    if !old.active() || !old.tunnel_matches || inspect(&engine, Policy::V2, None)?.any {
        return Err("Обновлять можно только целый проверенный набор фильтров.".into());
    }
    delete_policy(&engine, Policy::V1)?;
    stage_filters(&engine, &security, Policy::V2, &connection)?;
    transaction.commit()
}

/// Undoes a failed upgrade: puts the previously verified `V1` set back in the
/// same transaction that removes `V2`.
fn rollback() -> Result<()> {
    let connection = checked_connection()?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    delete_policy(&engine, Policy::V2)?;
    let old = inspect(&engine, Policy::V1, Some(connection.luid))?;
    if !(old.active() && old.tunnel_matches) {
        delete_policy(&engine, Policy::V1)?;
        stage_filters(&engine, &security, Policy::V1, &connection)?;
        add_sublayer(
            &engine,
            &security,
            Policy::V1,
            Policy::V1.verified(),
            "Tunnel Guard (проверено)",
        )?;
    }
    transaction.commit()
}

fn verify() -> Result<()> {
    let adapter = env::var(ADAPTER_ENV).map_err(|_| "Не передано имя TUN-адаптера.")?;
    let luid = interface_luid(&adapter)?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    let policy = inspect(&engine, Policy::V2, Some(luid))?;
    if !policy.complete
        || !policy.tunnel_matches
        || policy.verified
        || inspect(&engine, Policy::V1, None)?.any
    {
        return Err("Набор фильтров WFP или адаптер изменился во время проверки.".into());
    }
    add_sublayer(
        &engine,
        &security,
        Policy::V2,
        Policy::V2.verified(),
        "Tunnel Guard (проверено)",
    )?;
    transaction.commit()
}

fn remove() -> Result<()> {
    let engine = Engine::open()?;
    let transaction = engine.write()?;
    for policy in POLICIES {
        delete_policy(&engine, policy)?;
    }
    transaction.commit()
}

pub(super) fn run(args: &[String]) -> i32 {
    let result = match args {
        [action] if action == "Apply" => apply(),
        [action] if action == "Upgrade" => upgrade(),
        [action] if action == "Rollback" => rollback(),
        [action] if action == "Verify" => verify(),
        [action] if action == "Remove" => remove(),
        _ => return 20,
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            31
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_rules() -> Vec<Rule> {
        POLICIES.into_iter().flat_map(rules).collect()
    }

    #[test]
    fn every_layer_has_a_default_block_and_rule_keys_are_unique() {
        let rules = all_rules();
        for (index, rule) in rules.iter().enumerate() {
            assert!(!rules[..index]
                .iter()
                .any(|other| same_guid(other.key, rule.key)));
            let layer: Vec<_> = rules
                .iter()
                .filter(|other| other.policy == rule.policy && same_guid(other.layer, rule.layer))
                .collect();
            let mut blocks = layer
                .iter()
                .filter(|other| other.action() == FWP_ACTION_BLOCK);
            let block = blocks.next().unwrap();
            assert!(blocks.next().is_none());
            for permit in layer
                .iter()
                .filter(|other| other.action() == FWP_ACTION_PERMIT)
            {
                assert!(permit.weight() > block.weight());
                assert_eq!(permit.flags(), FWPM_FILTER_FLAG_PERSISTENT);
            }
        }
    }

    #[test]
    fn policy_objects_do_not_overlap() {
        let keys: Vec<GUID> = POLICIES
            .iter()
            .flat_map(|policy| [policy.sublayer(), policy.verified()])
            .chain(all_rules().into_iter().map(|rule| rule.key))
            .collect();
        for (index, key) in keys.iter().enumerate() {
            assert!(!keys[..index].iter().any(|other| same_guid(*other, *key)));
        }
    }

    #[test]
    fn v1_layout_is_unchanged() {
        // Installed V1 sets are recognised by these exact keys and counts.
        let rules: Vec<_> = rules(Policy::V1).collect();
        assert_eq!(rules.len(), 4 * 4 + 2 + 2);
        assert!(rules.iter().all(|rule| {
            !matches!(rule.kind, RuleKind::ForwardIn | RuleKind::ForwardOut)
                && (rule.kind != RuleKind::Dhcp || rule.ipv4)
                && rule.condition_count() <= 4
        }));
        let mihomo = rules.iter().find(|rule| rule.kind == RuleKind::Mihomo);
        assert_eq!(mihomo.unwrap().condition_count(), 1);
        assert!(same_guid(
            rules[0].key,
            GUID::from_u128(0x64fc98a5_0706_4a82_a8ea_ffbf83e32100)
        ));
        assert_eq!(Policy::V1.weight(), 0xe000);
    }

    #[test]
    fn v2_covers_forwarding_dhcpv6_and_requires_elevated_mihomo() {
        let rules: Vec<_> = rules(Policy::V2).collect();
        for layer in Policy::V2.layers() {
            assert!(rules
                .iter()
                .any(|rule| same_guid(rule.layer, *layer) && rule.kind == RuleKind::DefaultBlock));
        }
        let forward = |kind| {
            rules
                .iter()
                .filter(|rule| rule.kind == kind)
                .map(|rule| rule.interface_condition())
                .collect::<Vec<_>>()
        };
        assert_eq!(forward(RuleKind::ForwardIn).len(), 2);
        assert!(forward(RuleKind::ForwardOut)
            .iter()
            .all(|field| same_guid(field.unwrap(), FWPM_CONDITION_IP_FORWARD_INTERFACE)));
        let dhcp: Vec<_> = rules
            .iter()
            .filter(|rule| rule.kind == RuleKind::Dhcp)
            .map(|rule| rule.dhcp_ports())
            .collect();
        assert!(dhcp.contains(&(68, 67)) && dhcp.contains(&(546, 547)));
        assert!(rules
            .iter()
            .filter(|rule| rule.kind == RuleKind::Mihomo)
            .all(|rule| rule.condition_count() == 2));
        assert_eq!(Policy::V2.weight(), u16::MAX);
    }

    #[test]
    fn elevated_users_descriptor_is_valid() {
        let security = ObjectSecurity::from_sddl(ELEVATED_USERS).unwrap();
        let blob = security.blob();
        assert!(blob.size > 0 && !blob.data.is_null());
    }

    #[test]
    fn elevation_check_agrees_with_the_current_token() {
        let matches = process_matches_elevated_users(std::process::id()).unwrap();
        assert_eq!(matches, super::super::is_admin());
    }

    #[test]
    fn connection_rejects_unexpected_core_paths() {
        let exe = std::env::current_exe().unwrap();
        assert!(connection(&exe, "Mihomo").is_err());
        assert!(connection(Path::new("mihomo.exe"), "Mihomo").is_err());
        assert!(connection(Path::new(r"C:\missing\mihomo.exe"), "Mihomo").is_err());
    }

    #[test]
    #[ignore = "requires administrator rights and configured Mihomo; the WFP transaction is aborted"]
    fn windows_accepts_the_filters_without_activating_them() {
        let settings = settings::load_settings().unwrap();
        let client = settings::client_path(&settings).unwrap();
        let core = client
            .with_file_name("bin")
            .join("mihomo")
            .join("mihomo.exe");
        let connection = connection(&core, &settings.adapter).unwrap();
        let engine = Engine::open().unwrap();
        let security = ObjectSecurity::new().unwrap();
        for policy in POLICIES {
            assert!(!inspect(&engine, policy, None).unwrap().any);
            {
                let _transaction = engine.write().unwrap();
                stage_filters(&engine, &security, policy, &connection).unwrap();
                let pending = inspect(&engine, policy, Some(connection.luid)).unwrap();
                assert!(pending.complete);
                assert!(pending.tunnel_matches);
                assert!(!pending.verified);
            }
            assert!(!inspect(&engine, policy, None).unwrap().any);
        }
    }
}
