//! Tunnel Guard's own WFP sublayer. A terminating block covers each address
//! family and direction, with higher-weight exceptions inside the same layer.
//! The exceptions are soft permits so Windows Firewall can still block them.

pub(crate) mod group_network;

use super::wide;
use crate::{settings, status::GuardState, Result};
use std::{
    ffi::{c_void, OsStr},
    io,
    path::Path,
    ptr::{null, null_mut, NonNull},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{LocalFree, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
        NetworkManagement::{
            IpHelper::ConvertInterfaceAliasToLuid, Ndis::NET_LUID_LH, WindowsFilteringPlatform::*,
        },
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            PSECURITY_DESCRIPTOR,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

const SUBLAYER: GUID = GUID::from_u128(0x64fc98a5_0706_4a82_a8ea_ffbf83e32010);
const VERIFIED: GUID = GUID::from_u128(0x64fc98a5_0706_4a82_a8ea_ffbf83e32011);
const FILTER_BASE: u128 = 0x64fc98a5_0706_4a82_a8ea_ffbf83e32100;
const SUBLAYER_WEIGHT: u16 = 0xe000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
    DefaultBlock,
    Loopback,
    Tunnel,
    Mihomo,
    Dhcp,
    BootBlock,
}

#[derive(Clone, Copy)]
struct Rule {
    key: GUID,
    layer: GUID,
    kind: RuleKind,
    outbound: bool,
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
            _ => 1,
        }
    }

    fn interface_condition(self) -> GUID {
        if self.outbound {
            FWPM_CONDITION_IP_NEXTHOP_INTERFACE
        } else {
            FWPM_CONDITION_IP_LOCAL_INTERFACE
        }
    }
}

fn rules() -> impl Iterator<Item = Rule> {
    use RuleKind::{BootBlock, DefaultBlock, Dhcp, Loopback, Mihomo, Tunnel};
    [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, true),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, false),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false, true),
        (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, false, false),
    ]
    .into_iter()
    .enumerate()
    .flat_map(|(group, (layer, outbound, ipv4))| {
        [DefaultBlock, Loopback, Tunnel, Mihomo, Dhcp]
            .into_iter()
            .enumerate()
            .filter(move |(_, kind)| *kind != Dhcp || ipv4)
            .map(move |(index, kind)| Rule {
                key: GUID::from_u128(FILTER_BASE + (group * 16 + index) as u128),
                layer,
                kind,
                outbound,
            })
    })
    // Persistent ALE filters take over once BFE starts.
    .chain(
        [
            FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, layer)| Rule {
            key: GUID::from_u128(FILTER_BASE + 0x80 + index as u128),
            layer,
            kind: BootBlock,
            outbound: true,
        }),
    )
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
        let sddl = wide(OsStr::new(
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)",
        ));
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

fn conditions(
    rule: Rule,
    luid: &mut u64,
    app: &Allocation<FWP_BYTE_BLOB>,
) -> Vec<FWPM_FILTER_CONDITION0> {
    use RuleKind::*;
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
        Tunnel => vec![condition(
            rule.interface_condition(),
            FWP_MATCH_EQUAL,
            FWP_UINT64,
            FWP_CONDITION_VALUE0_0 { uint64: luid },
        )],
        Mihomo => vec![condition(
            FWPM_CONDITION_ALE_APP_ID,
            FWP_MATCH_EQUAL,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 {
                byteBlob: app.0.as_ptr(),
            },
        )],
        Dhcp => {
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
                    FWP_CONDITION_VALUE0_0 { uint16: 68 },
                ),
                condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_EQUAL,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: 67 },
                ),
                // DHCPv4 can discover a server via broadcast or renew with a
                // unicast server. Limit these ports to the Windows service host.
                condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_MATCH_EQUAL,
                    FWP_BYTE_BLOB_TYPE,
                    FWP_CONDITION_VALUE0_0 {
                        byteBlob: app.0.as_ptr(),
                    },
                ),
            ]
        }
    }
}

fn add_sublayer(engine: &Engine, security: &ObjectSecurity, key: GUID, name: &str) -> Result<()> {
    let mut name = wide(OsStr::new(name));
    let layer = FWPM_SUBLAYER0 {
        subLayerKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        weight: SUBLAYER_WEIGHT,
        ..Default::default()
    };
    check(
        unsafe { FwpmSubLayerAdd0(engine.0, &layer, security.0) },
        "создание слоя",
    )
}

fn stage_filters(
    engine: &Engine,
    security: &ObjectSecurity,
    mut luid: u64,
    app: &Allocation<FWP_BYTE_BLOB>,
    dhcp: &Allocation<FWP_BYTE_BLOB>,
) -> Result<()> {
    add_sublayer(engine, security, SUBLAYER, "Tunnel Guard")?;
    for rule in rules() {
        let mut conditions = conditions(
            rule,
            &mut luid,
            if rule.kind == RuleKind::Dhcp {
                dhcp
            } else {
                app
            },
        );
        let mut name = wide(OsStr::new("Tunnel Guard"));
        let filter = FWPM_FILTER0 {
            filterKey: rule.key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: rule.flags(),
            layerKey: rule.layer,
            subLayerKey: SUBLAYER,
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
        && same_guid(filter.subLayerKey, SUBLAYER)
        && filter.action.r#type == rule.action()
        && filter.numFilterConditions == rule.condition_count()
        && filter.weight.r#type == FWP_UINT8
        && unsafe { filter.weight.Anonymous.uint8 == rule.weight() }
}

fn expected_tunnel(rule: Rule, filter: &FWPM_FILTER0, luid: u64) -> bool {
    if filter.numFilterConditions != 1 || filter.filterCondition.is_null() {
        return false;
    }
    let condition = unsafe { &*filter.filterCondition };
    same_guid(condition.fieldKey, rule.interface_condition())
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

fn inspect(engine: &Engine, expected_luid: Option<u64>) -> Result<Inspection> {
    let layer = engine.sublayer(&SUBLAYER)?;
    let complete_layer = layer.as_ref().is_some_and(|layer| {
        layer.get().flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
            && layer.get().weight == SUBLAYER_WEIGHT
    });
    let marker = engine.sublayer(&VERIFIED)?;
    let mut result = Inspection {
        any: layer.is_some() || marker.is_some(),
        complete: complete_layer,
        verified: marker
            .is_some_and(|marker| marker.get().flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0),
        tunnel_matches: expected_luid.is_some(),
    };
    for rule in rules() {
        let Some(filter) = engine.filter(&rule.key)? else {
            result.complete = false;
            continue;
        };
        result.any = true;
        result.complete &= valid_filter(rule, filter.get());
        if rule.kind == RuleKind::Tunnel {
            result.tunnel_matches &=
                expected_luid.is_some_and(|luid| expected_tunnel(rule, filter.get(), luid));
        }
    }
    Ok(result)
}

pub(super) fn status(adapter: Option<&str>) -> Result<(GuardState, bool)> {
    let expected_luid = adapter.and_then(|name| interface_luid(name).ok());
    let result = inspect(&Engine::open()?, expected_luid)?;
    let state = if result.complete && result.verified {
        GuardState::On
    } else if result.any {
        GuardState::Partial
    } else {
        GuardState::Off
    };
    Ok((state, result.tunnel_matches))
}

fn connection() -> Result<(u64, Allocation<FWP_BYTE_BLOB>, Allocation<FWP_BYTE_BLOB>)> {
    let settings = settings::load_settings()?;
    settings::validate_connection(&settings)?;
    let client = settings::client_path(&settings)?;
    let mihomo = client
        .with_file_name("bin")
        .join("mihomo")
        .join("mihomo.exe");
    let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot не найден.")?;
    let dhcp = Path::new(&system_root).join("System32").join("svchost.exe");
    Ok((
        interface_luid(&settings.adapter)?,
        application_id(&mihomo)?,
        application_id(&dhcp)?,
    ))
}

fn apply() -> Result<()> {
    let (luid, app, dhcp) = connection()?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    if inspect(&engine, None)?.any {
        return Err("Сначала выключи текущие фильтры WFP.".into());
    }
    stage_filters(&engine, &security, luid, &app, &dhcp)?;
    transaction.commit()
}

fn verify() -> Result<()> {
    let settings = settings::load_settings()?;
    let luid = interface_luid(&settings.adapter)?;
    let engine = Engine::open()?;
    let security = ObjectSecurity::new()?;
    let transaction = engine.write()?;
    let policy = inspect(&engine, Some(luid))?;
    if !policy.complete || !policy.tunnel_matches || policy.verified {
        return Err("Набор фильтров WFP или адаптер изменился во время проверки.".into());
    }
    add_sublayer(&engine, &security, VERIFIED, "Tunnel Guard (проверено)")?;
    transaction.commit()
}

fn remove() -> Result<()> {
    let engine = Engine::open()?;
    let transaction = engine.write()?;
    for rule in rules() {
        let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &rule.key) };
        if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code, "удаление фильтра")?;
        }
    }
    for layer in [VERIFIED, SUBLAYER] {
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &layer) };
        if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            check(code, "удаление слоя")?;
        }
    }
    transaction.commit()
}

pub(super) fn run(args: &[String]) -> i32 {
    let result = match args {
        [action] if action == "Apply" => apply(),
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

    #[test]
    fn every_layer_has_a_default_block_and_rule_keys_are_unique() {
        let rules: Vec<_> = rules().collect();
        for (index, rule) in rules.iter().enumerate() {
            assert!(!rules[..index]
                .iter()
                .any(|other| same_guid(other.key, rule.key)));
            let layer: Vec<_> = rules
                .iter()
                .filter(|other| same_guid(other.layer, rule.layer))
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
    #[ignore = "requires administrator rights and configured Mihomo; the WFP transaction is aborted"]
    fn windows_accepts_the_filters_without_activating_them() {
        let (luid, app, dhcp) = connection().unwrap();
        let engine = Engine::open().unwrap();
        assert!(!inspect(&engine, None).unwrap().any);
        let security = ObjectSecurity::new().unwrap();
        {
            let _transaction = engine.write().unwrap();
            stage_filters(&engine, &security, luid, &app, &dhcp).unwrap();
            let pending = inspect(&engine, Some(luid)).unwrap();
            assert!(pending.complete);
            assert!(pending.tunnel_matches);
            assert!(!pending.verified);
        }
        assert!(!inspect(&engine, None).unwrap().any);
    }
}
