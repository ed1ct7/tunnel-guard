//! Read-only readiness diagnosis: v2rayN files, processes, listeners, the TUN
//! adapter and the running Mihomo's own view. It never fails because of a
//! check: every fact that could not be gathered becomes a failed or skipped
//! check.

use crate::{
    core_rules,
    http::{self, ControllerError},
    rules,
    settings::{self, Settings},
    status::now_ms,
    Result,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckId {
    Client,
    Core,
    Mixin,
    ClientRunning,
    Proxy,
    Controller,
    Adapter,
    Tun,
    Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckStatus {
    Ok,
    Fail,
    Warn,
    /// Not evaluated because a prerequisite failed.
    Skip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Check {
    pub id: CheckId,
    pub status: CheckStatus,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProxyGroup {
    pub name: String,
    pub kind: String,
    pub now: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CoreInfo {
    pub version: Option<String>,
    pub mode: Option<String>,
    pub tun_enabled: bool,
    pub tun_device: Option<String>,
    pub groups: Vec<ProxyGroup>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Diagnosis {
    pub checks: Vec<Check>,
    pub ready: bool,
    pub core: Option<CoreInfo>,
    pub checked_at: u64,
}

/// Checks that do not decide `ready`.
const ADVISORY: [CheckId; 2] = [CheckId::Mixin, CheckId::ClientRunning];
const GROUP_KINDS: [&str; 4] = ["Selector", "URLTest", "Fallback", "LoadBalance"];

fn null_as_empty<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u32>, D::Error> {
    Ok(Option::<Vec<u32>>::deserialize(deserializer)?.unwrap_or_default())
}

/// Output of the read-only PowerShell `Diagnose` action.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct SystemFacts {
    #[serde(default)]
    pub adapter_exists: bool,
    #[serde(default)]
    pub adapter_status: Option<String>,
    #[serde(default)]
    pub client_running: bool,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub proxy_pids: Vec<u32>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub controller_pids: Vec<u32>,
}

/// What the controller itself reports (`/configs` is required).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ControllerFacts {
    pub version: Option<String>,
    pub configs: Value,
    pub proxies: Option<Value>,
}

/// Everything the checks are computed from; built by `gather`.
pub(crate) struct Inputs {
    pub settings: Settings,
    pub client: std::result::Result<PathBuf, String>,
    pub core_exe: bool,
    /// `None` when the client path is not valid.
    pub mixin: Option<Result<bool>>,
    /// Adapter name and proxy port pass `validate_connection`.
    pub connection_valid: bool,
    pub controller_port: Option<u16>,
    pub system: Result<SystemFacts>,
    /// `None` when no controller port is known.
    pub controller: Option<std::result::Result<ControllerFacts, ControllerError>>,
}

fn core_exe_path(client_dir: &Path) -> PathBuf {
    client_dir
        .join("bin")
        .join("mihomo")
        .join(if cfg!(windows) {
            "mihomo.exe"
        } else {
            "mihomo"
        })
}

fn check(id: CheckId, status: CheckStatus, detail: impl Into<Option<String>>) -> Check {
    Check {
        id,
        status,
        detail: detail.into(),
    }
}

fn ok(id: CheckId, detail: impl Into<Option<String>>) -> Check {
    check(id, CheckStatus::Ok, detail)
}

fn fail(id: CheckId, detail: impl Into<Option<String>>) -> Check {
    check(id, CheckStatus::Fail, detail)
}

fn skip(id: CheckId) -> Check {
    check(id, CheckStatus::Skip, None)
}

fn is_ok(check: &Check) -> bool {
    check.status == CheckStatus::Ok
}

fn text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Proxy groups from `GET /proxies`, in GLOBAL's order when it is known.
pub(crate) fn proxy_groups(proxies: &Value) -> Vec<ProxyGroup> {
    let Some(map) = proxies.get("proxies").and_then(Value::as_object) else {
        return Vec::new();
    };
    let order: Vec<&str> = map
        .get("GLOBAL")
        .and_then(|global| global.get("all"))
        .and_then(Value::as_array)
        .map(|all| all.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut groups: Vec<ProxyGroup> = map
        .iter()
        .filter(|(name, _)| name.as_str() != "GLOBAL")
        .filter_map(|(name, entry)| {
            let kind = entry.get("type")?.as_str()?;
            GROUP_KINDS.contains(&kind).then(|| ProxyGroup {
                name: name.clone(),
                kind: kind.to_owned(),
                now: text(entry, "now"),
            })
        })
        .collect();
    groups.sort_by_key(|group| {
        order
            .iter()
            .position(|name| *name == group.name)
            .unwrap_or(usize::MAX)
    });
    groups
}

fn core_info(facts: &ControllerFacts) -> CoreInfo {
    let tun = facts.configs.get("tun");
    CoreInfo {
        version: facts.version.clone(),
        mode: text(&facts.configs, "mode"),
        tun_enabled: tun
            .and_then(|tun| tun.get("enable"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        tun_device: tun.and_then(|tun| text(tun, "device")),
        groups: facts.proxies.as_ref().map(proxy_groups).unwrap_or_default(),
    }
}

fn same_name(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

/// Pure assembly of the nine checks (in contract order) and the core info.
pub(crate) fn assemble(inputs: &Inputs) -> (Vec<Check>, Option<CoreInfo>) {
    let settings = &inputs.settings;
    let probe_failed = "проверка не удалась".to_string();

    let client = match &inputs.client {
        Ok(path) => ok(CheckId::Client, path.display().to_string()),
        Err(_) if settings.client_path.trim().is_empty() => {
            fail(CheckId::Client, "путь не задан".to_string())
        }
        Err(_) => fail(CheckId::Client, settings.client_path.clone()),
    };
    let core_file = format!(
        "bin{0}mihomo{0}{1}",
        std::path::MAIN_SEPARATOR,
        if cfg!(windows) {
            "mihomo.exe"
        } else {
            "mihomo"
        }
    );
    let core = if !is_ok(&client) {
        skip(CheckId::Core)
    } else if inputs.core_exe {
        ok(CheckId::Core, core_file)
    } else {
        fail(CheckId::Core, format!("нет {core_file}"))
    };
    let mixin = match (&inputs.mixin, is_ok(&client)) {
        (_, false) | (None, _) => skip(CheckId::Mixin),
        (Some(Ok(true)), true) => ok(CheckId::Mixin, "EnableMixinContent=true".to_string()),
        (Some(Ok(false)), true) => check(
            CheckId::Mixin,
            CheckStatus::Warn,
            "EnableMixinContent=false".to_string(),
        ),
        (Some(Err(error)), true) => fail(CheckId::Mixin, error.clone()),
    };

    let system = inputs.system.as_ref().ok();
    let client_running = match system {
        None => check(
            CheckId::ClientRunning,
            CheckStatus::Skip,
            probe_failed.clone(),
        ),
        Some(facts) if facts.client_running => ok(CheckId::ClientRunning, "v2rayN.exe".to_string()),
        Some(_) => check(
            CheckId::ClientRunning,
            CheckStatus::Warn,
            "v2rayN.exe не запущен".to_string(),
        ),
    };

    let port = settings.proxy_port;
    let proxy = match system {
        _ if !inputs.connection_valid => fail(CheckId::Proxy, format!("порт {port} некорректен")),
        None => check(CheckId::Proxy, CheckStatus::Skip, probe_failed.clone()),
        Some(facts) if !facts.proxy_pids.is_empty() => ok(CheckId::Proxy, format!("порт {port}")),
        Some(_) => fail(CheckId::Proxy, format!("порт {port} не слушается")),
    };

    let reachable = match &inputs.controller {
        Some(Ok(facts)) => Some(facts),
        _ => None,
    };
    let controller = match (system, inputs.controller_port) {
        _ if !is_ok(&proxy) => skip(CheckId::Controller),
        (None, _) => skip(CheckId::Controller),
        (_, None) => fail(CheckId::Controller, "порт неизвестен".to_string()),
        (Some(facts), Some(controller_port)) => {
            let shared = facts
                .controller_pids
                .iter()
                .any(|pid| facts.proxy_pids.contains(pid));
            match &inputs.controller {
                _ if facts.controller_pids.is_empty() && reachable.is_none() => fail(
                    CheckId::Controller,
                    format!("порт {controller_port} не слушается"),
                ),
                Some(Err(error)) => fail(
                    CheckId::Controller,
                    format!("порт {controller_port}: {}", error.message()),
                ),
                None => fail(
                    CheckId::Controller,
                    format!(
                        "порт {controller_port}: {}",
                        ControllerError::Unreachable.message()
                    ),
                ),
                Some(Ok(_)) if !facts.controller_pids.is_empty() && !shared => fail(
                    CheckId::Controller,
                    format!(
                        "порт {controller_port}: другой процесс (pid {})",
                        facts.controller_pids[0]
                    ),
                ),
                Some(Ok(_)) => ok(CheckId::Controller, format!("порт {controller_port}")),
            }
        }
    };

    let adapter_name = settings.adapter.as_str();
    let adapter = match system {
        _ if !inputs.connection_valid => {
            fail(CheckId::Adapter, "имя адаптера некорректно".to_string())
        }
        None => check(CheckId::Adapter, CheckStatus::Skip, probe_failed),
        Some(facts) if !facts.adapter_exists => {
            fail(CheckId::Adapter, format!("{adapter_name} не найден"))
        }
        Some(facts) => {
            let status = facts.adapter_status.clone().unwrap_or_default();
            if status.eq_ignore_ascii_case("Up") {
                ok(CheckId::Adapter, format!("{adapter_name}: Up"))
            } else {
                fail(CheckId::Adapter, format!("{adapter_name}: {status}"))
            }
        }
    };

    let info = reachable.map(core_info);
    let (tun, mode) = match (&info, is_ok(&controller)) {
        (Some(info), true) => {
            let device = info.tun_device.clone().unwrap_or_default();
            let tun = if !info.tun_enabled {
                fail(CheckId::Tun, "tun.enable=false".to_string())
            } else if same_name(&device, adapter_name) {
                ok(CheckId::Tun, format!("device={device}"))
            } else {
                fail(CheckId::Tun, format!("device={device}"))
            };
            let value = info.mode.clone().unwrap_or_default();
            let mode = if value.eq_ignore_ascii_case("rule") {
                ok(CheckId::Mode, format!("mode={value}"))
            } else {
                fail(CheckId::Mode, format!("mode={value}"))
            };
            (tun, mode)
        }
        _ => (skip(CheckId::Tun), skip(CheckId::Mode)),
    };

    (
        vec![
            client,
            core,
            mixin,
            client_running,
            proxy,
            controller,
            adapter,
            tun,
            mode,
        ],
        info,
    )
}

pub(crate) fn is_ready(checks: &[Check]) -> bool {
    checks
        .iter()
        .filter(|check| !ADVISORY.contains(&check.id))
        .all(is_ok)
}

fn fetch_controller(
    port: u16,
    secret: Option<&str>,
) -> std::result::Result<ControllerFacts, ControllerError> {
    let version = http::get_json(port, "/version", secret)?;
    let configs = http::get_json(port, "/configs", secret)?;
    if !configs.is_object() {
        return Err(ControllerError::Invalid);
    }
    let proxies = http::get_json(port, "/proxies", secret).ok();
    Ok(ControllerFacts {
        version: text(&version, "version"),
        configs,
        proxies,
    })
}

/// Collects the inputs; the system probe runs in parallel with the HTTP calls.
pub(crate) fn gather<P>(settings: &Settings, probe: P) -> Inputs
where
    P: FnOnce(Option<&str>, Option<u16>, Option<u16>) -> Result<SystemFacts> + Send,
{
    let client = settings::client_path(settings);
    let client_dir = client
        .as_ref()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let core_exe = client_dir
        .as_deref()
        .is_some_and(|dir| core_exe_path(dir).is_file());
    let mixin = client.is_ok().then(|| {
        rules::mixin_path(settings).and_then(|path| rules::mixin_content_enabled_for(&path))
    });
    let connection_valid = settings::validate_connection(settings).is_ok();
    // Port and secret of the running core come from the config v2rayN
    // generated for it; without one, v2rayN's TUN layout (proxy + 6).
    let generated = client_dir
        .as_deref()
        .and_then(|dir| core_rules::load_generated(dir, settings.proxy_port).ok());
    let controller_port = generated
        .as_ref()
        .and_then(|config| config.controller_port())
        .or_else(|| settings.proxy_port.checked_add(6))
        .filter(|port| *port != 0);
    let secret = generated.as_ref().and_then(|config| config.secret());
    drop(generated);
    let adapter = connection_valid.then_some(settings.adapter.as_str());
    let proxy_port = connection_valid.then_some(settings.proxy_port);
    let (system, controller) = std::thread::scope(|scope| {
        let system = scope.spawn(move || probe(adapter, proxy_port, controller_port));
        let controller = controller_port.map(|port| fetch_controller(port, secret.as_deref()));
        let system = system
            .join()
            .unwrap_or_else(|_| Err("Проверка системы прервалась.".into()));
        (system, controller)
    });
    Inputs {
        settings: settings.clone(),
        client,
        core_exe,
        mixin,
        connection_valid,
        controller_port,
        system,
        controller,
    }
}

pub(crate) fn diagnosis_from(inputs: &Inputs, checked_at: u64) -> Diagnosis {
    let (checks, core) = assemble(inputs);
    Diagnosis {
        ready: is_ready(&checks),
        checks,
        core,
        checked_at,
    }
}

fn probe_system(
    adapter: Option<&str>,
    proxy_port: Option<u16>,
    controller_port: Option<u16>,
) -> Result<SystemFacts> {
    #[cfg(windows)]
    {
        serde_json::from_value(crate::windows::diagnose_facts(
            adapter,
            proxy_port,
            controller_port,
        )?)
        .map_err(|_| "Не удалось прочитать состояние системы.".into())
    }
    #[cfg(not(windows))]
    {
        let _ = (adapter, proxy_port, controller_port);
        Err("Проверка системы для этой ОС не реализована.".into())
    }
}

/// `diagnose` command / `guardctl doctor`. Fails only when the settings
/// themselves cannot be read.
pub(crate) fn diagnose() -> Result<Diagnosis> {
    let settings = settings::load_settings()?;
    let inputs = gather(&settings, probe_system);
    Ok(diagnosis_from(&inputs, now_ms()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_controller;
    use serde_json::json;
    use std::fs;

    const IDS: [CheckId; 9] = [
        CheckId::Client,
        CheckId::Core,
        CheckId::Mixin,
        CheckId::ClientRunning,
        CheckId::Proxy,
        CheckId::Controller,
        CheckId::Adapter,
        CheckId::Tun,
        CheckId::Mode,
    ];

    fn settings() -> Settings {
        Settings {
            client_path: r"C:\v2rayN\v2rayN.exe".into(),
            adapter: "MihomoTest".into(),
            proxy_port: 18761,
            ..Settings::default()
        }
    }

    fn system() -> SystemFacts {
        SystemFacts {
            adapter_exists: true,
            adapter_status: Some("Up".into()),
            client_running: true,
            proxy_pids: vec![31108],
            controller_pids: vec![31108],
        }
    }

    fn controller(mode: &str, tun_enable: bool, device: &str) -> ControllerFacts {
        ControllerFacts {
            version: Some("v1.19.34".into()),
            configs: json!({"mode": mode, "mixed-port": 18761, "tun": {"enable": tun_enable, "device": device}}),
            proxies: Some(json!({"proxies": {
                "GLOBAL": {"type": "Selector", "now": "auto", "all": ["Server-4", "proxy", "auto"]},
                "auto": {"type": "URLTest", "now": "Server-4"},
                "proxy": {"type": "Selector", "now": ""},
                "Server-4": {"type": "WireGuard"},
                "DIRECT": {"type": "Direct"}
            }})),
        }
    }

    fn inputs() -> Inputs {
        Inputs {
            settings: settings(),
            client: Ok(PathBuf::from(r"C:\v2rayN\v2rayN.exe")),
            core_exe: true,
            mixin: Some(Ok(true)),
            connection_valid: true,
            controller_port: Some(18767),
            system: Ok(system()),
            controller: Some(Ok(controller("rule", true, "mihomotest"))),
        }
    }

    fn statuses(diagnosis: &Diagnosis) -> Vec<(CheckId, CheckStatus)> {
        diagnosis
            .checks
            .iter()
            .map(|check| (check.id, check.status))
            .collect()
    }

    fn status_of(diagnosis: &Diagnosis, id: CheckId) -> (CheckStatus, Option<String>) {
        let check = diagnosis
            .checks
            .iter()
            .find(|check| check.id == id)
            .unwrap();
        (check.status, check.detail.clone())
    }

    #[test]
    fn all_ok_is_ready_with_all_ids_in_order() {
        let diagnosis = diagnosis_from(&inputs(), 7);
        let ids: Vec<_> = diagnosis.checks.iter().map(|check| check.id).collect();
        assert_eq!(ids, IDS);
        assert!(diagnosis
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Ok));
        assert!(diagnosis.ready);
        assert_eq!(diagnosis.checked_at, 7);
        assert_eq!(
            status_of(&diagnosis, CheckId::Proxy).1.as_deref(),
            Some("порт 18761")
        );
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller).1.as_deref(),
            Some("порт 18767")
        );
        assert_eq!(
            status_of(&diagnosis, CheckId::Tun).1.as_deref(),
            Some("device=mihomotest")
        );
        let core = diagnosis.core.unwrap();
        assert_eq!(core.version.as_deref(), Some("v1.19.34"));
        assert_eq!(core.mode.as_deref(), Some("rule"));
        assert!(core.tun_enabled);
        assert_eq!(
            core.groups,
            vec![
                ProxyGroup {
                    name: "proxy".into(),
                    kind: "Selector".into(),
                    now: None
                },
                ProxyGroup {
                    name: "auto".into(),
                    kind: "URLTest".into(),
                    now: Some("Server-4".into())
                },
            ]
        );
    }

    #[test]
    fn advisory_checks_do_not_block_ready() {
        let mut input = inputs();
        input.mixin = Some(Ok(false));
        input.system = Ok(SystemFacts {
            client_running: false,
            ..system()
        });
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Mixin).0, CheckStatus::Warn);
        assert_eq!(
            status_of(&diagnosis, CheckId::ClientRunning).0,
            CheckStatus::Warn
        );
        assert!(diagnosis.ready);
        input.mixin = Some(Err("Не найдены настройки v2rayN.".into()));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Mixin).0, CheckStatus::Fail);
        assert!(diagnosis.ready);
    }

    #[test]
    fn bad_client_skips_file_checks_only() {
        let mut input = inputs();
        input.client = Err("Выбери существующий исполняемый файл v2rayN.exe.".into());
        input.mixin = None;
        input.core_exe = false;
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            statuses(&diagnosis)[..3],
            [
                (CheckId::Client, CheckStatus::Fail),
                (CheckId::Core, CheckStatus::Skip),
                (CheckId::Mixin, CheckStatus::Skip)
            ]
        );
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller).0,
            CheckStatus::Ok
        );
        assert!(!diagnosis.ready);
        input.settings.client_path = String::new();
        assert_eq!(
            status_of(&diagnosis_from(&input, 0), CheckId::Client)
                .1
                .as_deref(),
            Some("путь не задан")
        );
    }

    #[test]
    fn missing_core_exe_fails() {
        let mut input = inputs();
        input.core_exe = false;
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Core).0, CheckStatus::Fail);
        assert!(!diagnosis.ready);
    }

    #[test]
    fn closed_proxy_skips_controller_and_core_view() {
        let mut input = inputs();
        input.system = Ok(SystemFacts {
            proxy_pids: vec![],
            controller_pids: vec![],
            ..system()
        });
        input.controller = Some(Err(ControllerError::Unreachable));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            statuses(&diagnosis)[4..],
            [
                (CheckId::Proxy, CheckStatus::Fail),
                (CheckId::Controller, CheckStatus::Skip),
                (CheckId::Adapter, CheckStatus::Ok),
                (CheckId::Tun, CheckStatus::Skip),
                (CheckId::Mode, CheckStatus::Skip)
            ]
        );
        assert_eq!(
            status_of(&diagnosis, CheckId::Proxy).1.as_deref(),
            Some("порт 18761 не слушается")
        );
        assert_eq!(diagnosis.core, None);
        assert!(!diagnosis.ready);
    }

    #[test]
    fn unreachable_controller_fails_and_has_no_core() {
        let mut input = inputs();
        input.system = Ok(SystemFacts {
            controller_pids: vec![],
            ..system()
        });
        input.controller = Some(Err(ControllerError::Unreachable));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller),
            (CheckStatus::Fail, Some("порт 18767 не слушается".into()))
        );
        assert_eq!(status_of(&diagnosis, CheckId::Tun).0, CheckStatus::Skip);
        assert_eq!(diagnosis.core, None);

        input.system = Ok(system());
        input.controller = Some(Err(ControllerError::Unauthorized));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller),
            (
                CheckStatus::Fail,
                Some("порт 18767: Контроллер Mihomo отклонил ключ доступа".into())
            )
        );
    }

    #[test]
    fn controller_of_another_process_fails_but_core_is_reported() {
        let mut input = inputs();
        input.system = Ok(SystemFacts {
            controller_pids: vec![999],
            ..system()
        });
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller),
            (
                CheckStatus::Fail,
                Some("порт 18767: другой процесс (pid 999)".into())
            )
        );
        assert_eq!(status_of(&diagnosis, CheckId::Mode).0, CheckStatus::Skip);
        assert!(diagnosis.core.is_some());
        assert!(!diagnosis.ready);
    }

    #[test]
    fn tun_and_mode_mismatches() {
        let mut input = inputs();
        input.controller = Some(Ok(controller("global", true, "Meta")));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            status_of(&diagnosis, CheckId::Tun),
            (CheckStatus::Fail, Some("device=Meta".into()))
        );
        assert_eq!(
            status_of(&diagnosis, CheckId::Mode),
            (CheckStatus::Fail, Some("mode=global".into()))
        );
        input.controller = Some(Ok(controller("Rule", false, "MihomoTest")));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(
            status_of(&diagnosis, CheckId::Tun),
            (CheckStatus::Fail, Some("tun.enable=false".into()))
        );
        assert_eq!(status_of(&diagnosis, CheckId::Mode).0, CheckStatus::Ok);
        assert!(!diagnosis.ready);
    }

    #[test]
    fn adapter_states() {
        let mut input = inputs();
        input.system = Ok(SystemFacts {
            adapter_exists: false,
            adapter_status: None,
            ..system()
        });
        assert_eq!(
            status_of(&diagnosis_from(&input, 0), CheckId::Adapter),
            (CheckStatus::Fail, Some("MihomoTest не найден".into()))
        );
        input.system = Ok(SystemFacts {
            adapter_status: Some("Disconnected".into()),
            ..system()
        });
        assert_eq!(
            status_of(&diagnosis_from(&input, 0), CheckId::Adapter),
            (CheckStatus::Fail, Some("MihomoTest: Disconnected".into()))
        );
    }

    #[test]
    fn failed_probe_skips_system_checks() {
        let mut input = inputs();
        input.system = Err("powershell".into());
        let diagnosis = diagnosis_from(&input, 0);
        for id in [CheckId::ClientRunning, CheckId::Proxy, CheckId::Adapter] {
            assert_eq!(status_of(&diagnosis, id).0, CheckStatus::Skip, "{id:?}");
        }
        for id in [CheckId::Controller, CheckId::Tun, CheckId::Mode] {
            assert_eq!(status_of(&diagnosis, id).0, CheckStatus::Skip, "{id:?}");
        }
        assert!(!diagnosis.ready);
    }

    #[test]
    fn invalid_connection_fails_proxy_and_adapter() {
        let mut input = inputs();
        input.connection_valid = false;
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Proxy).0, CheckStatus::Fail);
        assert_eq!(status_of(&diagnosis, CheckId::Adapter).0, CheckStatus::Fail);
        assert_eq!(
            status_of(&diagnosis, CheckId::Controller).0,
            CheckStatus::Skip
        );
    }

    #[test]
    fn system_facts_from_powershell_json() {
        let facts: SystemFacts = serde_json::from_str(
            r#"{"adapter_exists":true,"adapter_status":"Up","client_running":false,"proxy_pids":[31108],"controller_pids":null}"#,
        )
        .unwrap();
        assert_eq!(facts.proxy_pids, vec![31108]);
        assert!(facts.controller_pids.is_empty());
        assert!(!facts.client_running);
        let empty: SystemFacts = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, SystemFacts::default());
    }

    #[test]
    fn groups_without_global_order_are_listed() {
        let groups = proxy_groups(&json!({"proxies": {
            "b": {"type": "Fallback", "now": "x"},
            "a": {"type": "LoadBalance"},
            "GLOBAL": {"type": "Selector"}
        }}));
        let names: Vec<_> = groups.iter().map(|group| group.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert!(proxy_groups(&json!({})).is_empty());
    }

    #[test]
    fn serializes_contract_shape() {
        let value = serde_json::to_value(diagnosis_from(&inputs(), 5)).unwrap();
        assert_eq!(value["checks"][3]["id"], "client_running");
        assert_eq!(value["checks"][3]["status"], "ok");
        assert_eq!(value["ready"], true);
        assert_eq!(value["checked_at"], 5);
        assert_eq!(value["core"]["tun_enabled"], true);
        assert_eq!(value["core"]["groups"][1]["kind"], "URLTest");
        let mut input = inputs();
        input.controller = Some(Err(ControllerError::Unreachable));
        let value = serde_json::to_value(diagnosis_from(&input, 5)).unwrap();
        assert!(value["core"].is_null());
        assert!(value["checks"][7]["detail"].is_null());
    }

    #[test]
    fn gather_reads_files_and_controller() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("v2rayN.exe"), b"").unwrap();
        fs::create_dir_all(root.join("bin/mihomo")).unwrap();
        fs::write(core_exe_path(root), b"").unwrap();
        fs::create_dir_all(root.join("guiConfigs")).unwrap();
        fs::write(root.join("guiConfigs/Mixin.yaml"), b"prepend-rules: []\n").unwrap();
        fs::write(
            root.join("guiConfigs/guiNConfig.json"),
            br#"{"ClashUIItem":{"EnableMixinContent":false}}"#,
        )
        .unwrap();
        let (port, server) = fake_controller(3, |_, path, _| match path {
            "/version" => (200, r#"{"meta":true,"version":"v1.19.34"}"#.into()),
            "/configs" => (
                200,
                r#"{"mode":"rule","tun":{"enable":true,"device":"MihomoTest"}}"#.into(),
            ),
            _ => (200, r#"{"proxies":{}}"#.into()),
        });
        fs::create_dir_all(root.join("binConfigs")).unwrap();
        fs::write(
            root.join("binConfigs/config.json"),
            format!("mixed-port: 18761\nexternal-controller: 127.0.0.1:{port}\nsecret: s3cr3t\nrules: []\n"),
        )
        .unwrap();
        let settings = Settings {
            client_path: root.join("v2rayN.exe").to_string_lossy().into_owned(),
            adapter: "MihomoTest".into(),
            proxy_port: 18761,
            ..Settings::default()
        };
        let input = gather(&settings, |adapter, proxy, controller| {
            assert_eq!(adapter, Some("MihomoTest"));
            assert_eq!(proxy, Some(18761));
            assert_eq!(controller, Some(port));
            Ok(SystemFacts {
                proxy_pids: vec![1],
                controller_pids: vec![1],
                ..system()
            })
        });
        let requests = server.join().unwrap();
        let paths: Vec<_> = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect();
        assert_eq!(paths, ["/version", "/configs", "/proxies"]);
        assert!(requests.iter().all(|request| request.method == "GET"
            && request
                .headers
                .contains(&("authorization".into(), "Bearer s3cr3t".into()))));
        assert_eq!(input.controller_port, Some(port));
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Mixin).0, CheckStatus::Warn);
        assert!(diagnosis.ready, "{:?}", diagnosis.checks);
        let text = serde_json::to_string(&diagnosis).unwrap();
        assert!(!text.contains("s3cr3t"));
    }

    #[test]
    fn gather_without_client_uses_default_controller_port() {
        // A port nobody listens on serves as proxy + 6.
        let free = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let settings = Settings {
            client_path: String::new(),
            adapter: "MihomoTest".into(),
            proxy_port: free - 6,
            ..Settings::default()
        };
        let input = gather(&settings, |_, _, controller| {
            assert_eq!(controller, Some(free));
            Err("no".into())
        });
        assert_eq!(input.controller_port, Some(free));
        assert_eq!(input.controller, Some(Err(ControllerError::Unreachable)));
        assert!(input.mixin.is_none());
        let diagnosis = diagnosis_from(&input, 0);
        assert_eq!(status_of(&diagnosis, CheckId::Client).0, CheckStatus::Fail);
        assert!(!diagnosis.ready);
    }
}
