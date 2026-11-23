use crate::{settings::ProtectionBackend, Result};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Firewall state as reported by the PowerShell script. Serialized names are
/// part of the CLI JSON and script contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum GuardState {
    On,
    Off,
    Partial,
    LegacyActive,
    LegacyInactive,
    Unsupported,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Status {
    pub state: GuardState,
    pub adapter_up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_backend: Option<ProtectionBackend>,
    /// Unix ms of the read; set in Rust, absent in the script output.
    #[serde(default)]
    pub checked_at: u64,
}

impl Status {
    /// What the tray shows. `checked_at` is deliberately ignored.
    pub(crate) fn view(&self) -> (GuardState, bool) {
        (self.state, self.adapter_up)
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn unknown() -> Self {
        Self {
            state: GuardState::Unknown,
            adapter_up: false,
            active_backend: None,
            checked_at: now_ms(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Enable,
    Disable,
    CleanLegacy,
}

impl Action {
    #[cfg(windows)]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Enable => "Enable",
            Self::Disable => "Disable",
            Self::CleanLegacy => "CleanLegacy",
        }
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(not(windows))]
pub(crate) fn unsupported_status() -> Status {
    Status {
        state: GuardState::Unsupported,
        adapter_up: false,
        active_backend: None,
        checked_at: now_ms(),
    }
}

/// Serialises status reads inside one process, so two PowerShell status
/// scripts never run at the same time.
static READ: Mutex<()> = Mutex::new(());

pub(crate) fn read_status() -> Result<Status> {
    let _read = READ.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    #[cfg(windows)]
    let status = crate::windows::status();
    #[cfg(not(windows))]
    let status = Ok(unsupported_status());
    status.map(|status| Status {
        checked_at: now_ms(),
        ..status
    })
}

pub(crate) fn active_rules() -> Result<serde_json::Value> {
    #[cfg(windows)]
    return crate::windows::active_rules();
    #[cfg(not(windows))]
    Err("Чтение правил активного Mihomo пока реализовано для Windows.".into())
}

pub(crate) fn read_vpn_targets() -> Result<Vec<String>> {
    #[cfg(windows)]
    return crate::windows::targets();
    #[cfg(not(windows))]
    Err("Чтение маршрутов Mihomo пока реализовано для Windows.".into())
}

pub(crate) fn apply_protection_headless(action: Action) -> Result<Status> {
    #[cfg(windows)]
    {
        crate::windows::worker_result(crate::windows::worker(&[action.name().to_owned()]) as u32)?;
        read_status()
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        Err("Системный kill switch для этой ОС пока не реализован.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_round_trip() {
        for (state, name) in [
            (GuardState::On, "On"),
            (GuardState::Off, "Off"),
            (GuardState::Partial, "Partial"),
            (GuardState::LegacyActive, "LegacyActive"),
            (GuardState::LegacyInactive, "LegacyInactive"),
            (GuardState::Unsupported, "Unsupported"),
            (GuardState::Unknown, "Unknown"),
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(serde_json::from_str::<GuardState>(&json).unwrap(), state);
        }
    }

    #[test]
    fn unknown_string_becomes_unknown() {
        let state: GuardState = serde_json::from_str("\"SomethingNew\"").unwrap();
        assert_eq!(state, GuardState::Unknown);
    }

    #[test]
    fn status_from_script_output_defaults_checked_at() {
        let status: Status = serde_json::from_str(r#"{"state":"On","adapter_up":true}"#).unwrap();
        assert_eq!(
            status,
            Status {
                state: GuardState::On,
                adapter_up: true,
                active_backend: None,
                checked_at: 0,
            }
        );
    }

    #[test]
    fn status_serializes_with_snake_case_fields() {
        let value = serde_json::to_value(Status {
            state: GuardState::Partial,
            adapter_up: false,
            active_backend: None,
            checked_at: 42,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"state": "Partial", "adapter_up": false, "checked_at": 42})
        );
    }

    #[test]
    fn view_ignores_checked_at() {
        let a = Status {
            state: GuardState::On,
            adapter_up: true,
            active_backend: None,
            checked_at: 1,
        };
        let b = Status {
            checked_at: 2,
            ..a.clone()
        };
        assert_eq!(a.view(), b.view());
        assert_ne!(a, b);
    }

    #[test]
    fn action_round_trips_snake_case() {
        let action: Action = serde_json::from_str("\"clean_legacy\"").unwrap();
        assert_eq!(action, Action::CleanLegacy);
        assert_eq!(
            serde_json::to_string(&Action::Enable).unwrap(),
            "\"enable\""
        );
    }

    #[test]
    fn now_is_unix_millis() {
        assert!(now_ms() > 1_700_000_000_000);
    }
}
