use crate::Result;
use serde::{Deserialize, Serialize};

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
}

#[derive(Clone, Copy, Deserialize)]
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

#[cfg(not(windows))]
pub(crate) fn unsupported_status() -> Status {
    Status {
        state: GuardState::Unsupported,
        adapter_up: false,
    }
}

pub(crate) fn read_status() -> Result<Status> {
    #[cfg(windows)]
    return crate::windows::status();
    #[cfg(not(windows))]
    Ok(unsupported_status())
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
    fn status_from_script_output() {
        let status: Status = serde_json::from_str(r#"{"state":"On","adapter_up":true}"#).unwrap();
        assert_eq!(
            status,
            Status {
                state: GuardState::On,
                adapter_up: true
            }
        );
    }

    #[test]
    fn status_serializes_with_same_field_names() {
        let value = serde_json::to_value(Status {
            state: GuardState::Partial,
            adapter_up: false,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"state": "Partial", "adapter_up": false})
        );
    }

    #[test]
    fn action_deserializes_snake_case() {
        let action: Action = serde_json::from_str("\"clean_legacy\"").unwrap();
        assert!(matches!(action, Action::CleanLegacy));
    }
}
