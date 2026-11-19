//! Stage reporting for `change_protection`. The elevated worker's PowerShell
//! writes `{"action","stage","at"}` to a file in `storage()`; the panel polls
//! it and forwards each new stage as a `guard-progress` event.

use crate::status::Action;
use serde::{Deserialize, Serialize};

pub(crate) const PROGRESS_FILE: &str = "protection-progress.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProgressStage {
    Preflight,
    Elevate,
    Settings,
    Tun,
    Egress,
    Backup,
    Apply,
    Policy,
    Verify,
    Restore,
    Cleanup,
    Done,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Progress {
    pub action: Action,
    pub stage: ProgressStage,
    pub at: u64,
}

/// Parse the worker's progress file. Returns `None` for anything that is not
/// a complete record of the expected operation written at or after `since`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_progress(raw: &[u8], action: Action, since: u64) -> Option<Progress> {
    let body = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    let progress: Progress = serde_json::from_slice(body).ok()?;
    (progress.action == action && progress.at >= since).then_some(progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_worker_record() {
        let raw = br#"{"stage":"tun","action":"enable","at":1700000000123}"#;
        assert_eq!(
            parse_progress(raw, Action::Enable, 0),
            Some(Progress {
                action: Action::Enable,
                stage: ProgressStage::Tun,
                at: 1_700_000_000_123
            })
        );
    }

    #[test]
    fn accepts_bom_and_clean_legacy() {
        let mut raw = vec![0xef, 0xbb, 0xbf];
        raw.extend_from_slice(br#"{"action":"clean_legacy","stage":"cleanup","at":5}"#);
        assert_eq!(
            parse_progress(&raw, Action::CleanLegacy, 5).map(|p| p.stage),
            Some(ProgressStage::Cleanup)
        );
    }

    #[test]
    fn rejects_other_action_stale_and_garbage() {
        let raw = br#"{"action":"disable","stage":"restore","at":10}"#;
        assert_eq!(parse_progress(raw, Action::Enable, 0), None);
        assert_eq!(parse_progress(raw, Action::Disable, 11), None);
        assert!(parse_progress(raw, Action::Disable, 10).is_some());
        assert_eq!(parse_progress(b"", Action::Enable, 0), None);
        assert_eq!(
            parse_progress(b"{\"action\":\"enable\"", Action::Enable, 0),
            None
        );
        let unknown = br#"{"action":"enable","stage":"teleport","at":1}"#;
        assert_eq!(parse_progress(unknown, Action::Enable, 0), None);
    }

    #[test]
    fn serializes_contract_shape() {
        let value = serde_json::to_value(Progress {
            action: Action::CleanLegacy,
            stage: ProgressStage::Failed,
            at: 7,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"action": "clean_legacy", "stage": "failed", "at": 7})
        );
    }
}
