//! History of saved Mixin `prepend-rules`, used to tell which list v2rayN baked
//! into the generated Mihomo config (see `core_rules`). Stored as
//! `storage()/prepend-history.json` = `[{at, rules}]`, oldest first.

use crate::{
    settings::{atomic_write, storage},
    Result,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub(crate) const HISTORY_FILE: &str = "prepend-history.json";
const LOCK_FILE: &str = "prepend-history.lock";
pub(crate) const HISTORY_CAP: usize = 50;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HistoryEntry {
    /// Unix ms (Mixin.yaml mtime when the list was observed or written).
    pub at: u64,
    pub rules: Vec<String>,
}

/// Append `entry` unless it repeats the last list; keep at most `cap` newest.
/// `None` means nothing changed.
pub(crate) fn appended(
    mut history: Vec<HistoryEntry>,
    entry: HistoryEntry,
    cap: usize,
) -> Option<Vec<HistoryEntry>> {
    if history.last().is_some_and(|last| last.rules == entry.rules) {
        return None;
    }
    history.push(entry);
    if history.len() > cap {
        let excess = history.len() - cap;
        history.drain(..excess);
    }
    Some(history)
}

/// A missing or damaged history is treated as empty: it only refines the
/// core-rules state and must never break it.
pub(crate) fn parse_history(raw: &[u8]) -> Vec<HistoryEntry> {
    serde_json::from_slice(raw).unwrap_or_default()
}

pub(crate) fn load_from(dir: &Path) -> Vec<HistoryEntry> {
    fs::read(dir.join(HISTORY_FILE))
        .map(|raw| parse_history(&raw))
        .unwrap_or_default()
}

pub(crate) fn record_in(dir: &Path, rules: &[String], at: u64) -> Result<()> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK_FILE))
        .map_err(|error| error.to_string())?;
    lock.lock().map_err(|error| error.to_string())?;
    let entry = HistoryEntry {
        at,
        rules: rules.to_vec(),
    };
    if let Some(next) = appended(load_from(dir), entry, HISTORY_CAP) {
        let bytes = serde_json::to_vec_pretty(&next).map_err(|error| error.to_string())?;
        atomic_write(&dir.join(HISTORY_FILE), &bytes)?;
    }
    Ok(())
}

pub(crate) fn load() -> Vec<HistoryEntry> {
    storage().map(|dir| load_from(&dir)).unwrap_or_default()
}

pub(crate) fn record(rules: &[String], at: u64) -> Result<()> {
    record_in(&storage()?, rules, at)
}

pub(crate) fn file_mtime_ms(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: u64, rules: &[&str]) -> HistoryEntry {
        HistoryEntry {
            at,
            rules: rules.iter().map(|rule| (*rule).to_owned()).collect(),
        }
    }

    #[test]
    fn appends_and_dedupes_against_last_only() {
        let history = appended(Vec::new(), entry(1, &["a"]), 50).unwrap();
        assert_eq!(appended(history.clone(), entry(2, &["a"]), 50), None);
        let history = appended(history, entry(3, &["b"]), 50).unwrap();
        // Same as an older entry but not the last one: kept.
        let history = appended(history, entry(4, &["a"]), 50).unwrap();
        assert_eq!(
            history,
            vec![entry(1, &["a"]), entry(3, &["b"]), entry(4, &["a"])]
        );
    }

    #[test]
    fn empty_list_is_a_valid_entry() {
        let history = appended(Vec::new(), entry(1, &[]), 50).unwrap();
        assert_eq!(history, vec![entry(1, &[])]);
        assert_eq!(appended(history, entry(2, &[]), 50), None);
    }

    #[test]
    fn caps_to_newest() {
        let mut history = Vec::new();
        for index in 0..60u64 {
            history = appended(history, entry(index, &[&index.to_string()]), 50).unwrap();
        }
        assert_eq!(history.len(), 50);
        assert_eq!(history.first().unwrap().at, 10);
        assert_eq!(history.last().unwrap().at, 59);
    }

    #[test]
    fn damaged_history_is_empty() {
        assert!(parse_history(b"{oops").is_empty());
        assert!(parse_history(b"{}").is_empty());
        assert_eq!(
            parse_history(br#"[{"at":5,"rules":["x"]}]"#),
            vec![entry(5, &["x"])]
        );
    }

    #[test]
    fn record_round_trips_in_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_from(dir.path()).is_empty());
        record_in(dir.path(), &["a".into()], 10).unwrap();
        record_in(dir.path(), &["a".into()], 20).unwrap();
        record_in(dir.path(), &["b".into()], 30).unwrap();
        assert_eq!(
            load_from(dir.path()),
            vec![entry(10, &["a"]), entry(30, &["b"])]
        );
        fs::write(dir.path().join(HISTORY_FILE), b"garbage").unwrap();
        record_in(dir.path(), &["c".into()], 40).unwrap();
        assert_eq!(load_from(dir.path()), vec![entry(40, &["c"])]);
    }

    #[test]
    fn mtime_of_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(file_mtime_ms(&dir.path().join("none")), None);
        let file = dir.path().join("x");
        fs::write(&file, b"1").unwrap();
        assert!(file_mtime_ms(&file).unwrap() > 1_700_000_000_000);
    }
}
