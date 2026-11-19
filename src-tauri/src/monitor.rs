//! Background polling: firewall status (`guard-state`) and saved configuration
//! (`guard-config`). The status reader is shared with the `guard_status`
//! command so that a forced read and a scheduled one never overlap and are
//! published in the order they were taken.

use crate::{
    history,
    rules::{config_snapshot, mixin_path},
    settings::Settings,
    status::{self, GuardState, Status},
    tray::update_tray,
    Result,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Condvar, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter};

pub(crate) const VISIBLE_INTERVAL: Duration = Duration::from_secs(4);
pub(crate) const HIDDEN_INTERVAL: Duration = Duration::from_secs(20);

struct Schedule {
    last_read: Option<Instant>,
    last_view: Option<(GuardState, bool)>,
    refresh: bool,
}

/// Held across read + publish so events leave in read order.
static PUBLISH: Mutex<()> = Mutex::new(());
static SCHEDULE: Mutex<Schedule> = Mutex::new(Schedule {
    last_read: None,
    last_view: None,
    refresh: false,
});
static WAKE: Condvar = Condvar::new();
static VISIBLE: AtomicBool = AtomicBool::new(true);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn poll_interval(visible: bool) -> Duration {
    if visible {
        VISIBLE_INTERVAL
    } else {
        HIDDEN_INTERVAL
    }
}

/// How long the monitor still sleeps; `None` = read now.
pub(crate) fn next_wait(
    last_read: Option<Instant>,
    now: Instant,
    visible: bool,
) -> Option<Duration> {
    let due = last_read? + poll_interval(visible);
    due.checked_duration_since(now)
        .filter(|wait| !wait.is_zero())
}

pub(crate) fn set_visible(visible: bool) {
    if VISIBLE.swap(visible, Ordering::SeqCst) != visible {
        // Take the schedule lock so the monitor cannot miss the wake-up.
        let _schedule = lock(&SCHEDULE);
        WAKE.notify_all();
    }
}

/// Ask the monitor for a fresh read as soon as possible (non-blocking).
pub(crate) fn request_refresh() {
    lock(&SCHEDULE).refresh = true;
    WAKE.notify_all();
}

/// Read, then emit `guard-state` (always) and update the tray (on change).
/// The returned flag is false once the app is gone.
fn read_and_publish(app: &AppHandle, fallback: bool) -> Result<(Status, bool)> {
    let _publish = lock(&PUBLISH);
    let result = status::read_status();
    let status = match result {
        Ok(status) => status,
        Err(_) if fallback => Status::unknown(),
        Err(error) => {
            lock(&SCHEDULE).last_read = Some(Instant::now());
            return Err(error);
        }
    };
    let changed = {
        let mut schedule = lock(&SCHEDULE);
        schedule.last_read = Some(Instant::now());
        let changed = schedule.last_view != Some(status.view());
        schedule.last_view = Some(status.view());
        changed
    };
    // The monitor recomputes its deadline from the new last_read.
    WAKE.notify_all();
    let target = app.clone();
    let event = status.clone();
    let alive = app
        .run_on_main_thread(move || {
            if changed {
                update_tray(&target, &event);
            }
            let _ = target.emit("guard-state", event);
        })
        .is_ok();
    Ok((status, alive))
}

/// Forced fresh read for the `guard_status` command.
pub(crate) fn refresh_now(app: &AppHandle) -> Result<Status> {
    read_and_publish(app, false).map(|(status, _)| status)
}

fn wait_for_next_poll() {
    let mut schedule = lock(&SCHEDULE);
    loop {
        if std::mem::take(&mut schedule.refresh) {
            return;
        }
        let visible = VISIBLE.load(Ordering::SeqCst);
        match next_wait(schedule.last_read, Instant::now(), visible) {
            None => return,
            Some(wait) => {
                schedule = WAKE
                    .wait_timeout(schedule, wait)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0;
            }
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn monitor(app: AppHandle) {
    std::thread::spawn(move || loop {
        match read_and_publish(&app, true) {
            Ok((_, false)) => return,
            _ => wait_for_next_poll(),
        }
    });
}

fn record_saved(settings: &Settings, rules: &[String]) -> Result<()> {
    let at = history::file_mtime_ms(&mixin_path(settings)?).ok_or("Mixin.yaml недоступен.")?;
    history::record(rules, at)
}

pub(crate) fn monitor_config(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = None;
        let mut recorded: Option<Vec<String>> = None;
        loop {
            if let Ok(snapshot) = config_snapshot() {
                if let Some(rules) = &snapshot.rules {
                    if recorded.as_ref() != Some(rules)
                        && record_saved(&snapshot.settings, rules).is_ok()
                    {
                        recorded = Some(rules.clone());
                    }
                }
                if last.as_ref() != Some(&snapshot) {
                    last = Some(snapshot.clone());
                    if app.emit("guard-config", snapshot).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_follows_visibility() {
        assert_eq!(poll_interval(true), Duration::from_secs(4));
        assert_eq!(poll_interval(false), Duration::from_secs(20));
    }

    #[test]
    fn reads_immediately_without_previous_read() {
        assert_eq!(next_wait(None, Instant::now(), true), None);
        assert_eq!(next_wait(None, Instant::now(), false), None);
    }

    #[test]
    fn waits_for_remaining_interval() {
        let start = Instant::now();
        let now = start + Duration::from_secs(1);
        assert_eq!(
            next_wait(Some(start), now, true),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            next_wait(Some(start), now, false),
            Some(Duration::from_secs(19))
        );
    }

    #[test]
    fn becoming_visible_after_long_hide_reads_now() {
        let start = Instant::now();
        let now = start + Duration::from_secs(10);
        assert_eq!(next_wait(Some(start), now, true), None);
        assert_eq!(
            next_wait(Some(start), now, false),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            next_wait(Some(start), start + Duration::from_secs(4), true),
            None
        );
    }
}
