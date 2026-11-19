use crate::{
    core_rules::{self, CoreRulesState},
    detect::{self, ClientDetection},
    diagnose::{self, Diagnosis},
    monitor,
    rules::{self, ConfigSnapshot},
    settings::{self, Settings},
    status::{self, Action, Status},
    Result,
};
use tauri::AppHandle;
#[cfg(windows)]
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) fn load_settings() -> Result<Settings> {
    settings::load_settings()
}

#[tauri::command]
pub(crate) async fn save_settings(settings: Settings, original: Settings) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        settings::edit_settings(Some(original), |_| settings).map(|_| ())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) fn config_snapshot() -> Result<ConfigSnapshot> {
    rules::config_snapshot()
}

#[tauri::command]
pub(crate) fn recover_routing_draft() -> Result<Option<Vec<String>>> {
    rules::recover_routing_draft()
}

#[tauri::command]
pub(crate) async fn pick_exe(app: AppHandle) -> Result<Option<String>> {
    let file = tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        let dialog = if cfg!(windows) {
            dialog.add_filter("Программы", &["exe"])
        } else {
            dialog
        };
        dialog.blocking_pick_file()
    })
    .await
    .map_err(|error| error.to_string())?;
    file.map(|path| {
        path.into_path()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| error.to_string())
    })
    .transpose()
}

#[tauri::command]
pub(crate) fn open_client() -> Result<()> {
    settings::open_client()
}

#[tauri::command]
pub(crate) fn load_rules() -> Result<Vec<String>> {
    rules::load_rules()
}

#[tauri::command]
pub(crate) async fn save_rules(
    rules: Vec<String>,
    original: Vec<String>,
    settings: Settings,
) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        rules::edit_rules(Some(settings), Some(original), |_| rules).map(|_| ())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn vpn_targets() -> Result<Vec<String>> {
    tauri::async_runtime::spawn_blocking(status::read_vpn_targets)
        .await
        .map_err(|error| error.to_string())?
}

/// Fresh read through the shared monitor reader; also emits `guard-state`.
#[tauri::command]
pub(crate) async fn guard_status(app: AppHandle) -> Result<Status> {
    blocking(move || monitor::refresh_now(&app)).await
}

#[tauri::command]
pub(crate) async fn change_protection(app: AppHandle, action: Action) -> Result<()> {
    #[cfg(windows)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or("Окно Tunnel Guard недоступно.")?;
        let parent = window.hwnd().map_err(|error| error.to_string())?.0 as isize;
        let result = blocking(move || {
            let report = move |progress: crate::progress::Progress| {
                let _ = app.emit("guard-progress", progress);
            };
            crate::windows::elevate(action, parent, &report)
        })
        .await;
        monitor::request_refresh();
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (app, action);
        Err("Системный kill switch для этой ОС пока не реализован.".into())
    }
}

#[tauri::command]
pub(crate) async fn diagnose() -> Result<Diagnosis> {
    blocking(diagnose::diagnose).await
}

#[tauri::command]
pub(crate) async fn core_rules_state() -> Result<CoreRulesState> {
    blocking(core_rules::state).await
}

#[tauri::command]
pub(crate) async fn reload_core() -> Result<CoreRulesState> {
    blocking(core_rules::reload).await
}

#[tauri::command]
pub(crate) async fn detect_client() -> Result<ClientDetection> {
    blocking(detect::detect_client).await
}

#[tauri::command]
pub(crate) fn set_window_visible(visible: bool) {
    monitor::set_visible(visible);
}
