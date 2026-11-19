use crate::{
    rules::{self, ConfigSnapshot},
    settings::{self, Settings},
    status::{self, Action, Status},
    tray::update_tray,
    Result,
};
use tauri::AppHandle;
#[cfg(windows)]
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

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

#[tauri::command]
pub(crate) async fn guard_status(app: AppHandle) -> Result<Status> {
    #[cfg(windows)]
    let snapshot = tauri::async_runtime::spawn_blocking(crate::windows::status)
        .await
        .map_err(|error| error.to_string())?;
    #[cfg(not(windows))]
    let snapshot = Ok(status::unsupported_status());
    if let Ok(status) = &snapshot {
        update_tray(&app, status);
    }
    snapshot
}

#[tauri::command]
pub(crate) async fn change_protection(app: AppHandle, action: Action) -> Result<()> {
    #[cfg(windows)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or("Окно Tunnel Guard недоступно.")?;
        let parent = window.hwnd().map_err(|error| error.to_string())?.0 as isize;
        tauri::async_runtime::spawn_blocking(move || crate::windows::elevate(action, parent))
            .await
            .map_err(|error| error.to_string())?
    }
    #[cfg(not(windows))]
    {
        let _ = (app, action);
        Err("Системный kill switch для этой ОС пока не реализован.".into())
    }
}
