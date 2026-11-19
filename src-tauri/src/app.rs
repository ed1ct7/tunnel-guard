use crate::{commands, process_groups, tray};
use tauri::{AppHandle, Manager, WindowEvent};

pub(crate) fn worker_exit_code() -> Option<i32> {
    #[cfg(windows)]
    {
        let args: Vec<_> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--firewall-worker") {
            return Some(crate::windows::worker(&args[2..]));
        }
    }
    None
}

pub(crate) fn reveal(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub(crate) fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| reveal(app)))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::load_settings,
            commands::save_settings,
            commands::config_snapshot,
            commands::recover_routing_draft,
            process_groups::load_process_groups,
            process_groups::save_process_groups,
            process_groups::run_process_group,
            commands::pick_exe,
            commands::open_client,
            commands::load_rules,
            commands::save_rules,
            commands::vpn_targets,
            commands::guard_status,
            commands::change_protection
        ])
        .setup(|app| {
            tray::build_tray(app)?;
            #[cfg(windows)]
            tray::monitor(app.handle().clone());
            tray::monitor_config(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("Tunnel Guard startup failed");
}
