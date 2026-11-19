use crate::{
    app::reveal,
    rules::config_snapshot,
    status::{GuardState, Status},
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter,
};

const ICON_ON: &[u8] = include_bytes!("../icons/on.png");
const ICON_WAITING: &[u8] = include_bytes!("../icons/waiting.png");
const ICON_OFF: &[u8] = include_bytes!("../icons/off.png");

fn tray_view(status: &Status) -> (&'static [u8], &'static str) {
    match (status.state, status.adapter_up) {
        (GuardState::On, true) => (ICON_ON, "Защита включена"),
        (GuardState::On, false) => (ICON_WAITING, "Туннель отключён"),
        (GuardState::Partial | GuardState::LegacyActive, _) => (ICON_WAITING, "Проверь правила"),
        (GuardState::Off | GuardState::LegacyInactive, _) => (ICON_OFF, "Защита выключена"),
        (GuardState::Unsupported | GuardState::Unknown, _) => (ICON_OFF, "Статус недоступен"),
    }
}

pub(crate) fn update_tray(app: &AppHandle, status: &Status) {
    let (icon, label) = tray_view(status);
    if let Some(tray) = app.tray_by_id("guard") {
        if let Ok(icon) = Image::from_bytes(icon) {
            let _ = tray.set_icon(Some(icon));
        }
        let _ = tray.set_tooltip(Some(format!("Tunnel Guard · {label}")));
    }
}

pub(crate) fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть Tunnel Guard", true, None::<&str>)?;
    let exit = MenuItem::with_id(app, "exit", "Закрыть панель", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &exit])?;
    TrayIconBuilder::with_id("guard")
        .icon(Image::from_bytes(ICON_OFF)?)
        .tooltip("Tunnel Guard · проверяем состояние")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => reveal(app),
            "exit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                reveal(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn monitor(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            let status = crate::windows::status().unwrap_or(Status {
                state: GuardState::Unknown,
                adapter_up: false,
            });
            if last.as_ref() != Some(&status) {
                last = Some(status.clone());
                let target = app.clone();
                if app
                    .run_on_main_thread(move || {
                        update_tray(&target, &status);
                        let _ = target.emit("guard-state", status);
                    })
                    .is_err()
                {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(8));
        }
    });
}

pub(crate) fn monitor_config(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            if let Ok(snapshot) = config_snapshot() {
                if last.as_ref() != Some(&snapshot) {
                    last = Some(snapshot.clone());
                    if app.emit("guard-config", snapshot).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(state: GuardState, adapter_up: bool) -> (&'static [u8], &'static str) {
        tray_view(&Status { state, adapter_up })
    }

    #[test]
    fn labels_follow_state() {
        assert_eq!(view(GuardState::On, true).1, "Защита включена");
        assert_eq!(view(GuardState::On, false).1, "Туннель отключён");
        assert_eq!(view(GuardState::Partial, true).1, "Проверь правила");
        assert_eq!(view(GuardState::LegacyActive, false).1, "Проверь правила");
        assert_eq!(view(GuardState::Off, true).1, "Защита выключена");
        assert_eq!(
            view(GuardState::LegacyInactive, false).1,
            "Защита выключена"
        );
        assert_eq!(view(GuardState::Unknown, false).1, "Статус недоступен");
        assert_eq!(view(GuardState::Unsupported, false).1, "Статус недоступен");
    }

    #[test]
    fn icons_follow_state() {
        assert_eq!(view(GuardState::On, true).0, ICON_ON);
        assert_eq!(view(GuardState::On, false).0, ICON_WAITING);
        assert_eq!(view(GuardState::Off, false).0, ICON_OFF);
    }
}
